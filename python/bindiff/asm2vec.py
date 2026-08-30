"""Learned function embeddings, asm2vec style, over .BinExport input.

The engine compares embeddings and never produces one. This is a producer: it
turns functions into vectors that a sidecar carries and
`match/function_feature.cc` compares by cosine. PyTorch is imported lazily and
only for training and inference, so it is never pulled into IDA's interpreter
and never linked into the differ.

The model follows asm2vec's shape -- PV-DM over instruction token sequences
drawn from random walks on the control flow graph -- with the pieces that
matter for diffing kept and the rest left out:

* a function is a "document" with its own vector;
* an instruction is a small bag of tokens (mnemonic, registers, normalised
  immediates), so two instructions differing only in a constant share most of
  their tokens;
* training predicts an instruction's tokens from the function vector plus the
  instructions either side of it, which is what makes the function vector
  absorb what the surrounding code does rather than only what it contains.

**The model must be frozen and shared.** Two binaries embedded by two
separately trained models land in unrelated spaces and their cosines mean
nothing -- the numbers still come out between 0 and 1, which is what makes this
a trap rather than an error. Training therefore happens once
(`tools/scripts/train_asm2vec.py`), and inference for a new binary optimises
only that binary's function vectors with the token vectors held fixed. That
also keeps a sidecar a property of one binary, which is what the content
addressing and the executable_id check depend on.
"""

from __future__ import annotations

import json
import random
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

FEATURE_ASM2VEC = "asm2vec/v1"

# Model shape. Small on purpose: the vocabulary is a few thousand tokens, the
# corpora available here are a few hundred thousand instructions, and a wider
# embedding would memorise rather than generalise.
DEFAULT_DIMENSION = 100
DEFAULT_WALKS_PER_FUNCTION = 10
DEFAULT_WALK_LENGTH = 40
DEFAULT_NEGATIVE_SAMPLES = 5
DEFAULT_EPOCHS = 5
# Passes over a binary's examples when fitting its function vectors. Each
# pass now covers every function at once, so far fewer are needed than when
# this counted single-sequence updates.
DEFAULT_INFERENCE_STEPS = 20

# Tokens seen fewer times than this are dropped. A token appearing once cannot
# be learned from and only adds a row to the embedding table.
DEFAULT_MIN_COUNT = 3

# Functions shorter than this get no vector, for the same reason the histogram
# producer skips them: a three-instruction thunk is indistinguishable from
# every other three-instruction thunk.
MIN_INSTRUCTIONS = 8

# Context tokens kept per instruction pair. Two instructions rarely have more
# than a handful of tokens between them, and a fixed width is what lets the
# whole corpus become one flat array.
MAX_CONTEXT_TOKENS = 16

# Examples per optimiser step.
DEFAULT_BATCH_SIZE = 4096

MODEL_FORMAT = "bindiff-asm2vec/1"


def _torch():
    """Imported here, never at module scope.

    Importing torch costs seconds and hundreds of megabytes of address space.
    Everything above this line -- tokenising, walking, the model file's shape --
    is needed by callers that only want to inspect a model, and the sidecar
    consumer in the engine needs none of it at all.
    """
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "asm2vec needs PyTorch. It is deliberately optional: only the "
            "producer uses it, never the differ or the IDA plugin. Install it "
            "with `pip install torch --index-url "
            "https://download.pytorch.org/whl/cpu`") from exc
    return torch


# -- tokenising ------------------------------------------------------------

def normalise_immediate(value: int) -> str:
    """An immediate as a token.

    Kept literally when small, bucketed by magnitude otherwise. Raw immediates
    would put every address and every string offset in the vocabulary, and two
    builds of one function share almost none of those -- which is the opposite
    of what a token is for.
    """
    if -16 <= value <= 16:
        return f"i:{value}"
    magnitude = value.bit_length() if value >= 0 else (-value).bit_length()
    return f"i:{'-' if value < 0 else ''}2^{magnitude}"


def instruction_tokens(proto, index: int) -> List[str]:
    """The token bag for one instruction: mnemonic, then its operands.

    An instruction is a bag rather than a single token so that two instructions
    differing only in one register still share most of their tokens. Treating
    a whole instruction as one symbol is what makes a vocabulary explode and
    generalise to nothing.
    """
    from bindiff._pb import binexport2_pb2

    expression_type = binexport2_pb2.BinExport2.Expression
    instruction = proto.instruction[index]
    tokens = [f"m:{proto.mnemonic[instruction.mnemonic_index].name}"]

    for operand_index in instruction.operand_index:
        for expression_index in proto.operand[operand_index].expression_index:
            expression = proto.expression[expression_index]
            if expression.type == expression_type.REGISTER:
                tokens.append(f"r:{expression.symbol}")
            elif expression.type == expression_type.IMMEDIATE_INT:
                tokens.append(normalise_immediate(expression.immediate))
            elif expression.type == expression_type.IMMEDIATE_FLOAT:
                tokens.append("f:imm")
            elif expression.type == expression_type.SYMBOL:
                # Present in an unstripped build and almost absent from a
                # stripped one. Kept because an import name survives stripping
                # and is strong evidence; it simply contributes nothing when
                # there is none.
                tokens.append(f"s:{expression.symbol}")
            elif expression.type == expression_type.OPERATOR:
                tokens.append(f"o:{expression.symbol}")
            elif expression.type == expression_type.DEREFERENCE:
                tokens.append("o:[]")
            elif expression.type == expression_type.SIZE_PREFIX:
                tokens.append(f"z:{expression.symbol}")
    return tokens


@dataclass
class FunctionCode:
    """One function's basic blocks, as token bags, plus its control flow."""

    address: int
    blocks: List[List[List[str]]] = field(default_factory=list)
    successors: Dict[int, List[int]] = field(default_factory=dict)

    def instruction_count(self) -> int:
        return sum(len(block) for block in self.blocks)


def read_functions(binexport_path: str) -> Dict[int, FunctionCode]:
    """Tokenises every function in an export, keyed by entry point address."""
    from bindiff.binexport import _load_pb2

    proto = _load_pb2().BinExport2()
    with open(binexport_path, "rb") as handle:
        proto.ParseFromString(handle.read())

    # Instruction addresses are delta-encoded, so resolving the entry point of
    # each flow graph means one pass over the whole instruction table.
    addresses: List[int] = []
    current = 0
    for instruction in proto.instruction:
        if instruction.HasField("address"):
            current = instruction.address
        addresses.append(current)
        current += len(instruction.raw_bytes)

    def indices(block) -> Iterable[int]:
        for index_range in block.instruction_index:
            begin = index_range.begin_index
            end = (index_range.end_index if index_range.HasField("end_index")
                   else begin + 1)
            yield from range(begin, end)

    functions: Dict[int, FunctionCode] = {}
    for flow_graph in proto.flow_graph:
        block_indices = list(flow_graph.basic_block_index)
        if not block_indices:
            continue
        position = {block: i for i, block in enumerate(block_indices)}
        entry = list(indices(proto.basic_block[flow_graph.entry_basic_block_index]))
        if not entry:
            continue

        code = FunctionCode(address=addresses[entry[0]])
        for block_index in block_indices:
            code.blocks.append([
                instruction_tokens(proto, i)
                for i in indices(proto.basic_block[block_index])])
        for edge in flow_graph.edge:
            source = position.get(edge.source_basic_block_index)
            target = position.get(edge.target_basic_block_index)
            if source is not None and target is not None:
                code.successors.setdefault(source, []).append(target)
        # Position of the entry block, so a walk starts where the function does.
        code.successors.setdefault(
            position.get(flow_graph.entry_basic_block_index, 0), [])
        functions[code.address] = code
    return functions


def walk(code: FunctionCode, rng: random.Random, length: int) -> List[List[str]]:
    """One random walk through the control flow graph, as token bags.

    Walks rather than address order because address order is an artefact of the
    compiler's layout: an optimiser that moves a cold block to the end of the
    function changes the sequence completely while changing nothing about what
    the function does. Following edges follows the code instead.
    """
    if not code.blocks:
        return []
    block = 0
    sequence: List[List[str]] = []
    while len(sequence) < length:
        sequence.extend(code.blocks[block])
        successors = code.successors.get(block) or []
        if not successors:
            break
        block = rng.choice(successors)
    return sequence[:length]


# -- the model file --------------------------------------------------------

@dataclass
class Asm2VecModel:
    """A frozen model: a vocabulary and its token vectors.

    Deliberately not a torch checkpoint. A checkpoint is a pickle, which means
    loading one executes whatever it contains, and this file is meant to be
    shared. JSON plus a raw float array can be read by anything and cannot run
    anything.
    """

    dimension: int
    tokens: List[str]
    vectors: List[List[float]]
    trained_on: List[str] = field(default_factory=list)
    epochs: int = 0

    def index_of(self) -> Dict[str, int]:
        return {token: i for i, token in enumerate(self.tokens)}

    def save(self, path) -> None:
        import array
        import io

        flat = array.array("f")
        for vector in self.vectors:
            flat.extend(vector)
        buffer = io.BytesIO()
        flat.tofile(buffer)

        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("format.json", json.dumps({
                "format": MODEL_FORMAT, "dimension": self.dimension,
                "tokens": len(self.tokens), "epochs": self.epochs,
                "trained_on": self.trained_on,
                # Little-endian float32, row major. Written down because a
                # model file outlives the code that wrote it.
                "layout": "float32 little-endian, tokens x dimension"}))
            archive.writestr("tokens.json", json.dumps(self.tokens))
            archive.writestr("vectors.f32", buffer.getvalue())

    @classmethod
    def load(cls, path) -> "Asm2VecModel":
        import array

        with zipfile.ZipFile(path) as archive:
            header = json.loads(archive.read("format.json"))
            if header.get("format") != MODEL_FORMAT:
                raise ValueError(
                    f"{path} is not a {MODEL_FORMAT} model "
                    f"(says {header.get('format')!r})")
            tokens = json.loads(archive.read("tokens.json"))
            flat = array.array("f")
            flat.frombytes(archive.read("vectors.f32"))

        dimension = header["dimension"]
        if len(flat) != len(tokens) * dimension:
            raise ValueError(
                f"{path} is truncated: {len(tokens)} tokens x {dimension} "
                f"dimensions needs {len(tokens) * dimension} floats, "
                f"found {len(flat)}")
        vectors = [list(flat[i * dimension:(i + 1) * dimension])
                   for i in range(len(tokens))]
        return cls(dimension=dimension, tokens=tokens, vectors=vectors,
                   trained_on=header.get("trained_on", []),
                   epochs=header.get("epochs", 0))


# -- training --------------------------------------------------------------

def build_vocabulary(corpus: Iterable[FunctionCode],
                     min_count: int = DEFAULT_MIN_COUNT) -> List[str]:
    counts: Counter = Counter()
    for code in corpus:
        for block in code.blocks:
            for tokens in block:
                counts.update(tokens)
    # Sorted by count then name, so the same corpus always produces the same
    # vocabulary in the same order -- a model file that shuffled between runs
    # would make every comparison of two runs meaningless.
    return [token for token, count in
            sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            if count >= min_count]


def _sequences(corpus: Sequence[FunctionCode], rng: random.Random,
               walks: int, length: int) -> List[Tuple[int, List[List[str]]]]:
    out = []
    for index, code in enumerate(corpus):
        if code.instruction_count() < MIN_INSTRUCTIONS:
            continue
        for _ in range(walks):
            sequence = walk(code, rng, length)
            if len(sequence) >= 3:
                out.append((index, sequence))
    return out


def _examples(sequences, index_of: Dict[str, int], max_context: int):
    """Flattens walks into (function, context tokens, target token) triples.

    Done once, before any training, and this is the difference between a model
    that trains in a minute and one that does not finish. The walks do not
    change between epochs, so rebuilding the context of every instruction on
    every epoch -- and taking one optimiser step per sequence, as the first
    version did -- spends nearly all its time on Python and autograd bookkeeping
    for a few dozen numbers at a time. Flat arrays let a batch of thousands go
    through in one step.

    Contexts are padded to a fixed width with a mask rather than averaged here,
    because the function vector has to be added before the mean is taken.
    """
    functions: List[int] = []
    contexts: List[List[int]] = []
    masks: List[List[float]] = []
    targets: List[int] = []

    for function_index, sequence in sequences:
        for position in range(1, len(sequence) - 1):
            neighbours = [index_of[t]
                          for offset in (position - 1, position + 1)
                          for t in sequence[offset] if t in index_of]
            if not neighbours:
                continue
            neighbours = neighbours[:max_context]
            padded = neighbours + [0] * (max_context - len(neighbours))
            mask = ([1.0] * len(neighbours)
                    + [0.0] * (max_context - len(neighbours)))
            for token in sequence[position]:
                target = index_of.get(token)
                if target is None:
                    continue
                functions.append(function_index)
                contexts.append(padded)
                masks.append(mask)
                targets.append(target)
    return functions, contexts, masks, targets


def _batch_loss(torch, context_vectors, targets, token_out, weights, negative):
    """Negative-sampling loss for a batch of (context, target) pairs."""
    positive = token_out(targets)
    sampled = torch.multinomial(weights, targets.numel() * negative,
                                replacement=True)
    negatives = token_out(sampled).view(targets.numel(), negative, -1)

    positive_score = (context_vectors * positive).sum(dim=1)
    negative_score = torch.bmm(negatives,
                               context_vectors.unsqueeze(2)).squeeze(2)
    return -(torch.nn.functional.logsigmoid(positive_score).mean()
             + torch.nn.functional.logsigmoid(-negative_score).mean())


def train(corpus: Sequence[FunctionCode], *,
          dimension: int = DEFAULT_DIMENSION,
          walks: int = DEFAULT_WALKS_PER_FUNCTION,
          length: int = DEFAULT_WALK_LENGTH,
          epochs: int = DEFAULT_EPOCHS,
          negative: int = DEFAULT_NEGATIVE_SAMPLES,
          min_count: int = DEFAULT_MIN_COUNT,
          batch_size: int = DEFAULT_BATCH_SIZE,
          seed: int = 20260829,
          learning_rate: float = 0.025,
          progress=None) -> Asm2VecModel:
    """Trains token vectors. The function vectors are thrown away.

    Only the vocabulary survives, because that is what makes two binaries
    comparable later: inference re-derives a function vector against these
    fixed tokens, so any binary embedded with this model lands in the same
    space as any other.
    """
    torch = _torch()
    torch.manual_seed(seed)
    rng = random.Random(seed)

    tokens = build_vocabulary(corpus, min_count)
    if not tokens:
        raise ValueError("no token met the minimum count; corpus is too small")
    index_of = {token: i for i, token in enumerate(tokens)}

    sequences = _sequences(corpus, rng, walks, length)
    if not sequences:
        raise ValueError("no function was long enough to walk")

    # Negative samples are drawn from the unigram distribution raised to 3/4,
    # as in word2vec: sampling uniformly wastes most updates on tokens that
    # never occur, and sampling by raw frequency drowns everything in `mov`.
    counts = Counter()
    for _, sequence in sequences:
        for bag in sequence:
            counts.update(t for t in bag if t in index_of)
    weights = torch.tensor(
        [counts.get(token, 1) ** 0.75 for token in tokens], dtype=torch.float)

    token_in = torch.nn.Embedding(len(tokens), dimension)
    token_out = torch.nn.Embedding(len(tokens), dimension)
    torch.nn.init.uniform_(token_in.weight, -0.5 / dimension, 0.5 / dimension)
    torch.nn.init.zeros_(token_out.weight)
    functions = torch.nn.Embedding(len(corpus), dimension)
    torch.nn.init.uniform_(functions.weight, -0.5 / dimension, 0.5 / dimension)

    parameters = list(token_in.parameters()) + list(token_out.parameters()) \
        + list(functions.parameters())
    optimiser = torch.optim.Adam(parameters, lr=learning_rate)

    flat_functions, flat_contexts, flat_masks, flat_targets = _examples(
        sequences, index_of, MAX_CONTEXT_TOKENS)
    if not flat_targets:
        raise ValueError("no instruction had a context to learn from")

    all_functions = torch.tensor(flat_functions, dtype=torch.long)
    all_contexts = torch.tensor(flat_contexts, dtype=torch.long)
    all_masks = torch.tensor(flat_masks, dtype=torch.float)
    all_targets = torch.tensor(flat_targets, dtype=torch.long)
    count = all_targets.numel()

    for epoch in range(epochs):
        order = torch.randperm(count)
        total = 0.0
        steps = 0
        for start in range(0, count, batch_size):
            rows = order[start:start + batch_size]
            contexts = token_in(all_contexts[rows])
            masks = all_masks[rows].unsqueeze(-1)
            pooled = (contexts * masks).sum(dim=1) / masks.sum(dim=1).clamp(
                min=1.0)
            context_vectors = functions(all_functions[rows]) + pooled

            loss = _batch_loss(torch, context_vectors, all_targets[rows],
                               token_out, weights, negative)
            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
            total += float(loss)
            steps += 1
        if progress is not None:
            progress({"epoch": epoch + 1, "epochs": epochs,
                      "loss": total / steps if steps else 0.0,
                      "sequences": len(sequences), "examples": count})

    return Asm2VecModel(dimension=dimension, tokens=tokens,
                        vectors=token_in.weight.detach().tolist(),
                        epochs=epochs)


# -- inference -------------------------------------------------------------

def infer(model: Asm2VecModel, functions: Dict[int, FunctionCode], *,
          walks: int = DEFAULT_WALKS_PER_FUNCTION,
          length: int = DEFAULT_WALK_LENGTH,
          steps: int = DEFAULT_INFERENCE_STEPS,
          negative: int = DEFAULT_NEGATIVE_SAMPLES,
          batch_size: int = DEFAULT_BATCH_SIZE,
          seed: int = 20260829,
          learning_rate: float = 0.05,
          progress=None) -> Dict[int, List[float]]:
    """Vectors for a new binary's functions, in the model's own space.

    The token vectors do not move. That is the entire point: a function vector
    is only comparable to another if both were fitted against the same fixed
    tokens, and a model retrained per binary would give every pair a confident
    cosine that means nothing.
    """
    torch = _torch()
    torch.manual_seed(seed)
    rng = random.Random(seed)

    index_of = model.index_of()
    token_in = torch.nn.Embedding(len(model.tokens), model.dimension)
    with torch.no_grad():
        token_in.weight.copy_(torch.tensor(model.vectors))
    token_in.weight.requires_grad_(False)

    # The output table is not in the model file -- it is scaffolding for
    # training, not part of the representation -- so inference re-derives its
    # own from the input vectors. Fixed too, so the objective stays still while
    # the function vector moves.
    token_out = torch.nn.Embedding(len(model.tokens), model.dimension)
    with torch.no_grad():
        token_out.weight.copy_(token_in.weight)
    token_out.weight.requires_grad_(False)

    counts = Counter()
    ordered = [address for address in sorted(functions)
               if functions[address].instruction_count() >= MIN_INSTRUCTIONS]
    prepared = []
    for address in ordered:
        sequences = []
        for _ in range(walks):
            sequence = walk(functions[address], rng, length)
            if len(sequence) >= 3:
                sequences.append(sequence)
                for bag in sequence:
                    counts.update(t for t in bag if t in index_of)
        if sequences:
            prepared.append((address, sequences))

    if not prepared:
        return {}
    weights = torch.tensor(
        [counts.get(token, 1) ** 0.75 for token in model.tokens],
        dtype=torch.float)

    # Every function is fitted at once rather than one at a time. They share
    # the frozen token tables and never interact -- each function vector only
    # appears in its own examples -- so solving them together is the same
    # problem with the per-function Python and autograd overhead paid once
    # instead of thousands of times.
    addresses = [address for address, _ in prepared]
    position = {address: i for i, address in enumerate(addresses)}
    flat_functions, flat_contexts, flat_masks, flat_targets = _examples(
        [(position[address], sequence)
         for address, sequences in prepared for sequence in sequences],
        index_of, MAX_CONTEXT_TOKENS)
    if not flat_targets:
        return {}

    all_functions = torch.tensor(flat_functions, dtype=torch.long)
    all_contexts = torch.tensor(flat_contexts, dtype=torch.long)
    all_masks = torch.tensor(flat_masks, dtype=torch.float)
    all_targets = torch.tensor(flat_targets, dtype=torch.long)
    count = all_targets.numel()

    vectors = torch.nn.Embedding(len(addresses), model.dimension)
    torch.nn.init.uniform_(vectors.weight, -0.5 / model.dimension,
                           0.5 / model.dimension)
    optimiser = torch.optim.Adam(vectors.parameters(), lr=learning_rate)

    for step in range(steps):
        order = torch.randperm(count)
        for start in range(0, count, batch_size):
            rows = order[start:start + batch_size]
            contexts = token_in(all_contexts[rows])
            masks = all_masks[rows].unsqueeze(-1)
            pooled = (contexts * masks).sum(dim=1) / masks.sum(dim=1).clamp(
                min=1.0)
            context_vectors = vectors(all_functions[rows]) + pooled
            loss = _batch_loss(torch, context_vectors, all_targets[rows],
                               token_out, weights, negative)
            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
        if progress is not None:
            progress({"step": step + 1, "steps": steps,
                      "functions": len(addresses), "examples": count})

    learned = vectors.weight.detach().tolist()
    return {address: learned[position[address]] for address in addresses
            if any(learned[position[address]])}


def build_sidecar(binexport_path: str, model: Asm2VecModel,
                  feature_name: str = FEATURE_ASM2VEC,
                  confidence: float = 1.0,
                  executable_id: Optional[str] = None,
                  **infer_options):
    """A sidecar carrying one learned embedding per function."""
    from bindiff.binexport import read_metadata
    from bindiff.metadata import (BinaryMetadata, FunctionMetadata,
                                  embedding_feature)

    vectors = infer(model, read_functions(binexport_path), **infer_options)
    if executable_id is None:
        executable_id = read_metadata(binexport_path).get("executable_id", "")

    metadata = BinaryMetadata(executable_id=executable_id)
    for address in sorted(vectors):
        metadata.functions.append(FunctionMetadata(
            address=address,
            features=[embedding_feature(feature_name, vectors[address],
                                        confidence=confidence)]))
    if not metadata.functions:
        metadata.warnings.append("no function was long enough to embed")
    return metadata
