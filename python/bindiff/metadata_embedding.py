"""Function embeddings from a .BinExport, with no model and no dependencies.

The engine compares embeddings; it does not produce them. This is the simplest
producer that exists -- a TF-IDF weighted histogram of instruction mnemonics --
and it is here for two reasons.

It is the floor. A learned model (asm2vec, jTrans) has to beat a bag of
mnemonics to be worth its weight, and until something measures the bag nobody
knows what that bar is. Measured on nine pairs of real programs, this ranks the
true counterpart first for 16% of the functions the differ gets wrong or
misses, against 0.31% for chance -- so there is content signal in the residual,
and this says how much of it is cheap.

It is also the whole cosine path exercised end to end without PyTorch: same
sidecar, same feature name convention, same matching step. A learned producer
replaces this file and changes nothing else.

Deliberately *not* a good embedding. It ignores order, operands, control flow
and calls. That is the point -- it is a baseline.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence

from bindiff.metadata import (BinaryMetadata, FunctionMetadata,
                              embedding_feature, stable_key)

FEATURE_MNEMONIC_HISTOGRAM = "mnemonic-histogram/v1"

# Dimensions the histogram is hashed into. Mnemonic vocabulary is small -- a
# few hundred on x86 including the SSE and AVX families -- but hashing rather
# than building a vocabulary keeps the width fixed and independent of which
# binary is being read, which is what lets two sides compare at all: a
# vocabulary derived per file would number the same mnemonic differently in
# each of them.
DEFAULT_DIMENSION = 256

# Functions this short carry no signal worth a vector. A two-instruction thunk
# has the same histogram as every other two-instruction thunk, and pairing them
# by cosine is pairing them by chance.
MIN_INSTRUCTIONS = 8


def _bucket(mnemonic: str, dimension: int) -> int:
    """Hashing trick, on the same stable hash the key features use."""
    return stable_key(mnemonic) % dimension


def function_mnemonics(binexport_path: str) -> Dict[int, Counter]:
    """Mnemonic multiset per function entry address.

    Instruction addresses in a .BinExport are delta-encoded -- an instruction
    stores its address only when it does not follow the previous one -- so the
    whole instruction table is walked once to resolve them, exactly as
    binexport.read_function_details does.
    """
    from bindiff.binexport import _load_pb2

    proto = _load_pb2().BinExport2()
    with open(binexport_path, "rb") as handle:
        proto.ParseFromString(handle.read())

    mnemonics = [m.name for m in proto.mnemonic]

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

    by_address: Dict[int, Counter] = {}
    for flow_graph in proto.flow_graph:
        blocks = list(flow_graph.basic_block_index)
        if not blocks:
            continue
        entry = list(indices(proto.basic_block[flow_graph.entry_basic_block_index]))
        if not entry:
            continue
        bag: Counter = Counter()
        for block_index in blocks:
            for index in indices(proto.basic_block[block_index]):
                bag[mnemonics[proto.instruction[index].mnemonic_index]] += 1
        by_address[addresses[entry[0]]] = bag
    return by_address


def _document_frequency(bags: Iterable[Counter]) -> Counter:
    frequency: Counter = Counter()
    for bag in bags:
        frequency.update(bag.keys())
    return frequency


def embed(bags: Dict[int, Counter], dimension: int = DEFAULT_DIMENSION,
          min_instructions: int = MIN_INSTRUCTIONS) -> Dict[int, List[float]]:
    """TF-IDF weighted, hashed mnemonic histograms.

    Weighted rather than raw counts because the common instructions carry no
    information: every function moves and compares, so a raw histogram makes
    every function look alike and the cosines all cluster near one. The inverse
    document frequency is computed over this binary, which is the only corpus
    available at this point -- two sides of a diff therefore weight slightly
    differently, and cosine is unaffected by that to first order because both
    are dominated by the same rare mnemonics.
    """
    eligible = {address: bag for address, bag in bags.items()
                if sum(bag.values()) >= min_instructions}
    if not eligible:
        return {}

    frequency = _document_frequency(eligible.values())
    total = len(eligible)

    vectors: Dict[int, List[float]] = {}
    for address, bag in eligible.items():
        vector = [0.0] * dimension
        for mnemonic, count in bag.items():
            # Sublinear term frequency: a loop body repeating one instruction
            # two hundred times is not two hundred times the evidence.
            weight = (1.0 + math.log(count)) * math.log(
                total / (1 + frequency[mnemonic]))
            vector[_bucket(mnemonic, dimension)] += weight
        if any(vector):
            # Left unnormalised: the engine normalises on load, and doing it
            # twice is one more place for the two to disagree.
            vectors[address] = vector
    return vectors


def build_sidecar(binexport_path: str,
                  dimension: int = DEFAULT_DIMENSION,
                  min_instructions: int = MIN_INSTRUCTIONS,
                  feature_name: str = FEATURE_MNEMONIC_HISTOGRAM,
                  confidence: float = 1.0,
                  executable_id: Optional[str] = None) -> BinaryMetadata:
    """A sidecar carrying one embedding per function worth embedding."""
    from bindiff.binexport import read_metadata

    vectors = embed(function_mnemonics(binexport_path), dimension,
                    min_instructions)
    if executable_id is None:
        executable_id = read_metadata(binexport_path).get("executable_id", "")

    metadata = BinaryMetadata(executable_id=executable_id)
    for address in sorted(vectors):
        metadata.functions.append(FunctionMetadata(
            address=address,
            features=[embedding_feature(feature_name, vectors[address],
                                        confidence=confidence)]))
    if not metadata.functions:
        metadata.warnings.append(
            f"no function had at least {min_instructions} instructions; "
            f"nothing to embed")
    return metadata


def cosine(lhs: Sequence[float], rhs: Sequence[float]) -> float:
    """Cosine on the engine's scale: [-1, 1] mapped onto [0, 1].

    Here so a producer can score its own output the way the engine will,
    without reimplementing the mapping and getting it subtly different.
    """
    if len(lhs) != len(rhs) or not lhs:
        return 0.0
    dot = sum(a * b for a, b in zip(lhs, rhs))
    left = math.sqrt(sum(a * a for a in lhs))
    right = math.sqrt(sum(b * b for b in rhs))
    if not left or not right:
        return 0.0
    return (max(-1.0, min(1.0, dot / (left * right))) + 1.0) / 2.0
