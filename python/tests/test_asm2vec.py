"""Tests for the learned embedding producer.

Most of this file is about the parts that do not need PyTorch: tokenising,
walking the control flow graph, and the model file. Those are what decide
whether the embedding means anything, and they are checkable in the harness.
The training loop itself is exercised in one small end-to-end test that skips
when torch is absent, because torch is deliberately optional -- only the
producer needs it, never the differ or the plugin.
"""

from __future__ import annotations

import importlib.util

import pytest

from bindiff.asm2vec import (Asm2VecModel, FunctionCode, MODEL_FORMAT,
                             build_vocabulary, normalise_immediate, walk)

torch_available = importlib.util.find_spec("torch") is not None
needs_torch = pytest.mark.skipif(not torch_available,
                                 reason="PyTorch is optional; only the "
                                        "producer uses it")


def code(blocks, successors=None, address=0x1000) -> FunctionCode:
    return FunctionCode(address=address,
                        blocks=[[[t] for t in block] for block in blocks],
                        successors=successors or {})


class TestImmediateNormalisation:
    def test_small_values_are_kept(self):
        """A shift by 3 or a compare against 0 is part of what the function
        does, and the exact value is the signal."""
        assert normalise_immediate(0) == "i:0"
        assert normalise_immediate(-4) == "i:-4"
        assert normalise_immediate(16) == "i:16"

    def test_large_values_are_bucketed_by_magnitude(self):
        """Addresses and string offsets differ between any two builds. Keeping
        them literally would put a token in the vocabulary that occurs once and
        can never match anything."""
        assert normalise_immediate(0x401000) == normalise_immediate(0x40f000)
        assert normalise_immediate(1 << 20) != normalise_immediate(1 << 30)

    def test_sign_is_kept(self):
        """A large negative offset is a stack access; a large positive one is
        usually a pointer. Collapsing them would merge two different things."""
        assert normalise_immediate(1 << 20) != normalise_immediate(-(1 << 20))


class TestWalks:
    def test_follows_edges_rather_than_layout(self):
        """Address order is the compiler's choice: moving a cold block to the
        end changes the sequence completely while changing nothing about what
        the function does."""
        function = code([["a"], ["b"], ["c"]], {0: [2], 2: [1]})
        import random

        tokens = [bag[0] for bag in walk(function, random.Random(1), 10)]
        assert tokens == ["a", "c", "b"]

    def test_stops_at_a_block_with_no_successors(self):
        import random

        function = code([["a"], ["b"]], {0: [1]})
        assert len(walk(function, random.Random(1), 100)) == 2

    def test_respects_the_length_limit(self):
        import random

        # A self-loop would otherwise walk forever.
        function = code([["a"]], {0: [0]})
        assert len(walk(function, random.Random(1), 7)) == 7

    def test_an_empty_function_walks_to_nothing(self):
        import random

        assert walk(FunctionCode(address=0x1000), random.Random(1), 10) == []

    def test_a_walk_is_reproducible_for_a_seed(self):
        """Two runs of one diff must produce the same vectors; a walk that
        moved would make every comparison between runs meaningless."""
        import random

        function = code([["a"], ["b"], ["c"], ["d"]],
                        {0: [1, 2], 1: [3], 2: [3]})
        first = walk(function, random.Random(7), 20)
        second = walk(function, random.Random(7), 20)
        assert first == second


class TestVocabulary:
    def test_drops_tokens_too_rare_to_learn(self):
        corpus = [code([["common"] * 5 + ["rare"]])]
        vocabulary = build_vocabulary(corpus, min_count=3)
        assert "common" in vocabulary
        assert "rare" not in vocabulary

    def test_order_is_stable_for_a_corpus(self):
        """A model file whose token order shuffled between runs would make two
        models of the same corpus incomparable."""
        corpus = [code([["b"] * 3 + ["a"] * 3 + ["c"] * 5])]
        assert (build_vocabulary(corpus, min_count=1)
                == build_vocabulary(corpus, min_count=1))
        # Ties broken by name, so equal counts do not depend on dict order.
        assert build_vocabulary(corpus, min_count=1) == ["c", "a", "b"]


class TestModelFile:
    def make(self) -> Asm2VecModel:
        return Asm2VecModel(dimension=3, tokens=["m:mov", "r:eax"],
                            vectors=[[0.5, -0.25, 1.0], [1.0, 2.0, -3.0]],
                            trained_on=["a.BinExport"], epochs=4)

    def test_round_trips(self, tmp_path):
        path = tmp_path / "model.a2v"
        self.make().save(path)
        loaded = Asm2VecModel.load(path)

        assert loaded.dimension == 3
        assert loaded.tokens == ["m:mov", "r:eax"]
        assert loaded.epochs == 4
        assert loaded.trained_on == ["a.BinExport"]
        for got, expected in zip(loaded.vectors, self.make().vectors):
            assert got == pytest.approx(expected)

    def test_is_not_a_pickle(self, tmp_path):
        """A model file is meant to be shared, and loading a torch checkpoint
        executes whatever is inside it. This one is a zip of JSON and raw
        floats: readable by anything, able to run nothing."""
        import zipfile

        path = tmp_path / "model.a2v"
        self.make().save(path)
        with zipfile.ZipFile(path) as archive:
            assert sorted(archive.namelist()) == ["format.json",
                                                  "tokens.json",
                                                  "vectors.f32"]

    def test_refuses_a_file_of_another_format(self, tmp_path):
        import json
        import zipfile

        path = tmp_path / "other.a2v"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("format.json", json.dumps({"format": "something"}))
            archive.writestr("tokens.json", "[]")
            archive.writestr("vectors.f32", b"")
        with pytest.raises(ValueError, match=MODEL_FORMAT):
            Asm2VecModel.load(path)

    def test_refuses_a_truncated_file(self, tmp_path):
        """Silently loading short rows would give every function a vector made
        partly of the next function's, and the cosines would still look fine."""
        import json
        import zipfile

        path = tmp_path / "short.a2v"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("format.json", json.dumps(
                {"format": MODEL_FORMAT, "dimension": 4}))
            archive.writestr("tokens.json", json.dumps(["a", "b"]))
            archive.writestr("vectors.f32", b"\x00" * 4)  # one float, needs 8
        with pytest.raises(ValueError, match="truncated"):
            Asm2VecModel.load(path)


@needs_torch
class TestTrainingAndInference:
    def corpus(self):
        # Two clearly different kinds of function, repeated, so a model has
        # something to learn in a couple of seconds.
        loops = [code([["m:cmp", "m:jne", "m:add"]] * 3, {0: [1], 1: [2]},
                      address=0x1000 + i) for i in range(6)]
        calls = [code([["m:push", "m:call", "m:pop"]] * 3, {0: [1], 1: [2]},
                      address=0x2000 + i) for i in range(6)]
        return loops + calls

    def test_learns_a_vocabulary_and_embeds_in_its_space(self):
        from bindiff.asm2vec import infer, train

        model = train(self.corpus(), dimension=8, epochs=2, walks=2, length=8,
                      min_count=1)
        assert model.tokens
        assert all(len(v) == 8 for v in model.vectors)

        functions = {f.address: f for f in self.corpus()}
        vectors = infer(model, functions, steps=5, walks=2, length=8)
        assert vectors
        assert all(len(v) == 8 for v in vectors.values())

    def test_inference_does_not_move_the_model(self):
        """The whole reason the model is frozen: two binaries are only
        comparable if both were fitted against the same fixed tokens."""
        from bindiff.asm2vec import infer, train

        model = train(self.corpus(), dimension=8, epochs=1, walks=2, length=8,
                      min_count=1)
        before = [list(v) for v in model.vectors]
        infer(model, {f.address: f for f in self.corpus()}, steps=5, walks=2,
              length=8)
        assert model.vectors == before

    def test_inference_is_reproducible(self):
        """Same model, same binary, same vectors -- otherwise a diff would not
        reproduce and no regression test could hold."""
        from bindiff.asm2vec import infer, train

        model = train(self.corpus(), dimension=8, epochs=1, walks=2, length=8,
                      min_count=1)
        functions = {f.address: f for f in self.corpus()}
        first = infer(model, functions, steps=5, walks=2, length=8)
        second = infer(model, functions, steps=5, walks=2, length=8)
        assert first.keys() == second.keys()
        for address in first:
            assert first[address] == pytest.approx(second[address])

    def test_short_functions_get_no_vector(self):
        from bindiff.asm2vec import infer, train

        model = train(self.corpus(), dimension=8, epochs=1, walks=2, length=8,
                      min_count=1)
        stub = code([["m:ret"]], address=0x9000)
        vectors = infer(model, {0x9000: stub}, steps=5, walks=2, length=8)
        assert 0x9000 not in vectors


@needs_torch
@pytest.mark.requires_extension
def test_embeds_a_real_export(insider_pair, tmp_path):
    from bindiff.asm2vec import (FEATURE_ASM2VEC, build_sidecar,
                                 read_functions, train)

    functions = read_functions(str(insider_pair[0]))
    assert functions, "no function was read from the export"

    model = train(list(functions.values()), dimension=16, epochs=1, walks=2,
                  length=16, min_count=2)
    metadata = build_sidecar(str(insider_pair[0]), model, steps=5, walks=2,
                             length=16)

    assert metadata.functions, metadata.warnings
    assert metadata.executable_id
    for function in metadata.functions:
        feature = function.feature(FEATURE_ASM2VEC)
        assert feature is not None
        assert len(feature.vector) == 16
