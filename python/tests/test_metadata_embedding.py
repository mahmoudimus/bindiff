"""Tests for the baseline embedding producer.

This producer exists to be beaten -- it is a bag of mnemonics, and a learned
model has to do better to be worth its weight. What is checked here is the part
a learned producer will inherit unchanged: the feature contract, the hashing
that makes two binaries comparable at all, and the refusals that keep an
unusable vector out of a sidecar.
"""

from __future__ import annotations

from collections import Counter

import pytest

from bindiff.metadata import METRIC_COSINE, embedding_feature
from bindiff.metadata_embedding import (DEFAULT_DIMENSION,
                                        FEATURE_MNEMONIC_HISTOGRAM,
                                        MIN_INSTRUCTIONS, _bucket, cosine,
                                        embed)


def bag(**counts) -> Counter:
    return Counter(counts)


class TestEmbeddingFeature:
    def test_carries_the_vector_and_the_metric(self):
        feature = embedding_feature("model/v1", [1.0, 2.0, 3.0])
        assert feature.metric == METRIC_COSINE
        assert list(feature.vector) == [1.0, 2.0, 3.0]

    def test_refuses_a_vector_with_no_direction(self):
        """An all-zero vector has no cosine to anything. Refused at the
        producer rather than dropped on load, because a producer emitting them
        is producing nothing and should hear about it."""
        with pytest.raises(ValueError, match="no direction"):
            embedding_feature("model/v1", [0.0, 0.0, 0.0])

    def test_refuses_an_empty_vector(self):
        with pytest.raises(ValueError, match="empty"):
            embedding_feature("model/v1", [])

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"),
                                     float("-inf")])
    def test_refuses_non_finite_values(self, bad):
        """A NaN propagates through every dot product it touches and turns
        each one into a comparison that is false both ways."""
        with pytest.raises(ValueError, match="non-finite"):
            embedding_feature("model/v1", [1.0, bad])


class TestHashing:
    def test_the_same_mnemonic_lands_in_the_same_bucket_everywhere(self):
        """The whole reason for hashing rather than building a vocabulary: a
        vocabulary derived per file would number "push" differently in each of
        two binaries, and the two sides would not be comparable at all."""
        assert _bucket("push", 256) == _bucket("push", 256)
        assert 0 <= _bucket("vpxor", 256) < 256

    def test_the_bucket_is_stable_across_processes(self):
        """stable_key is a truncated SHA-256, not Python's randomised hash. A
        sidecar written by one process must compare against one written by
        another."""
        import subprocess
        import sys

        script = ("import sys; sys.path.insert(0, 'python');"
                  "from bindiff.metadata_embedding import _bucket;"
                  "print(_bucket('push', 256))")
        # PYTHONHASHSEED deliberately differs from this process's.
        out = subprocess.run([sys.executable, "-c", script],
                             capture_output=True, text=True,
                             env={"PYTHONHASHSEED": "12345", "PATH": "/usr/bin"},
                             cwd=str(__import__("pathlib").Path(
                                 __file__).resolve().parents[2]))
        if out.returncode != 0:
            pytest.skip(f"could not run a second interpreter: {out.stderr}")
        assert int(out.stdout.strip()) == _bucket("push", 256)


class TestEmbed:
    def test_skips_functions_too_short_to_say_anything(self):
        """A two-instruction thunk has the same histogram as every other
        two-instruction thunk; pairing them by cosine is pairing them by
        chance."""
        vectors = embed({
            0x1000: bag(push=1, ret=1),
            0x2000: Counter({f"op{i}": 1 for i in range(MIN_INSTRUCTIONS)}),
        })
        assert 0x1000 not in vectors
        assert 0x2000 in vectors

    def test_vectors_all_have_the_declared_width(self):
        vectors = embed({
            address: Counter({f"op{i}": 1 for i in range(MIN_INSTRUCTIONS + 2)})
            for address in (0x1000, 0x2000, 0x3000)
        })
        assert vectors
        assert all(len(v) == DEFAULT_DIMENSION for v in vectors.values())

    def test_a_mnemonic_every_function_has_carries_no_weight(self):
        """Inverse document frequency is the point: every function moves and
        compares, so a raw histogram makes every function look alike."""
        common = {address: Counter({"mov": MIN_INSTRUCTIONS})
                  for address in range(0x1000, 0x1000 + 5)}
        vectors = embed(common)
        # log(5 / (1 + 5)) is negative but tiny; what matters is that a
        # universal mnemonic cannot dominate. Nothing survives here at all,
        # which is the strongest form of that.
        assert all(abs(sum(v)) < 1.0 for v in vectors.values())

    def test_functions_with_the_same_mix_score_alike(self):
        rare = Counter({"vpermd": 4, "vpxor": 4})
        noise = Counter({f"op{i}": 1 for i in range(MIN_INSTRUCTIONS)})
        vectors = embed({0x1000: rare + noise, 0x2000: rare + noise,
                         0x3000: noise, 0x4000: noise,
                         0x5000: Counter({"fdiv": 9})})
        assert cosine(vectors[0x1000], vectors[0x2000]) > 0.99
        assert (cosine(vectors[0x1000], vectors[0x2000])
                > cosine(vectors[0x1000], vectors[0x5000]))


class TestCosine:
    def test_matches_the_scale_the_engine_uses(self):
        """[-1, 1] mapped onto [0, 1], because every threshold in the engine is
        a similarity in [0, 1]. Reimplementing the mapping in the producer and
        getting it subtly different is exactly the bug this shares code to
        avoid."""
        assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
        assert cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.5)
        assert cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(0.0)

    def test_different_widths_do_not_compare(self):
        assert cosine([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0
        assert cosine([], []) == 0.0

    def test_magnitude_does_not_matter(self):
        assert cosine([3.0, 4.0], [30.0, 40.0]) == pytest.approx(1.0)


@pytest.mark.requires_extension
def test_builds_a_sidecar_from_a_real_export(insider_pair, tmp_path):
    """End to end over an actual .BinExport, including the delta-encoded
    instruction table walk."""
    from bindiff.metadata_embedding import build_sidecar

    metadata = build_sidecar(str(insider_pair[0]))

    assert metadata.functions, metadata.warnings
    assert metadata.executable_id
    for function in metadata.functions:
        feature = function.feature(FEATURE_MNEMONIC_HISTOGRAM)
        assert feature is not None
        assert feature.metric == METRIC_COSINE
        assert len(feature.vector) == DEFAULT_DIMENSION
        assert any(feature.vector), "a vector with no direction was emitted"


@pytest.mark.requires_extension
def test_a_function_is_nearer_to_itself_than_to_its_neighbours(insider_pair):
    """The weakest possible sanity check on the embedding, and the one that
    catches a producer that is emitting noise: the same function in the same
    binary must be its own nearest neighbour."""
    from bindiff.metadata_embedding import embed, function_mnemonics

    vectors = embed(function_mnemonics(str(insider_pair[0])))
    addresses = sorted(vectors)[:40]
    assert len(addresses) > 5

    for address in addresses:
        best = max(addresses,
                   key=lambda other: cosine(vectors[address], vectors[other]))
        assert best == address or cosine(
            vectors[address], vectors[best]) == pytest.approx(1.0, abs=1e-6)
