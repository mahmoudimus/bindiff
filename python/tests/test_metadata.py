"""Tests for sidecar metadata construction.

Canonicalisation carries the weight here. A prototype feature that hashes
`unsigned int` and `uint32_t` differently is worse than having no feature: it
produces confident non-matches between two builds of the same function.
"""

from __future__ import annotations

import pytest

from bindiff.metadata import (
    FEATURE_CALLEE_SEQUENCE,
    FEATURE_PROTOTYPE,
    METRIC_COSINE,
    METRIC_EXACT,
    BinaryMetadata,
    Feature,
    FunctionMetadata,
    callee_sequence_feature,
    canonical_prototype,
    canonical_type,
    constants_feature,
    frame_feature,
    prototype_feature,
    stable_key,
)


class TestStableKey:
    def test_is_stable_across_processes(self):
        """Python's hash() is per-process randomised; a sidecar hashed with it
        would not agree between two runs."""
        import subprocess
        import sys

        script = ("import sys; sys.path.insert(0, %r);"
                  "from bindiff.metadata import stable_key;"
                  "print(stable_key('int(char*)'))" % _package_root())
        outputs = set()
        for seed in ("0", "1", "12345"):
            completed = subprocess.run(
                [sys.executable, "-c", script], capture_output=True, text=True,
                env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"})
            assert completed.returncode == 0, completed.stderr
            outputs.add(completed.stdout.strip())
        assert len(outputs) == 1, f"key varies with PYTHONHASHSEED: {outputs}"

    def test_fits_in_64_bits(self):
        assert 0 <= stable_key("anything") < 2 ** 64

    def test_differs_for_different_input(self):
        assert stable_key("a") != stable_key("b")


def _package_root() -> str:
    from pathlib import Path

    import bindiff

    return str(Path(bindiff.__file__).resolve().parent.parent)


class TestTypeCanonicalisation:
    @pytest.mark.parametrize("spellings", [
        ("unsigned int", "uint32_t", "unsigned __int32", "DWORD", "unsigned"),
        ("int", "__int32", "int32_t", "signed int", "long"),
        ("unsigned char", "uint8_t", "BYTE", "unsigned __int8"),
        ("unsigned long long", "uint64_t", "QWORD", "size_t"),
        ("__int64", "long long", "int64_t"),
    ])
    def test_equivalent_spellings_agree(self, spellings):
        canonical = {canonical_type(s) for s in spellings}
        assert len(canonical) == 1, f"{spellings} -> {canonical}"

    def test_distinct_widths_stay_distinct(self):
        assert canonical_type("uint32_t") != canonical_type("uint64_t")
        assert canonical_type("int") != canonical_type("unsigned int")

    def test_pointer_depth_is_preserved(self):
        assert canonical_type("char *") != canonical_type("char")
        assert canonical_type("char **") != canonical_type("char *")

    def test_pointed_at_type_is_reduced_to_a_width(self):
        assert canonical_type("unsigned char *") == canonical_type("uint8_t *")

    def test_qualifiers_are_ignored(self):
        assert canonical_type("const char *") == canonical_type("char *")
        assert canonical_type("volatile int") == canonical_type("int")

    def test_calling_conventions_are_ignored(self):
        assert canonical_type("__fastcall int") == canonical_type("int")

    def test_struct_names_do_not_survive(self):
        """A struct recovered from two binaries rarely has the same name;
        keeping it would make every prototype unique."""
        assert canonical_type("struct _FOO *") == canonical_type("struct _BAR *")

    def test_arrays_decay_to_pointers(self):
        assert canonical_type("char[16]") == canonical_type("char *")

    def test_empty_and_none_are_handled(self):
        assert canonical_type("") == "?"
        assert canonical_type(None) == "?"


class TestPrototype:
    def test_same_prototype_different_spelling_hashes_equal(self):
        a = prototype_feature("unsigned int", ["char *", "unsigned int"])
        b = prototype_feature("uint32_t", ["const char *", "DWORD"])
        assert a.key == b.key

    def test_different_arity_differs(self):
        assert (prototype_feature("int", ["int"]).key
                != prototype_feature("int", ["int", "int"]).key)

    def test_parameter_order_matters(self):
        assert (prototype_feature("int", ["char *", "int"]).key
                != prototype_feature("int", ["int", "char *"]).key)

    def test_rendering_is_readable(self):
        assert canonical_prototype("int", ["char *", "unsigned int"]) == "i32(i8*,u32)"

    def test_void_no_args(self):
        assert canonical_prototype("void", []) == "void()"


class TestFrame:
    def test_small_size_differences_do_not_split_a_function(self):
        """Frame size shifts by a few bytes between builds for reasons that
        have nothing to do with identity."""
        assert frame_feature(64, 2, 3).key == frame_feature(72, 2, 3).key

    def test_large_differences_do_split(self):
        assert frame_feature(16, 2, 3).key != frame_feature(256, 2, 3).key

    def test_argument_count_matters(self):
        assert frame_feature(64, 2, 3).key != frame_feature(64, 4, 3).key


class TestCalleeSequence:
    def test_order_matters(self):
        assert (callee_sequence_feature(["a", "b"]).key
                != callee_sequence_feature(["b", "a"]).key)

    def test_same_sequence_agrees(self):
        assert (callee_sequence_feature(["a", "b"]).key
                == callee_sequence_feature(["a", "b"]).key)

    def test_empty_is_still_a_valid_feature(self):
        assert callee_sequence_feature([]).name == FEATURE_CALLEE_SEQUENCE


class TestConstants:
    def test_uninteresting_small_values_are_dropped(self):
        """0/1/2 appear everywhere; including them makes every function look
        alike."""
        assert (constants_feature([0, 1, 2, 0xDEADBEEF]).key
                == constants_feature([0xDEADBEEF]).key)

    def test_order_does_not_matter(self):
        assert (constants_feature([0xAAAA, 0xBBBB]).key
                == constants_feature([0xBBBB, 0xAAAA]).key)

    def test_duplicates_do_not_matter(self):
        assert (constants_feature([0xAAAA, 0xAAAA]).key
                == constants_feature([0xAAAA]).key)


class TestFeatureValidation:
    def test_exactly_one_value_is_required(self):
        with pytest.raises(ValueError, match="exactly one"):
            Feature(name="x", metric=METRIC_EXACT)
        with pytest.raises(ValueError, match="exactly one"):
            Feature(name="x", metric=METRIC_EXACT, key=1, packed=b"a")

    def test_metric_and_value_must_agree(self):
        with pytest.raises(ValueError, match="carries no vector"):
            Feature(name="x", metric=METRIC_COSINE, key=1)


class TestDescriptors:
    def test_counts_each_feature(self):
        meta = BinaryMetadata(functions=[
            FunctionMetadata(address=0x1000,
                             features=[prototype_feature("int", ["int"])]),
            FunctionMetadata(address=0x2000,
                             features=[prototype_feature("void", []),
                                       frame_feature(16, 0, 0)]),
        ])
        by_name = {d["name"]: d for d in meta.descriptors()}
        assert by_name[FEATURE_PROTOTYPE]["count"] == 2
        assert by_name[FEATURE_PROTOTYPE]["metric"] == METRIC_EXACT

    def test_vector_dimension_is_recorded(self):
        meta = BinaryMetadata(functions=[FunctionMetadata(
            address=0x1000,
            features=[Feature(name="asm2vec/v1", metric=METRIC_COSINE,
                              vector=[0.1] * 128)])])
        assert meta.descriptors()[0]["dimension"] == 128

    def test_inconsistent_dimensions_are_rejected(self):
        """Vectors of different length are not comparable, and silently
        keeping both would make a nearest-neighbour pass meaningless."""
        meta = BinaryMetadata(functions=[
            FunctionMetadata(address=0x1000, features=[
                Feature(name="asm2vec/v1", metric=METRIC_COSINE,
                        vector=[0.1] * 128)]),
            FunctionMetadata(address=0x2000, features=[
                Feature(name="asm2vec/v1", metric=METRIC_COSINE,
                        vector=[0.1] * 64)]),
        ])
        with pytest.raises(ValueError, match="inconsistent dimensions"):
            meta.descriptors()

    def test_empty_metadata_has_no_descriptors(self):
        assert BinaryMetadata().descriptors() == []
