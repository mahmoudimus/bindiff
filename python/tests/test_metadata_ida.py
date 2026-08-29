"""Tests for the IDA-derived sidecar features.

The fixture .idb files are 32-bit databases IDA 9.x will not open without an
upgrade tool the test image does not ship, so these features cannot yet be
measured against the checked-in ground truth the way imports/v1 was. What can
be tested is everything that decides what a feature *is*, which is why the
extractors take a source interface instead of calling IDA directly.
"""

from __future__ import annotations

import pytest

from bindiff.metadata import (
    FEATURE_FRAME,
    FEATURE_IMPORTS,
    FEATURE_PROTOTYPE,
    BinaryMetadata,
    FunctionMetadata,
    imports_feature,
)
from bindiff.metadata_ida import (
    Frame,
    Prototype,
    build_metadata,
    merge,
)


class FakeSource:
    """A FunctionSource that is not IDA."""

    def __init__(self, functions):
        # {address: (Prototype | None, Frame | None, is_library)}
        self._functions = functions

    def function_addresses(self):
        return sorted(self._functions)

    def prototype(self, address):
        return self._functions[address][0]

    def frame(self, address):
        return self._functions[address][1]

    def is_library(self, address):
        return self._functions[address][2]


def _source(extra=None):
    """The baseline one-function source, plus any `extra` entries.

    A plain dict rather than **kwargs: the keys are addresses, and Python
    keyword arguments have to be strings.
    """
    functions = {
        0x401000: (Prototype("int", ["char *", "unsigned int"]),
                   Frame(size=64, argument_count=2, local_count=4), False),
    }
    functions.update(extra or {})
    return FakeSource(functions)


class TestPrototypeIsInformative:
    def test_a_recovered_signature_counts(self):
        assert Prototype("int", ["char *"]).is_informative
        assert Prototype("void", ["int", "int"]).is_informative

    def test_idas_default_guess_does_not(self):
        """IDA gives every unanalysed function `int __cdecl f()`.

        Emitting those would put thousands of functions in one bucket, so the
        feature would pair nothing while looking like it was working.
        """
        assert not Prototype("int", []).is_informative

    def test_a_real_nullary_function_counts_when_the_return_type_is_real(self):
        assert Prototype("char *", []).is_informative
        assert Prototype("void", []).is_informative

    def test_an_empty_return_type_does_not(self):
        assert not Prototype("", ["int"]).is_informative
        assert not Prototype("_UNKNOWN", []).is_informative


class TestBuildMetadata:
    def test_emits_both_features_with_readable_attributes(self):
        metadata = build_metadata(_source())
        assert len(metadata.functions) == 1
        function = metadata.functions[0]

        assert function.address == 0x401000
        assert function.feature(FEATURE_PROTOTYPE) is not None
        assert function.feature(FEATURE_FRAME) is not None
        # Readable forms exist for explaining a match, and are never matched on.
        assert function.attributes["prototype"] == "i32(i8*,u32)"
        assert "64 bytes" in function.attributes["frame"]

    def test_library_code_is_skipped_by_default(self):
        """Matched by name in practice, and usually the bulk of a binary; a
        prototype feature over thousands of identical CRT wrappers adds buckets
        without adding signal."""
        source = _source({0x402000: (Prototype("int", ["char *"]),
                                     Frame(16, 1, 1), True)})
        assert len(build_metadata(source).functions) == 1
        assert len(build_metadata(source, include_library=True).functions) == 2

    def test_a_function_with_neither_feature_is_omitted(self):
        source = _source({0x403000: (None, None, False)})
        addresses = [f.address for f in build_metadata(source).functions]
        assert addresses == [0x401000]

    def test_an_uninformative_prototype_is_dropped_but_the_frame_kept(self):
        source = FakeSource({0x401000: (Prototype("int", []),
                                        Frame(32, 0, 2), False)})
        function = build_metadata(source).functions[0]
        assert function.feature(FEATURE_PROTOTYPE) is None
        assert function.feature(FEATURE_FRAME) is not None

    def test_a_database_with_nothing_useful_says_so(self):
        """A half-populated sidecar must be recognisable as such rather than
        looking like a binary with genuinely few features."""
        metadata = build_metadata(FakeSource({0x401000: (None, None, False)}))
        assert not metadata.functions
        assert any("prototype" in w for w in metadata.warnings)
        assert any("frame" in w for w in metadata.warnings)

    def test_equivalent_spellings_produce_the_same_key(self):
        """The whole point of canonicalisation: two compilers will not spell a
        signature identically, and a feature that hashes them apart produces
        confident non-matches."""
        one = build_metadata(FakeSource({
            0x401000: (Prototype("unsigned int", ["char *", "unsigned long"]),
                       None, False)}))
        other = build_metadata(FakeSource({
            0x501000: (Prototype("uint32_t", ["int8_t *", "DWORD"]), None,
                       False)}))
        assert (one.functions[0].feature(FEATURE_PROTOTYPE).key
                == other.functions[0].feature(FEATURE_PROTOTYPE).key)

    def test_signedness_still_separates_them(self):
        """The converse, so the test above is not just proving that
        canonicalisation collapses everything to one key."""
        signed = build_metadata(FakeSource({
            0x401000: (Prototype("int", ["char *"]), None, False)}))
        unsigned = build_metadata(FakeSource({
            0x501000: (Prototype("int", ["unsigned char *"]), None, False)}))
        assert (signed.functions[0].feature(FEATURE_PROTOTYPE).key
                != unsigned.functions[0].feature(FEATURE_PROTOTYPE).key)


class TestMerge:
    def test_folds_features_in_by_address(self):
        """The two producers run separately -- one over the .BinExport, one
        inside IDA -- and both describe the same binary."""
        from_export = BinaryMetadata(functions=[
            FunctionMetadata(address=0x401000,
                             features=[imports_feature(["malloc", "free"])],
                             attributes={"imports": "free,malloc"})])
        from_ida = build_metadata(_source())

        merged = merge(from_export, from_ida)
        assert len(merged.functions) == 1
        function = merged.functions[0]
        assert function.feature(FEATURE_IMPORTS) is not None
        assert function.feature(FEATURE_PROTOTYPE) is not None
        assert function.attributes["imports"] == "free,malloc"
        assert function.attributes["prototype"] == "i32(i8*,u32)"

    def test_functions_only_one_side_knows_about_are_kept(self):
        from_export = BinaryMetadata(functions=[
            FunctionMetadata(address=0x400000,
                             features=[imports_feature(["a", "b"])])])
        merged = merge(from_export, build_metadata(_source()))
        assert [f.address for f in merged.functions] == [0x400000, 0x401000]

    def test_a_feature_is_not_duplicated(self):
        first = build_metadata(_source())
        second = build_metadata(_source())
        merged = merge(first, second)
        names = [f.name for f in merged.functions[0].features]
        assert len(names) == len(set(names))

    def test_the_result_is_ordered_by_address(self):
        from_export = BinaryMetadata(functions=[
            FunctionMetadata(address=0x900000,
                             features=[imports_feature(["a", "b"])]),
            FunctionMetadata(address=0x100000,
                             features=[imports_feature(["c", "d"])])])
        merged = merge(from_export, build_metadata(_source()))
        addresses = [f.address for f in merged.functions]
        assert addresses == sorted(addresses)

    def test_warnings_and_executable_id_carry_over(self):
        into = BinaryMetadata()
        other = BinaryMetadata(executable_id="deadbeef",
                               warnings=["no decompiler"])
        merged = merge(into, other)
        assert merged.executable_id == "deadbeef"
        assert "no decompiler" in merged.warnings

    def test_an_existing_executable_id_is_not_overwritten(self):
        into = BinaryMetadata(executable_id="original")
        merge(into, BinaryMetadata(executable_id="other"))
        assert into.executable_id == "original"


def test_the_module_imports_without_ida():
    """Importing ida_* outside a running IDA takes the interpreter down, so
    every such import has to be inside IdaSource, not at module scope.

    That this test file imported the module at all is most of the assertion;
    this pins it so a stray top-level `import ida_funcs` fails here rather than
    in a headless worker.
    """
    import ast
    import pathlib

    import bindiff.metadata_ida as module

    assert hasattr(module, "IdaSource")
    tree = ast.parse(pathlib.Path(module.__file__).read_text())
    top_level = [
        alias.name
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import)
                      else [ast.alias(name=node.module or "")])
    ]
    offenders = [name for name in top_level
                 if name.startswith(("ida_", "idautils", "idc", "idaapi"))]
    assert not offenders, f"IDA imported at module scope: {offenders}"


@pytest.mark.slow
def test_extracts_from_a_real_database(tmp_path):
    """IdaSource against a database that actually exists.

    The checked-in .idb fixtures are 32-bit and IDA 9.x will not open them
    without an upgrade tool the image does not ship, so a fresh binary is
    compiled instead -- the same approach test_headless.py uses for the export
    stage. This is the only thing that exercises the real IDA calls; everything
    above runs against a fake source.
    """
    import importlib.util
    import subprocess

    if importlib.util.find_spec("idapro") is None:
        pytest.skip("idalib not available")

    source = tmp_path / "sample.c"
    source.write_text(
        "#include <string.h>\n"
        "int scale(int x, unsigned n) { return x * (int)n; }\n"
        "char *pick(char *a, char *b, int which) { return which ? a : b; }\n"
        "int main(void) { char x[8]; memset(x, 0, sizeof x);\n"
        "                 return scale(3, 4) + (pick(x, x, 1) != 0); }\n")
    binary = tmp_path / "sample"
    try:
        subprocess.run(["gcc", "-O0", "-g", "-o", str(binary), str(source)],
                       check=True, capture_output=True, timeout=120)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("no C compiler to build a sample binary")

    import idapro

    assert idapro.open_database(str(binary), True) == 0
    try:
        from bindiff.metadata_ida import IdaSource, build_metadata

        ida_source = IdaSource()
        addresses = list(ida_source.function_addresses())
        assert addresses, "IDA found no functions in a freshly analysed binary"

        # The real calls must return something of the right shape, or None --
        # never raise. A wrong API name would surface right here.
        for address in addresses:
            prototype = ida_source.prototype(address)
            assert prototype is None or prototype.return_type
            frame = ida_source.frame(address)
            assert frame is None or frame.size >= 0
            assert isinstance(ida_source.is_library(address), bool)

        metadata = build_metadata(ida_source)
        # Not asserting a feature count: how much type information IDA recovers
        # without a decompiler varies by version and build. What must hold is
        # that it ran, and that anything it did emit is well formed.
        for function in metadata.functions:
            assert function.features
            assert function.address in addresses
    finally:
        idapro.close_database(False)
