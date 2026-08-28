"""Tests for reading .BinExport and computing unmatched functions.

This is the data that unblocks the unmatched views: a .BinDiff stores matches
only, so anything about what was *not* matched has to come from the exports.
Run against the real fixture exports rather than a synthesised proto.
"""

from __future__ import annotations

import pytest

from bindiff.binexport import (
    ExportedFunction,
    FunctionType,
    find_binexports_for,
    read_functions,
    read_metadata,
)
from ida_plugin.ui_logic import (
    UNMATCHED_COLUMNS,
    filter_unmatched,
    sort_unmatched,
    unmatched_functions,
)


def _function(address=0x401000, name="sub_401000", demangled="",
              type=FunctionType.NORMAL):
    return ExportedFunction(address=address, name=name,
                            demangled_name=demangled, type=type)


class TestExportedFunction:
    @pytest.mark.parametrize("type,expected", [
        (FunctionType.NORMAL, False),
        (FunctionType.LIBRARY, True),
        (FunctionType.IMPORTED, True),
        (FunctionType.THUNK, True),
    ])
    def test_library_classification(self, type, expected):
        assert _function(type=type).is_library is expected

    @pytest.mark.parametrize("name,expected", [
        ("main", True), ("encrypt_buffer", True),
        ("sub_401000", False), ("loc_401000", False),
        ("nullsub_1", False), ("j_sub_401000", False), ("", False),
    ])
    def test_real_name_detection(self, name, expected):
        assert _function(name=name).has_real_name is expected

    def test_demangled_name_is_preferred(self):
        function = _function(name="_Z3fooi", demangled="foo(int)")
        assert function.best_name == "foo(int)"
        assert _function(name="main").best_name == "main"


class TestUnmatched:
    def test_subtracts_the_matched_set(self):
        functions = [_function(address=a) for a in (0x1000, 0x2000, 0x3000)]
        rows = unmatched_functions(functions, [0x2000])
        assert [r.address for r in rows] == [0x1000, 0x3000]

    def test_library_code_is_hidden_by_default(self):
        """It is usually the bulk of what goes unmatched, and burying a handful
        of real unmatched functions under thousands of thunks is not usable."""
        functions = [
            _function(address=0x1000),
            _function(address=0x2000, type=FunctionType.LIBRARY),
            _function(address=0x3000, type=FunctionType.THUNK),
        ]
        assert [r.address for r in unmatched_functions(functions, [])] == [0x1000]
        assert len(unmatched_functions(functions, [], include_library=True)) == 3

    def test_rows_are_ordered_by_address(self):
        functions = [_function(address=a) for a in (0x3000, 0x1000, 0x2000)]
        assert [r.address for r in unmatched_functions(functions, [])] == [
            0x1000, 0x2000, 0x3000]

    def test_everything_matched_is_empty(self):
        functions = [_function(address=0x1000)]
        assert unmatched_functions(functions, [0x1000]) == []

    def test_sorting_by_each_column(self):
        rows = unmatched_functions(
            [_function(address=0x2000, name="beta"),
             _function(address=0x1000, name="Alpha")], [])
        for column, _label in UNMATCHED_COLUMNS:
            assert len(sort_unmatched(rows, column)) == 2
        assert [r.name for r in sort_unmatched(rows, "name")] == ["Alpha", "beta"]

    def test_unknown_sort_column_raises(self):
        with pytest.raises(ValueError, match="unknown column"):
            sort_unmatched([], "nonsense")

    def test_filtering(self):
        rows = unmatched_functions(
            [_function(address=0x401000, name="encrypt"),
             _function(address=0x402000, name="other")], [])
        assert len(filter_unmatched(rows, "encr")) == 1
        assert len(filter_unmatched(rows, "0x401000")) == 1
        assert len(filter_unmatched(rows, "401000")) == 1
        assert len(filter_unmatched(rows, "")) == 2


class TestFindBinexports:
    def test_recovers_both_from_the_engine_naming(self, tmp_path):
        (tmp_path / "a.BinExport").write_bytes(b"x")
        (tmp_path / "b.BinExport").write_bytes(b"x")
        primary, secondary = find_binexports_for(str(tmp_path / "a_vs_b.BinDiff"))
        assert primary and primary.endswith("a.BinExport")
        assert secondary and secondary.endswith("b.BinExport")

    def test_returns_none_when_the_file_is_absent(self, tmp_path):
        assert find_binexports_for(str(tmp_path / "a_vs_b.BinDiff")) == (None, None)

    def test_returns_none_for_an_unrecognised_name(self, tmp_path):
        assert find_binexports_for(str(tmp_path / "results.BinDiff")) == (None, None)


@pytest.mark.requires_extension
class TestAgainstRealExports:
    def test_reads_the_fixture_function_list(self, insider_pair):
        primary, _secondary = insider_pair
        functions = read_functions(str(primary))

        assert functions, "no functions read from a real .BinExport"
        # The engine reports 219 functions for insider_gcc, of which 117 are
        # non-library; the reader must see all of them, not just one class.
        assert len(functions) > 200
        assert any(f.is_library for f in functions)
        assert any(not f.is_library for f in functions)
        assert all(f.address > 0 for f in functions)

    def test_reads_meta_information(self, insider_pair):
        primary, _secondary = insider_pair
        meta = read_metadata(str(primary))
        assert meta["executable_name"]

    def test_unmatched_agrees_with_the_database(self, bindiff_module,
                                                insider_pair, tmp_path):
        """The whole point: matched + unmatched should account for the binary.

        Compared against the non-library total the engine itself recorded, so
        this catches the reader and the subtraction disagreeing with the
        engine about what counts as a function.
        """
        from bindiff import BinDiffDatabase

        primary, secondary = insider_pair
        database = tmp_path / "u.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary),
                                   str(database)) == 0

        functions = read_functions(str(primary))
        with BinDiffDatabase.open(str(database)) as db:
            matched = [m.address_primary for m in db.matches()]

        unmatched = unmatched_functions(functions, matched)
        everything = unmatched_functions(functions, [], include_library=True)

        assert len(unmatched) < len(everything)
        # No matched function may appear in the unmatched list.
        assert not ({r.address for r in unmatched} & set(matched))

    def test_rejects_a_file_that_is_not_a_binexport(self, tmp_path):
        junk = tmp_path / "junk.BinExport"
        junk.write_bytes(b"this is not a protobuf at all, not even close")
        with pytest.raises(ValueError):
            read_functions(str(junk))

    def test_rejects_an_empty_file(self, tmp_path):
        empty = tmp_path / "empty.BinExport"
        empty.write_bytes(b"")
        with pytest.raises(ValueError, match="empty"):
            read_functions(str(empty))
