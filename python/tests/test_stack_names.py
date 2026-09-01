"""Tests for recovering stack-variable names from a .BinExport.

Upstream issue #13 is "Variable names are not being imported anymore", and
BinExport2 has no locals table, so the first read of the schema says the data
is not there. It is: a stack operand is an IMMEDIATE_INT expression carrying
both the displacement and its name.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

pytest.importorskip("google.protobuf")
_pb = pytest.importorskip("bindiff._pb.binexport2_pb2")

_spec = importlib.util.spec_from_file_location(
    "bindiff_stack_names", _ROOT / "bindiff" / "stack_names.py")
stack_names = importlib.util.module_from_spec(_spec)
sys.modules["bindiff_stack_names"] = stack_names
_spec.loader.exec_module(stack_names)

E = _pb.BinExport2.Expression


def build_export(tmp_path, operands):
    """One instruction at 0x1000 whose operands are described by `operands`,
    a list of (expression_type, symbol, immediate_or_None)."""
    proto = _pb.BinExport2()
    instruction = proto.instruction.add()
    instruction.address = 0x1000
    instruction.raw_bytes = b"\x90\x90"

    for kind, symbol, immediate in operands:
        expression = proto.expression.add()
        expression.type = kind
        if symbol is not None:
            expression.symbol = symbol
        if immediate is not None:
            expression.immediate = immediate
        operand = proto.operand.add()
        operand.expression_index.append(len(proto.expression) - 1)
        instruction.operand_index.append(len(proto.operand) - 1)

    path = tmp_path / "sample.BinExport"
    path.write_bytes(proto.SerializeToString())
    return path


class TestWhatCountsAsAVariable:
    def test_a_named_immediate_is_one(self, tmp_path):
        path = build_export(tmp_path, [(E.IMMEDIATE_INT, "myThing", 8)])
        found = stack_names.read_stack_names(path)
        assert [(f.name, f.offset, f.operand_index) for f in found] == [
            ("myThing", 8, 0)]

    @pytest.mark.parametrize("kind,symbol", [
        (E.REGISTER, "rbp"),
        (E.SIZE_PREFIX, "ss:"),
        (E.OPERATOR, "+"),
        (E.DEREFERENCE, "["),
    ])
    def test_other_expression_kinds_are_not(self, tmp_path, kind, symbol):
        """Every expression kind uses the symbol field. Reading it without
        checking the type returns registers and punctuation as "names"."""
        path = build_export(tmp_path, [(kind, symbol, None)])
        assert stack_names.read_stack_names(path) == []

    def test_an_immediate_without_a_symbol_is_not(self, tmp_path):
        path = build_export(tmp_path, [(E.IMMEDIATE_INT, None, 42)])
        assert stack_names.read_stack_names(path) == []


class TestGeneratedNames:
    @pytest.mark.parametrize("name", [
        "var_50", "arg_18", "var_F0", "var_s0",
        "var_30+8", "var_128+4", "arg_0+10", "sub_401000", "off_1802D36C0",
    ])
    def test_disassembler_names_are_dropped(self, name):
        """var_50 in one binary has no relationship to var_50 in another, and
        the +N forms are how IDA renders a reference into the middle of a
        slot -- missing them left a quarter of the results looking meaningful
        when none of them were."""
        assert stack_names.is_generated_name(name)

    @pytest.mark.parametrize("name", [
        "Src", "Str1", "pExceptionObject", "Block", "Size", "my_local",
    ])
    def test_real_names_are_kept(self, name):
        assert not stack_names.is_generated_name(name)

    def test_include_generated_returns_them_anyway(self, tmp_path):
        """Useful for inspecting an export; never for porting."""
        path = build_export(tmp_path, [(E.IMMEDIATE_INT, "var_50", 16)])
        assert stack_names.read_stack_names(path) == []
        assert len(stack_names.read_stack_names(
            path, include_generated=True)) == 1


class TestOffsets:
    def test_a_negative_displacement_reads_as_negative(self, tmp_path):
        """Frame offsets below the frame pointer arrive as large unsigned
        integers; -104 as 18446744073709551512 is not actionable."""
        path = build_export(
            tmp_path, [(E.IMMEDIATE_INT, "myThing", (1 << 64) - 104)])
        assert stack_names.read_stack_names(path)[0].offset == -104

    def test_a_positive_displacement_is_untouched(self, tmp_path):
        path = build_export(tmp_path, [(E.IMMEDIATE_INT, "anArg", 8)])
        assert stack_names.read_stack_names(path)[0].offset == 8


class TestGrouping:
    def test_keyed_by_address_and_operand(self, tmp_path):
        path = build_export(tmp_path, [
            (E.REGISTER, "rax", None),
            (E.IMMEDIATE_INT, "myThing", 8),
        ])
        grouped = stack_names.stack_names_by_operand(path)
        assert list(grouped) == [0x1000]
        assert grouped[0x1000][1].name == "myThing"
        # Operand 0 was a register, so it is absent rather than empty.
        assert 0 not in grouped[0x1000]
