"""Porting stack-variable names into a database -- upstream issue #13.

Split from test_stack_names.py, which gates on the generated protobuf
bindings: reading an export needs them, deciding what to rename does not.

The two halves are deliberately separate. bindiff.stack_names reads names out
of a .BinExport; bindiff.stack_names_ida resolves the primary's own frame
offset and does the rename, because neither is knowable from the export --
987 of 2910 matched operands had different displacements on the measured
pair, a third of them.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


class TestGeneratedNamesWithHexSuffixes:
    """IDA writes its hex offsets with a trailing "h", on either half of a
    name: "var_80h" and "var_240+Ch". Missing that left 519 operands looking
    human-named on the measured pair -- every one of them a var_*, and every
    one refused by the rename as an invalid identifier."""

    @pytest.mark.parametrize("name", [
        "var_80h", "var_58h", "var_240+Ch", "var_38+Ch", "var_A0+Ch",
        "var_30+8", "var_50", "arg_0", "var_s0", "sub_140001000",
    ])
    def test_it_is_generated(self, name):
        from bindiff.stack_names import is_generated_name
        assert is_generated_name(name)

    @pytest.mark.parametrize("name", [
        "Src", "Str1", "pExceptionObject", "Block", "Size", "count",
    ])
    def test_a_real_name_is_not(self, name):
        from bindiff.stack_names import is_generated_name
        assert not is_generated_name(name)


class TestNamingAWholeVariable:
    """BinExport renders a reference into the middle of a slot as "Src+8",
    which names no variable: the variable is Src and the operand points eight
    bytes into it. It was written by a person, so it is not "generated" -- it
    is simply not a name."""

    @pytest.mark.parametrize("name", ["Src", "Str1", "_reserved", "a1"])
    def test_an_identifier_can_be_given_to_a_member(self, name):
        from bindiff.stack_names import names_a_whole_variable
        assert names_a_whole_variable(name)

    @pytest.mark.parametrize("name", ["Src+8", "Str1+8", "var_240+Ch",
                                      "8bad", "", None])
    def test_anything_else_cannot(self, name):
        from bindiff.stack_names import names_a_whole_variable
        assert not names_a_whole_variable(name)


class TestPlanningRenames:
    """The offset is deliberately not carried across. A .BinExport records
    the raw displacement in the instruction and the two sides do not agree:
    987 of 2910 matched operands differed on the measured pair. The name
    travels with the instruction and the primary's own offset is resolved
    against the database when the rename is applied."""

    class _Database:
        def __init__(self, pairs):
            self._pairs = pairs

        def matches(self):
            from types import SimpleNamespace
            return [SimpleNamespace(id=1, similarity=1.0, confidence=1.0,
                                    address_primary=0x1000,
                                    address_secondary=0x2000)]

        def instruction_matches_for(self, match_ids=None):
            return {1: self._pairs}

    def _named(self, name, offset=-0x50):
        from bindiff.stack_names import StackName
        return StackName(address=0x2005, operand_index=1, name=name,
                         offset=offset)

    def test_it_addresses_the_primary_instruction(self):
        from ida_plugin.porting import plan_stack_name_ports

        ports = plan_stack_name_ports(
            self._Database([(0x1005, 0x2005)]),
            {0x2005: {1: self._named("count")}})
        assert [(p.function, p.address, p.operand_index, p.name)
                for p in ports] == [(0x1000, 0x1005, 1, "count")]

    def test_it_carries_no_offset(self):
        """There is nowhere to put one, on purpose."""
        from ida_plugin.porting import plan_stack_name_ports

        ports = plan_stack_name_ports(
            self._Database([(0x1005, 0x2005)]),
            {0x2005: {1: self._named("count")}})
        assert not hasattr(ports[0], "offset")

    def test_a_sub_reference_is_not_planned(self):
        from ida_plugin.porting import plan_stack_name_ports

        assert plan_stack_name_ports(
            self._Database([(0x1005, 0x2005)]),
            {0x2005: {1: self._named("Src+8")}}) == []

    def test_an_unmatched_instruction_contributes_nothing(self):
        from ida_plugin.porting import plan_stack_name_ports

        assert plan_stack_name_ports(
            self._Database([(0x1005, 0x2009)]),
            {0x2005: {1: self._named("count")}}) == []

    def test_a_match_below_the_floor_is_skipped(self):
        from ida_plugin.porting import plan_stack_name_ports

        database = self._Database([(0x1005, 0x2005)])
        database.matches()[0].similarity = 0.1
        matches = database.matches
        from types import SimpleNamespace
        database.matches = lambda: [SimpleNamespace(
            id=1, similarity=0.1, confidence=1.0,
            address_primary=0x1000, address_secondary=0x2000)]
        assert plan_stack_name_ports(
            database, {0x2005: {1: self._named("count")}}) == []


class TestApplyingWithoutIda:
    def test_nothing_to_do_is_not_an_error(self):
        from bindiff.stack_names_ida import apply_stack_names
        assert apply_stack_names([]).applied == 0

    def test_it_refuses_without_a_database(self):
        from bindiff.stack_names_ida import StackNamePort, apply_stack_names

        with pytest.raises(RuntimeError, match="open IDA database"):
            apply_stack_names([StackNamePort(function=1, address=2,
                                             operand_index=0, name="x")])
