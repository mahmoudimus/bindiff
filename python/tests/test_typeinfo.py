"""Tests for ordering C type definitions so they parse.

BinExport2 cannot represent a type, so porting types is IDA-to-IDA and the
whole difficulty is order: a prototype cannot be applied until the types it
names exist, and those types reference each other.

Diaphora calls parse_decls in a loop ten times and lets successes accumulate.
That works and hides which definitions were actually circular; this sorts them
and reports what could not be sorted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "bindiff_typeinfo", _ROOT / "bindiff" / "typeinfo.py")
typeinfo = importlib.util.module_from_spec(_spec)
sys.modules["bindiff_typeinfo"] = typeinfo
_spec.loader.exec_module(typeinfo)

TypeDeclaration = typeinfo.TypeDeclaration
FunctionType = typeinfo.FunctionType


def decl(name, definition, kind="struct"):
    return TypeDeclaration(name=name, definition=definition, kind=kind)


class TestFindingReferences:
    def test_a_known_type_is_found(self):
        known = {"Header", "Flags"}
        found = typeinfo.referenced_types(
            "struct Body { Header h; int n; Flags f; };", known)
        assert found == {"Header", "Flags"}

    def test_keywords_and_builtins_are_not_types(self):
        found = typeinfo.referenced_types(
            "struct X { unsigned int n; const char *s; };",
            {"int", "char", "unsigned", "const"})
        assert found == set()

    def test_an_unknown_identifier_is_not_a_type(self):
        """Field names, macros and half the standard library look like type
        names to a regex, which is why this matches against a known set."""
        found = typeinfo.referenced_types(
            "struct X { SomeMacro n; int fieldName; };", {"Header"})
        assert found == set()


class TestPointerReferences:
    def test_a_pointer_only_use_is_recognised(self):
        assert typeinfo.pointer_only_references(
            "struct Node { Node *next; };", {"Node"}) == {"Node"}

    def test_a_by_value_use_is_not(self):
        assert typeinfo.pointer_only_references(
            "struct Body { Header h; };", {"Header"}) == set()

    def test_mixed_use_counts_as_by_value(self):
        """One by-value member is enough to need the complete type, however
        many pointers there also are."""
        assert typeinfo.pointer_only_references(
            "struct X { Header *p; Header h; };", {"Header"}) == set()


class TestOrdering:
    def test_a_dependency_comes_first(self):
        plan = typeinfo.order_declarations([
            decl("Body", "struct Body { Header h; };"),
            decl("Header", "struct Header { int n; };"),
        ])
        assert [d.name for d in plan.declarations] == ["Header", "Body"]
        assert plan.unresolved == []

    def test_a_chain_is_ordered_throughout(self):
        plan = typeinfo.order_declarations([
            decl("C", "struct C { B b; };"),
            decl("A", "struct A { int n; };"),
            decl("B", "struct B { A a; };"),
        ])
        assert [d.name for d in plan.declarations] == ["A", "B", "C"]

    def test_independent_types_are_ordered_stably(self):
        """Reproducible output: a plan that changes between runs makes a diff
        of two exports unreadable."""
        given = [decl("Zebra", "struct Zebra { int n; };"),
                 decl("Apple", "struct Apple { int n; };")]
        first = typeinfo.order_declarations(given)
        second = typeinfo.order_declarations(list(reversed(given)))
        assert ([d.name for d in first.declarations]
                == [d.name for d in second.declarations] == ["Apple", "Zebra"])


class TestCycles:
    def test_a_self_pointer_is_not_a_cycle(self):
        plan = typeinfo.order_declarations([
            decl("Node", "struct Node { Node *next; int v; };"),
        ])
        assert [d.name for d in plan.declarations] == ["Node"]
        assert plan.unresolved == []

    def test_a_pointer_cycle_is_broken_by_forward_declarations(self):
        plan = typeinfo.order_declarations([
            decl("A", "struct A { B *b; };"),
            decl("B", "struct B { A *a; };"),
        ])
        assert plan.unresolved == []
        assert set(plan.forward_declarations) == {"struct A;", "struct B;"}
        # And the forward declarations come before the definitions.
        assert plan.statements[:2] == ["struct A;", "struct B;"]

    def test_a_by_value_cycle_is_reported_not_retried(self):
        """No ordering fixes this and no number of retries will either. C
        cannot express it, so it is the caller's to report."""
        plan = typeinfo.order_declarations([
            decl("A", "struct A { B b; };"),
            decl("B", "struct B { A a; };"),
        ])
        assert plan.unresolved == ["A", "B"]
        assert plan.declarations == []

    def test_a_typedef_cannot_be_forward_declared(self):
        """struct X; is legal, typedef X; is not, so a typedef cycle stays a
        cycle."""
        declaration = decl("Handle", "typedef Other *Handle;", kind="typedef")
        assert declaration.forward_declaration is None


class TestWhatFunctionsNeed:
    def test_transitive_references_are_collected(self):
        declarations = [
            decl("Header", "struct Header { Flags f; };"),
            decl("Flags", "enum Flags { A, B };", kind="enum"),
            decl("Unused", "struct Unused { int n; };"),
        ]
        needed = typeinfo.needed_by(
            [FunctionType(address=0x1000,
                          declaration="int parse(Header *h);")],
            declarations)
        assert needed == {"Header", "Flags"}

    def test_a_function_needing_nothing_needs_nothing(self):
        needed = typeinfo.needed_by(
            [FunctionType(address=0x1000, declaration="int f(int a);")],
            [decl("Header", "struct Header { int n; };")])
        assert needed == set()


class TestTypesTheTargetAlreadyHas:
    """The efficient case, and the common one: if hexrays.til is loaded in the
    target then mblock_t is already there and only the prototype is missing."""

    def test_a_present_type_is_not_emitted_again(self):
        plan = typeinfo.order_declarations(
            [decl("mblock_t", "struct mblock_t { int serial; };")],
            already_present={"mblock_t"})
        assert plan.declarations == []
        assert plan.unresolved == []

    def test_a_present_type_satisfies_a_dependency(self):
        """Body needs mblock_t; the target has it; so Body can be emitted
        without emitting mblock_t."""
        plan = typeinfo.order_declarations(
            [decl("Body", "struct Body { mblock_t m; };"),
             decl("mblock_t", "struct mblock_t { int serial; };")],
            already_present={"mblock_t"})
        assert [d.name for d in plan.declarations] == ["Body"]
        assert plan.unresolved == []

    def test_a_dependency_on_something_absent_still_orders(self):
        plan = typeinfo.order_declarations(
            [decl("Body", "struct Body { mblock_t m; Flags f; };"),
             decl("Flags", "enum Flags { A };", kind="enum"),
             decl("mblock_t", "struct mblock_t { int serial; };")],
            already_present={"mblock_t"})
        assert [d.name for d in plan.declarations] == ["Flags", "Body"]

    def test_a_cycle_through_a_present_type_is_not_a_cycle(self):
        plan = typeinfo.order_declarations(
            [decl("A", "struct A { mblock_t m; };"),
             decl("mblock_t", "struct mblock_t { A a; };")],
            already_present={"mblock_t"})
        assert [d.name for d in plan.declarations] == ["A"]
        assert plan.unresolved == []


class TestPlanningOnlyWhatIsNeeded:
    def test_unreferenced_types_are_left_alone(self):
        """Porting a whole type library because one function was imported is
        not a favour."""
        declarations = [decl("mblock_t", "struct mblock_t { int serial; };"),
                        decl("Unrelated", "struct Unrelated { int n; };")]
        functions = [FunctionType(
            address=0x130236AB0,
            declaration="mblock_t *__fastcall resolve_goto_target("
                        "mblock_t *blk, bool require_single_pred)")]
        plan = typeinfo.plan_types(declarations, functions)
        assert [d.name for d in plan.declarations] == ["mblock_t"]

    def test_nothing_needed_plans_nothing(self):
        plan = typeinfo.plan_types(
            [decl("mblock_t", "struct mblock_t { int serial; };")],
            [FunctionType(address=0x1000, declaration="int f(int a);")])
        assert plan.declarations == []

    def test_the_real_example_needs_nothing_when_the_til_is_loaded(self):
        """resolve_goto_target's prototype names mblock_t and bool. With
        hexrays.til loaded the target has mblock_t, and bool is a builtin, so
        the plan is empty and only the prototype is applied."""
        plan = typeinfo.plan_types(
            [decl("mblock_t", "struct mblock_t { int serial; };")],
            [FunctionType(
                address=0x130236AB0,
                declaration="mblock_t *__fastcall resolve_goto_target("
                            "mblock_t *blk, bool require_single_pred)")],
            already_present={"mblock_t"})
        assert plan.statements == []


class TestTheSidecarFormat:
    """Types travel in their own JSON file, not in the protobuf sidecar: the
    C++ engine parses that one and will never read a type."""

    def test_a_round_trip_preserves_everything(self):
        declarations = [decl("mblock_t", "struct mblock_t { int serial; };"),
                        decl("mopt_t", "enum mopt_t { A, B };", kind="enum")]
        functions = [FunctionType(
            address=0x18008D120, name="resolve_goto_target",
            declaration="mblock_t *__fastcall resolve_goto_target("
                        "mblock_t *blk, bool require_single_pred)")]
        data = typeinfo.to_json(declarations, functions, source="/x/y.i64")
        back_types, back_functions = typeinfo.from_json(data)
        assert back_types == declarations
        assert back_functions == functions

    def test_the_kind_survives_because_forward_declaration_depends_on_it(self):
        data = typeinfo.to_json([decl("E", "enum E { A };", kind="enum")], [])
        back, _ = typeinfo.from_json(data)
        assert back[0].forward_declaration == "enum E;"

    def test_an_unknown_version_is_refused(self):
        """Read as if it were the current shape, a future sidecar would be
        misread rather than rejected."""
        with pytest.raises(ValueError, match="version"):
            typeinfo.from_json({"version": 99, "types": [], "functions": []})

    def test_incomplete_entries_are_dropped(self):
        data = {"version": typeinfo.TYPES_FORMAT_VERSION,
                "types": [{"name": "X"}, {"definition": "struct Y {};"}],
                "functions": [{"address": 1, "name": "f"}]}
        types, functions = typeinfo.from_json(data)
        assert types == [] and functions == []

    def test_the_path_sits_beside_its_source(self):
        assert typeinfo.types_path_for("/a/b/hexx64-9.3.i64") == \
            "/a/b/hexx64-9.3.i64.types.json"
