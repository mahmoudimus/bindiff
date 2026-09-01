"""Tests for reading comments out of a .BinExport with their types intact.

The engine's own reader keys comments by (address, operand) in a map, so
several comments at one address collapse into one entry. A documented
function typically carries three -- a LOCATION comment holding its name, a
FUNCTION comment, and a DEFAULT one -- and the survivor was the name. Porting
then wrote the function's own name over its documentation, which from outside
looked like comments not being ported at all.

Exports are built here as protobufs rather than read from a fixture, so the
placement rules are exercised directly.
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

# Loaded by path: bindiff/__init__ pulls in the Cython extension, and this
# module needs only the protobuf bindings.
_spec = importlib.util.spec_from_file_location(
    "bindiff_comments", _ROOT / "bindiff" / "comments.py")
comments_mod = importlib.util.module_from_spec(_spec)
sys.modules["bindiff_comments"] = comments_mod
_spec.loader.exec_module(comments_mod)


def build_export(tmp_path, instructions, comments):
    """A minimal BinExport2.

    `instructions` is a list of (address_or_None, length); `comments` a list of
    (instruction_index, text, type_name).
    """
    proto = _pb.BinExport2()
    for address, length in instructions:
        instruction = proto.instruction.add()
        if address is not None:
            instruction.address = address
        instruction.raw_bytes = b"\x90" * length

    strings = {}
    for _index, text, _type in comments:
        if text not in strings:
            strings[text] = len(proto.string_table)
            proto.string_table.append(text)

    for index, text, type_name in comments:
        comment = proto.comment.add()
        comment.instruction_index = index
        comment.string_table_index = strings[text]
        comment.type = getattr(_pb.BinExport2.Comment, type_name)

    path = tmp_path / "sample.BinExport"
    path.write_bytes(proto.SerializeToString())
    return path


class TestAddressRecovery:
    """BinExport2 omits `address` when an instruction follows the previous
    one, so the list has to be walked."""

    def test_an_implicit_address_is_recovered(self, tmp_path):
        path = build_export(
            tmp_path,
            [(0x1000, 4), (None, 2), (None, 3)],
            [(1, "second", "DEFAULT"), (2, "third", "DEFAULT")])
        found = {c.address: c.text for c in comments_mod.read_comments(path)}
        assert found == {0x1004: "second", 0x1006: "third"}

    def test_an_explicit_address_restarts_the_run(self, tmp_path):
        path = build_export(
            tmp_path,
            [(0x1000, 4), (None, 4), (0x2000, 4)],
            [(1, "follows", "DEFAULT"), (2, "jumps", "DEFAULT")])
        found = {c.address: c.text for c in comments_mod.read_comments(path)}
        assert found == {0x1004: "follows", 0x2000: "jumps"}


class TestKeepingEveryComment:
    def test_three_at_one_address_all_survive(self, tmp_path):
        """The defect this exists for: the engine kept one and it was the
        name."""
        path = build_export(
            tmp_path, [(0x1000, 4)],
            [(0, "the documentation", "FUNCTION"),
             (0, "the documentation", "DEFAULT"),
             (0, "the_name", "LOCATION")])
        found = comments_mod.read_comments(path)
        assert len(found) == 3
        assert {c.type for c in found} == {"FUNCTION", "DEFAULT", "LOCATION"}

    def test_empty_text_is_dropped(self, tmp_path):
        path = build_export(tmp_path, [(0x1000, 4)],
                            [(0, "", "DEFAULT")])
        assert comments_mod.read_comments(path) == []


class TestWhatIsPortable:
    def test_a_location_comment_is_not_carried(self, tmp_path):
        """It holds the location's own name. Symbol porting already handles
        names, and carrying it would overwrite a real comment with one."""
        path = build_export(
            tmp_path, [(0x1000, 4)],
            [(0, "the_name", "LOCATION"),
             (0, "the documentation", "FUNCTION")])
        grouped = comments_mod.portable_comments(path)
        assert [c.text for c in grouped[0x1000]] == ["the documentation"]

    def test_reference_comments_are_not_carried(self, tmp_path):
        """They name a global or local in *this* binary; carried across they
        assert something about addresses that do not exist there."""
        path = build_export(
            tmp_path, [(0x1000, 4)],
            [(0, "off_1802D36C0", "GLOBAL_REFERENCE"),
             (0, "local thing", "LOCAL_REFERENCE")])
        assert comments_mod.portable_comments(path) == {}

    def test_function_and_instruction_comments_are_both_kept(self, tmp_path):
        """One address legitimately holds both, and they go to different
        places in IDA."""
        path = build_export(
            tmp_path, [(0x1000, 4)],
            [(0, "about the function", "FUNCTION"),
             (0, "about this instruction", "DEFAULT")])
        grouped = comments_mod.portable_comments(path)
        assert len(grouped[0x1000]) == 2

    def test_anterior_and_posterior_are_portable(self, tmp_path):
        """Real sentences, not single words: a bare token is what IDA writes
        at a call site, and the filter drops those. The first version of this
        test used "above" and "below" and started failing the moment the
        filter learned about them, which is the filter working."""
        path = build_export(
            tmp_path, [(0x1000, 4)],
            [(0, "set up the frame before the call", "ANTERIOR"),
             (0, "the result is in rax here", "POSTERIOR")])
        assert len(comments_mod.portable_comments(path)[0x1000]) == 2


class TestChoosingOne:
    def test_a_function_comment_wins(self, tmp_path):
        path = build_export(
            tmp_path, [(0x1000, 4)],
            [(0, "short instruction note", "DEFAULT"),
             (0, "the function documentation", "FUNCTION")])
        best = comments_mod.best_for_address(
            comments_mod.portable_comments(path)[0x1000])
        assert best.type == "FUNCTION"

    def test_otherwise_the_longest(self, tmp_path):
        path = build_export(
            tmp_path, [(0x1000, 4)],
            [(0, "short", "DEFAULT"), (0, "a much longer note", "ANTERIOR")])
        best = comments_mod.best_for_address(
            comments_mod.portable_comments(path)[0x1000])
        assert best.text == "a much longer note"

    def test_nothing_is_none(self):
        assert comments_mod.best_for_address([]) is None


class TestFilteringIdasOwnComments:
    """13,218 portable comments on a real export, of which 285 are human.

    Porting the rest carries the other binary's boilerplate into someone's
    database, where it overwrites what IDA generates natively -- with the
    wrong addresses in it.
    """

    @pytest.mark.parametrize("text", [
        "Trap to Debugger",
        "switch jump",
        "jumptable 0000000180191217 case 82",
        "switch 18 cases",
        "; Section 1. (virtual address 00001000)",
        "void (__cdecl *)()",
        "Size",
        "Src",
        "void *",
        "unsigned int",
        "",
        "   ",
    ])
    def test_idas_own_are_refused(self, text):
        assert comments_mod.is_generated_comment(text)

    @pytest.mark.parametrize("text", [
        "Merge-chain entry test: v7->succset.n == 1",
        "Test mblock_t.flags (+0x18) & 0x10000 -- qualifies for DCE sweep",
        "mba_remove_empty_and_unreachable_blocks -- the CFG sweep.",
        "this is wrong, see the other branch",
    ])
    def test_a_persons_note_is_kept(self, text):
        assert not comments_mod.is_generated_comment(text)

    def test_concatenated_annotations_are_refused(self):
        """IDA joins several of its own comments at one address into one
        multi-line string. Anchored patterns match none of it, which is why
        jumptable annotations survived the first version of this filter."""
        text = ("jumptable 00000001802B4A5C cases 53-57,61-85\n"
                "jumptable 00000001802B4A5C default case")
        assert comments_mod.is_generated_comment(text)

    def test_a_real_note_beside_an_annotation_is_kept(self):
        """All lines boilerplate is what makes the whole boilerplate; one
        real line means somebody wrote something."""
        text = ("jumptable 00000001802B4A5C cases 53-57\n"
                "this dispatch is the hot path")
        assert not comments_mod.is_generated_comment(text)

    def test_include_generated_turns_it_off(self, tmp_path):
        path = build_export(tmp_path, [(0x1000, 4)],
                            [(0, "Trap to Debugger", "DEFAULT")])
        assert comments_mod.portable_comments(path) == {}
        assert comments_mod.portable_comments(
            path, include_generated=True)[0x1000]
