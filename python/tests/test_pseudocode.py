"""Comments written in the decompiler view.

Hex-Rays keeps these in its own store, keyed by a treeloc (an address plus an
item preciser), reached through restore_user_cmts / save_user_cmts. They are
not disassembly comments -- set_cmt never sees them and neither does
BinExport. Measured on a real 9.3 database: the same note existed twice, at
two different addresses,

    disassembly comment  @ 0x180097611   the `mov ecx, 0C9A1h`
    decompiler comment   @ 0x180097616   the `call`, itp 69

and porting only the first is what made an imported function carry the
comment in the disassembly and not in the pseudocode.
"""

from __future__ import annotations

import pytest

from bindiff.pseudocode import (PseudocodeComment, by_function, from_json,
                                to_json, translate)


class TestRoundTrip:
    def test_it_survives_the_sidecar(self):
        comments = [PseudocodeComment(0x1000, 0x1010, 69, "note"),
                    PseudocodeComment(0x1000, 0x1020, 4, "other")]
        assert from_json(to_json(comments)) == comments

    def test_a_sidecar_without_the_section_reads_as_none(self):
        """An older sidecar is an older file, not a broken one -- its types
        are still good."""
        assert from_json([]) == []
        assert from_json(None) == []

    def test_an_entry_without_text_is_dropped(self):
        assert from_json([{"function": 1, "address": 2, "item": 3,
                           "text": ""}]) == []

    def test_a_malformed_entry_does_not_take_the_rest_with_it(self):
        good = {"function": 1, "address": 2, "item": 3, "text": "keep"}
        assert len(from_json([{"text": "no address"}, good])) == 1


class TestTranslation:
    def _comment(self, address, text="note"):
        return PseudocodeComment(0x180097180, address, 69, text)

    def test_it_moves_onto_the_primary_address(self):
        ported = translate([self._comment(0x180097616)],
                           {0x180097616: 0x130070556}, 0x1300700e0)
        assert [(c.function, c.address, c.item) for c in ported] == [
            (0x1300700e0, 0x130070556, 69)]

    def test_an_unmatched_address_is_dropped_not_guessed(self):
        """Hex-Rays takes any treeloc without complaint and then discards the
        ones that do not land on a ctree item. A guess would read as a
        comment that ported and then vanished."""
        assert translate([self._comment(0x180097616)], {}, 0x1300700e0) == []

    def test_the_item_preciser_is_carried_verbatim(self):
        """It names a position in the printed line -- after the semicolon, on
        argument three -- and means the same thing in either database."""
        ported = translate([PseudocodeComment(1, 0x10, 71, "x")],
                           {0x10: 0x20}, 0x30)
        assert ported[0].item == 71

    def test_the_text_is_untouched(self):
        ported = translate([self._comment(0x10, "INTERR 51617 (0xC9A1)")],
                           {0x10: 0x20}, 0x30)
        assert ported[0].text == "INTERR 51617 (0xC9A1)"


class TestGrouping:
    def test_it_groups_by_entry_point(self):
        """save_user_cmts takes a whole function's set at once, so the writer
        has to see them a function at a time."""
        grouped = by_function([PseudocodeComment(0x100, 0x110, 1, "a"),
                               PseudocodeComment(0x100, 0x120, 1, "b"),
                               PseudocodeComment(0x200, 0x210, 1, "c")])
        assert sorted(grouped) == [0x100, 0x200]
        assert len(grouped[0x100]) == 2


class TestWithoutADecompiler:
    """Hex-Rays is licensed separately. Every entry point degrades to "none"
    rather than raising: a missing decompiler is a smaller loss than a failed
    export, and it must never cost the comments and names that did go."""

    def test_reading_returns_nothing(self):
        from bindiff.pseudocode_ida import read_pseudocode_comments
        assert read_pseudocode_comments() == []

    def test_writing_refuses_rather_than_raising(self):
        from bindiff.pseudocode_ida import apply_pseudocode_comments
        written, refused = apply_pseudocode_comments(
            [PseudocodeComment(1, 2, 3, "x")])
        assert (written, refused) == (0, 1)


class TestSidecarIntegration:
    def test_the_section_rides_in_the_type_sidecar(self):
        from bindiff.typeinfo import (pseudocode_from_json, to_json as
                                      types_to_json, with_pseudocode)

        comments = [PseudocodeComment(1, 2, 69, "note")]
        sidecar = with_pseudocode(types_to_json([], [], "x"), comments)
        assert pseudocode_from_json(sidecar) == comments

    def test_a_sidecar_written_before_this_still_reads_its_types(self):
        from bindiff.typeinfo import (from_json, pseudocode_from_json,
                                      to_json as types_to_json)
        from bindiff.typeinfo import TypeDeclaration

        old = types_to_json([TypeDeclaration(name="foo", definition="struct foo {};")],
                            [], "x")
        assert pseudocode_from_json(old) == []
        declarations, _ = from_json(old)
        assert [d.name for d in declarations] == ["foo"]

    def test_no_comments_leaves_the_sidecar_alone(self):
        from bindiff.typeinfo import to_json as types_to_json, with_pseudocode

        plain = types_to_json([], [], "x")
        assert with_pseudocode(plain, []) == plain

    def test_a_future_version_is_refused_rather_than_misread(self):
        from bindiff.typeinfo import pseudocode_from_json

        with pytest.raises(ValueError, match="version"):
            pseudocode_from_json({"pseudocode_version": 99,
                                  "pseudocode_comments": []})
