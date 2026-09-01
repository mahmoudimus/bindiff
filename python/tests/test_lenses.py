"""A lens is a saved filter, sort and column set. Three sessions, three
lenses; the search field narrows within one."""

import pytest

from ida_plugin.lenses import (ALL, LENSES, NEEDS_A_LOOK, READY_TO_PORT,
                               apply_lens, lens_by_key, lens_counts)
from ida_plugin.query import parse_query
from ida_plugin.ui_logic import DEFAULT_VISIBLE_COLUMNS, ChangeType, MatchRow


def row(**overrides) -> MatchRow:
    defaults = dict(match_id=1, similarity=0.9, confidence=0.9, change_flags=0,
                    address_primary=0x401000, name_primary="sub_401000",
                    address_secondary=0x501000, name_secondary="parse_type",
                    algorithm="function: hash matching", manual=False,
                    comments_ported=False, basic_blocks=3, edges=2,
                    instructions=20, trust="strong")
    defaults.update(overrides)
    return MatchRow(**defaults)


ROWS = [
    row(match_id=1),                                             # strong, unchanged, named there
    row(match_id=2, trust="check", similarity=0.6),              # needs a look
    row(match_id=3, change_flags=int(ChangeType.STRUCTURAL)),    # strong but restructured
    row(match_id=4, name_secondary="sub_501000"),                # nothing to port
    row(match_id=5, trust="weak", similarity=0.2, name_primary="mine"),
]


class TestPredicates:
    def test_needs_a_look_is_not_strong_or_restructured(self):
        assert [r.match_id for r in NEEDS_A_LOOK.select(ROWS, 0.5)] == [2, 3, 5]

    def test_ready_to_port_is_named_on_the_other_side(self):
        assert [r.match_id for r in READY_TO_PORT.select(ROWS, 0.5)] == [1, 2, 3, 5]

    def test_threshold_does_not_change_membership(self):
        assert READY_TO_PORT.select(ROWS, 0.95) == READY_TO_PORT.select(ROWS, 0.0)

    def test_all_is_everything(self):
        assert ALL.select(ROWS, 0.5) == ROWS


class TestShape:
    def test_three_lenses_with_distinct_keys(self):
        assert [lens.key for lens in LENSES] == ["needs_a_look", "ready_to_port", "all"]
        assert lens_by_key("all") is ALL
        with pytest.raises(ValueError):
            lens_by_key("nope")

    def test_default_columns_for_the_judgement_lenses(self):
        assert NEEDS_A_LOOK.columns == DEFAULT_VISIBLE_COLUMNS
        assert ALL.columns == DEFAULT_VISIBLE_COLUMNS

    def test_the_port_lens_shows_the_outcome(self):
        assert "outcome" in READY_TO_PORT.columns
        assert "comments_available" in READY_TO_PORT.columns
        assert "found_by" not in READY_TO_PORT.columns


class TestApplying:
    def test_query_narrows_within_the_lens(self):
        shown = apply_lens(ROWS, NEEDS_A_LOOK, parse_query("trust:weak"), 0.5)
        assert [r.match_id for r in shown] == [5]

    def test_default_sort_is_similarity_descending(self):
        shown = apply_lens(ROWS, ALL, parse_query(""), 0.5)
        assert [r.similarity for r in shown] == sorted(
            (r.similarity for r in ROWS), reverse=True)

    def test_a_header_click_overrides_the_sort(self):
        shown = apply_lens(ROWS, ALL, parse_query(""), 0.5,
                           sort_column="similarity", sort_descending=False)
        assert shown[0].match_id == 5

    def test_counts_cover_every_lens(self):
        assert lens_counts(ROWS, 0.5) == {"needs_a_look": 3, "ready_to_port": 4, "all": 5}
