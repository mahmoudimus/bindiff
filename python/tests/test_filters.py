"""Per-column filter rules.

IDA's choosers carry this and there is no API to borrow it -- the quick
filter, the "Modify filters..." dialog and the column picker belong to the
chooser widget. An embedded chooser would bring them along, but its per-row
colour cannot express a per-cell Trust tint and its columns are fixed at
construction, which the lenses change. So the rules are rebuilt here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ida_plugin.filters import (ANY_COLUMN, ENDS_WITH, EXCLUDE, INCLUDE, IS,
                                STARTS_WITH, Rule, RuleSet, Unusable)

# Rendered cells, in COLUMNS order: trust, this database, other binary, sim,
# changed, found by, state.
ROW = ("Strong", "sub_1000", "memcpy", "0.94", "instructions",
       "hash matching", "ported")
OTHER = ("Weak", "sub_2000", "CRT_init", "0.31", "",
         "address sequence", "—")


def keeps(rules, cells=ROW) -> bool:
    return RuleSet(rules).matches(cells)


class TestConditions:
    def test_contains_is_the_default(self):
        assert keeps([Rule("emcp")])

    def test_is_demands_the_whole_cell(self):
        assert keeps([Rule("memcpy", column="other_binary", condition=IS)])
        assert not keeps([Rule("emcp", column="other_binary", condition=IS)])

    def test_starts_and_ends(self):
        assert keeps([Rule("mem", column="other_binary", condition=STARTS_WITH)])
        assert not keeps([Rule("cpy", column="other_binary",
                               condition=STARTS_WITH)])
        assert keeps([Rule("cpy", column="other_binary", condition=ENDS_WITH)])

    def test_case_is_ignored_by_default(self):
        assert keeps([Rule("MEMCPY")])

    def test_and_respected_when_asked(self):
        assert not keeps([Rule("MEMCPY", match_case=True)])
        assert keeps([Rule("memcpy", match_case=True)])

    def test_whole_words(self):
        assert keeps([Rule("hash", column="found_by", whole_words=True)])
        assert not keeps([Rule("has", column="found_by", whole_words=True)])

    def test_regex(self):
        assert keeps([Rule(r"^mem.py$", column="other_binary", regex=True)])
        assert not keeps([Rule(r"^cpy", column="other_binary", regex=True)])

    def test_a_regex_that_does_not_parse_says_so(self):
        """Rather than matching nothing, which reads as an empty result."""
        with pytest.raises(Unusable, match="not a valid pattern"):
            RuleSet([Rule("(unclosed", regex=True)])


class TestColumns:
    def test_any_searches_every_cell(self):
        assert keeps([Rule("hash matching")])

    def test_a_named_column_searches_only_that_one(self):
        assert not keeps([Rule("hash matching", column="other_binary")])

    def test_a_hidden_column_still_filters(self):
        """The value exists whether or not the column is shown -- otherwise a
        lens change would silently alter what a filter selects."""
        assert keeps([Rule("ported", column="state")])

    def test_a_column_that_no_longer_exists_drops_the_rule(self):
        """Not treated as "(any)": silently widening a filter shows rows the
        reader excluded on purpose."""
        assert keeps([Rule("nothing matches this", column="gone_away")])


class TestCombination:
    """A row survives when it matches at least one enabled include (or there
    are none) and no enabled exclude."""

    def test_no_rules_keeps_everything(self):
        assert keeps([])
        assert not RuleSet([])

    def test_one_include_restricts(self):
        assert keeps([Rule("memcpy")])
        assert not keeps([Rule("memcpy")], OTHER)

    def test_two_includes_admit_either(self):
        rules = [Rule("memcpy"), Rule("CRT")]
        assert keeps(rules) and keeps(rules, OTHER)

    def test_an_exclude_wins_over_an_include(self):
        assert not keeps([Rule("memcpy"), Rule("Strong", action=EXCLUDE)])

    def test_an_exclude_alone_keeps_everything_else(self):
        rules = [Rule("CRT", action=EXCLUDE)]
        assert keeps(rules) and not keeps(rules, OTHER)

    def test_a_disabled_rule_does_nothing(self):
        assert keeps([Rule("nothing", enabled=False)])

    def test_an_empty_value_does_nothing(self):
        assert keeps([Rule("")])


class TestCaching:
    def test_an_identical_list_narrows(self):
        rules = [Rule("memcpy")]
        assert RuleSet(rules).narrows(RuleSet(rules))

    def test_adding_an_include_does_not(self):
        """It widens: a second include admits rows the first refused. A cache
        built on "more rules means fewer rows" hides them with no way to
        tell."""
        first = RuleSet([Rule("memcpy")])
        assert not first.with_rule(Rule("CRT")).narrows(first)

    def test_adding_an_exclude_does_not_either(self):
        """It only ever narrows, but claiming so here would mean the rule
        depended on the action -- and getting that wrong is silent."""
        first = RuleSet([Rule("memcpy")])
        assert not first.with_rule(Rule("x", action=EXCLUDE)).narrows(first)


class TestEditing:
    def test_rules_are_added_removed_and_toggled_without_mutation(self):
        first = RuleSet([Rule("a")])
        second = first.with_rule(Rule("b"))
        assert len(first.rules) == 1 and len(second.rules) == 2
        assert len(second.without(0).rules) == 1
        assert second.toggled(0, False).rules[0].enabled is False
        assert second.rules[0].enabled is True


class TestDescription:
    def test_it_reads_like_the_dialog(self):
        assert Rule("memcpy").describe() == \
            "If (any) contains 'memcpy' then include"

    def test_flags_and_column_show(self):
        text = Rule("x", column="state", action=EXCLUDE, match_case=True,
                    whole_words=True).describe()
        assert "state" in text and "exclude" in text
        assert "case" in text and "whole words" in text


class TestAgainstRealRows:
    """The rules match ui_logic.cell_values, so what you filter on is what
    you can see."""

    def _row(self, **kwargs):
        from ida_plugin.ui_logic import MatchRow
        base = dict(match_id=1, similarity=0.94, confidence=0.9,
                    change_flags=0, address_primary=0x1000,
                    name_primary="sub_1000", address_secondary=0x2000,
                    name_secondary="memcpy", algorithm="hash matching",
                    manual=False, comments_ported=False, basic_blocks=3,
                    edges=2, instructions=10)
        base.update(kwargs)
        return MatchRow(**base)

    def test_a_rule_matches_the_rendered_cell(self):
        from ida_plugin.ui_logic import cell_values

        cells = cell_values(self._row())
        assert RuleSet([Rule("memcpy")]).matches(cells)
        # "0.94" is a string in the cell; nothing here knows it is a float.
        assert RuleSet([Rule("0.9", column="similarity")]).matches(cells)

    def test_every_column_key_is_addressable(self):
        """A rule can name any column the table knows, shown or not."""
        from ida_plugin.ui_logic import COLUMNS, cell_values

        cells = cell_values(self._row())
        for key, _label in COLUMNS:
            RuleSet([Rule("x", column=key)]).matches(cells)
