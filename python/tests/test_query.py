"""The search field's grammar. One field, structured: free text finds a name
or an address, `key:value` becomes a chip that can be read back and removed."""

import pytest

from ida_plugin.query import Query, Term, parse_query
from ida_plugin.ui_logic import (STATE_BY_HAND, STATE_NONE, STATE_PORTED,
                                 STATE_VERIFIED, ChangeType, MatchRow)


def row(**overrides) -> MatchRow:
    defaults = dict(match_id=1, similarity=0.5, confidence=0.5, change_flags=0,
                    address_primary=0x401000, name_primary="sub_401000",
                    address_secondary=0x501000, name_secondary="parse_type",
                    algorithm="function: hash matching", manual=False,
                    comments_ported=False, basic_blocks=3, edges=2,
                    instructions=20, trust="strong", state=STATE_NONE)
    defaults.update(overrides)
    return MatchRow(**defaults)


class TestParsing:
    def test_plain_words_are_text(self):
        query = parse_query("parse type")
        assert query.text == "parse type"
        assert query.terms == ()

    def test_terms_become_chips_and_leave_the_text(self):
        query = parse_query("parse sim:<0.8 changed:instr")
        assert query.text == "parse"
        assert query.chips() == ["sim:<0.8", "changed:instr"]
        assert query.terms[0] == Term("sim", "<", "0.8", "sim:<0.8")

    def test_a_bare_number_means_at_least(self):
        assert parse_query("sim:0.9").terms[0].op == ">="

    @pytest.mark.parametrize("bad", ["sim:high", "sim:<2", "changed:colour",
                                     "state:maybe", "trust:ok", "found-by:"])
    def test_an_unparseable_term_is_text(self, bad):
        query = parse_query(bad)
        assert query.terms == ()
        assert query.text == bad

    def test_round_trips_to_a_string(self):
        assert str(parse_query("parse  sim:<0.8")) == "parse sim:<0.8"

    def test_without_drops_one_chip(self):
        query = parse_query("a sim:<0.8 trust:weak")
        assert query.without("sim:<0.8").chips() == ["trust:weak"]
        assert query.without("nope").chips() == ["sim:<0.8", "trust:weak"]


class TestMatching:
    def test_text_matches_either_name_or_an_address(self):
        assert parse_query("parse").matches(row())
        assert parse_query("401000").matches(row())
        assert not parse_query("zzz").matches(row())

    def test_sim_and_coverage_compare(self):
        assert parse_query("sim:<0.8").matches(row(similarity=0.5))
        assert not parse_query("sim:<0.8").matches(row(similarity=0.9))
        assert parse_query("coverage:>=0.5").matches(row(confidence=0.5))
        assert not parse_query("coverage:>0.5").matches(row(confidence=0.5))

    def test_changed_names_an_aspect(self):
        changed = row(change_flags=int(ChangeType.INSTRUCTIONS))
        assert parse_query("changed:instr").matches(changed)
        assert parse_query("changed:instructions").matches(changed)
        assert not parse_query("changed:jumps").matches(changed)
        assert parse_query("changed:any").matches(changed)
        assert parse_query("changed:none").matches(row())

    def test_state_values(self):
        assert parse_query("state:unverified").matches(row())
        assert parse_query("state:verified").matches(row(state=STATE_VERIFIED))
        assert parse_query("state:by-hand").matches(row(state=STATE_BY_HAND))
        assert parse_query("state:ported").matches(row(state=STATE_PORTED))
        assert not parse_query("state:ported").matches(row())

    def test_found_by_is_a_substring_of_the_plain_name(self):
        assert parse_query("found-by:hash").matches(row())
        assert not parse_query("found-by:address").matches(row())

    def test_trust(self):
        assert parse_query("trust:strong").matches(row())
        assert not parse_query("trust:weak").matches(row())

    def test_terms_and_text_all_have_to_hold(self):
        assert parse_query("parse trust:strong sim:>=0.5").matches(row())
        assert not parse_query("parse trust:strong sim:>0.5").matches(row())


class TestNarrowing:
    def test_adding_a_chip_narrows(self):
        assert parse_query("a sim:<0.8").narrows(parse_query("a"))

    def test_removing_a_chip_does_not(self):
        assert not parse_query("a").narrows(parse_query("a sim:<0.8"))

    def test_changing_a_chip_does_not(self):
        assert not parse_query("sim:<0.9").narrows(parse_query("sim:<0.8"))

    def test_extending_text_narrows_but_an_address_never_does(self):
        assert parse_query("pars").narrows(parse_query("par"))
        assert not parse_query("401").narrows(parse_query("40"))

    def test_narrowing_agrees_with_filtering_from_scratch(self):
        rows = [row(match_id=i, similarity=i / 10, name_primary=f"sub_{i}")
                for i in range(10)]
        previous, current = parse_query("sub"), parse_query("sub sim:<0.5")
        assert current.narrows(previous)
        narrowed = [r for r in rows if previous.matches(r) if current.matches(r)]
        assert narrowed == [r for r in rows if current.matches(r)]
