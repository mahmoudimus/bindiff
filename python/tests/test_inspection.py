"""Everything true of exactly one pair, with every engine token beside its
expansion. Pure content; the inspector renders it."""

from ida_plugin.inspection import build_inspection
from ida_plugin.session import ResultMeta
from ida_plugin.ui_logic import ChangeType, MatchRow

META = ResultMeta("/x.BinDiff", "a.i64", "b.i64", 10, 1, 2, False)


def row(**over) -> MatchRow:
    fields = dict(match_id=7, similarity=0.64, confidence=0.91,
                  change_flags=int(ChangeType.INSTRUCTIONS | ChangeType.BRANCH_INVERSION),
                  address_primary=0x13001F80, name_primary="sub_13001F80",
                  address_secondary=0x1800220C, name_secondary="parse_type_string",
                  algorithm="function: edges callgraph MD index", manual=False,
                  comments_ported=False, basic_blocks=12, edges=14, instructions=219,
                  basic_blocks_primary=14, instructions_primary=260, edges_primary=16,
                  basic_blocks_secondary=13, instructions_secondary=241, edges_secondary=15,
                  trust="check", comments_available=4)
    fields.update(over)
    return MatchRow(**fields)


def test_identity_names_the_other_side_and_both_addresses():
    view = build_inspection(row(), META, threshold=0.5)
    assert view.title == "parse_type_string"
    assert view.subtitle == "b.i64 1800220C → a.i64 13001F80"


def test_measures_carry_token_expansion_and_value():
    view = build_inspection(row(), META, threshold=0.5)
    by_label = {m.label: m for m in view.measures}
    assert by_label["Similarity"].value == "0.64"
    assert by_label["Block coverage"].token == "confidence"
    assert by_label["Block coverage"].value == "0.91"
    assert by_label["Algorithm class"].value == "structural"
    assert by_label["Found by"].token == "function: edges callgraph MD index"
    assert by_label["Found by"].value == "call-graph edges"
    assert by_label["Matched blocks"].value == "12 of 14 / 13"
    assert by_label["Matched instructions"].value == "219 of 260 / 241"
    assert "Block coverage" in view.coverage_caveat
    assert view.engine_algorithm == "function: edges callgraph MD index"


def test_totals_are_omitted_when_unknown():
    view = build_inspection(row(basic_blocks_primary=0, basic_blocks_secondary=0,
                                instructions_primary=0, instructions_secondary=0,
                                edges_primary=0, edges_secondary=0), META, threshold=0.5)
    by_label = {m.label: m for m in view.measures}
    assert by_label["Matched blocks"].value == "12"


def test_changed_expands_every_letter():
    view = build_inspection(row(), META, threshold=0.5)
    assert view.changed[1] == ("I", "Instructions", True)
    assert view.changed[3] == ("J", "Jumps", True)
    assert view.changed[0] == ("G", "Graph", False)


def test_would_port_over_a_generated_name():
    view = build_inspection(row(), META, threshold=0.5)
    assert view.would_port[0] == "Name parse_type_string"
    assert "auto-generated" in view.would_port[1]
    assert view.would_port[2] == "4 comments"
    assert view.port_label == "Port name + 4 comments"


def test_would_port_over_your_own_name_says_so():
    view = build_inspection(row(name_primary="mine"), META, threshold=0.5)
    assert "a name you wrote" in view.would_port[1]


def test_nothing_to_port():
    view = build_inspection(row(name_secondary="sub_1800220C", comments_available=0),
                            META, threshold=0.5)
    assert view.would_port == ("No name to port",)
    assert view.port_label == "Nothing to port"
    assert view.title == "sub_13001F80"


def test_below_threshold_is_stated_not_hidden():
    view = build_inspection(row(), META, threshold=0.9)
    assert any("Below the 0.90 threshold" in line for line in view.would_port)
    assert view.port_label == "Port name + 4 comments"


def test_no_meta_still_builds():
    view = build_inspection(row(), None, threshold=0.5)
    assert view.subtitle == "1800220C → 13001F80"
