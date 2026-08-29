"""Tests for the plugin's presentation logic.

These import no Qt and no IDA. That is the point of keeping the logic in its own
module: the sorting, filtering and formatting that a UI actually gets wrong are
checked here, in the headless harness, instead of by clicking.
"""

import pytest

from ida_plugin.ui_logic import (
    COLUMNS,
    ChangeType,
    MatchFilter,
    MatchRow,
    build_statistics,
    describe_change_flags,
    filter_rows,
    format_address,
    format_change_flags,
    rows_from_database,
    similarity_color,
    sort_rows,
)


def make_row(**overrides) -> MatchRow:
    defaults = dict(
        match_id=1,
        similarity=0.5,
        confidence=0.5,
        change_flags=0,
        address_primary=0x401000,
        name_primary="sub_401000",
        address_secondary=0x501000,
        name_secondary="sub_501000",
        algorithm="function: hash matching",
        manual=False,
        comments_ported=False,
        basic_blocks=3,
        edges=2,
        instructions=20,
    )
    defaults.update(overrides)
    return MatchRow(**defaults)


class TestChangeFlags:
    def test_no_changes_renders_all_dashes(self):
        assert format_change_flags(0) == "-------"

    def test_all_changes_render_the_engine_string(self):
        every = sum(int(flag) for flag in ChangeType if flag)
        # GetChangeDescription() starts from "GIOJELC" and dashes out the bits
        # that are clear, so a fully changed function reads exactly this.
        assert format_change_flags(every) == "GIOJELC"

    def test_each_flag_lands_in_its_own_column(self):
        expected = {
            ChangeType.STRUCTURAL: "G------",
            ChangeType.INSTRUCTIONS: "-I-----",
            ChangeType.OPERANDS: "--O----",
            ChangeType.BRANCH_INVERSION: "---J---",
            ChangeType.ENTRY_POINT: "----E--",
            ChangeType.LOOPS: "-----L-",
            ChangeType.CALLS: "------C",
        }
        for flag, rendered in expected.items():
            assert format_change_flags(int(flag)) == rendered

    def test_describe_lists_only_what_changed(self):
        flags = int(ChangeType.STRUCTURAL | ChangeType.CALLS)
        assert describe_change_flags(flags) == ["Graph", "Calls"]
        assert describe_change_flags(0) == []


class TestSorting:
    def test_sorts_by_similarity_descending(self):
        rows = [make_row(similarity=s) for s in (0.1, 0.9, 0.5)]
        ordered = sort_rows(rows, "similarity", descending=True)
        assert [r.similarity for r in ordered] == [0.9, 0.5, 0.1]

    def test_names_sort_case_insensitively(self):
        rows = [make_row(name_primary=n) for n in ("beta", "Alpha", "gamma")]
        ordered = sort_rows(rows, "name_primary")
        assert [r.name_primary for r in ordered] == ["Alpha", "beta", "gamma"]

    def test_unknown_column_is_an_error(self):
        # Silently returning the input order would look like a UI that ignores
        # the click.
        with pytest.raises(ValueError, match="unknown column"):
            sort_rows([make_row()], "nonsense")

    def test_every_declared_column_is_sortable(self):
        rows = [make_row(similarity=0.2), make_row(similarity=0.8)]
        for column, _label in COLUMNS:
            assert len(sort_rows(rows, column)) == 2


class TestFiltering:
    def test_empty_filter_keeps_everything(self):
        rows = [make_row(), make_row(similarity=0.1)]
        assert filter_rows(rows, MatchFilter()) == rows

    def test_text_matches_either_name(self):
        rows = [
            make_row(name_primary="encrypt", name_secondary="x"),
            make_row(name_primary="y", name_secondary="decrypt"),
            make_row(name_primary="unrelated", name_secondary="other"),
        ]
        assert len(filter_rows(rows, MatchFilter(text="crypt"))) == 2

    def test_text_is_case_insensitive(self):
        rows = [make_row(name_primary="EncryptBuffer")]
        assert filter_rows(rows, MatchFilter(text="encryptbuf")) == rows

    @pytest.mark.parametrize("query", ["0x401000", "401000"])
    def test_text_matches_an_address(self, query):
        # Names must not contain the digits, or the name branch would match and
        # this would pass without the address branch working at all.
        rows = [
            make_row(address_primary=0x401000, name_primary="alpha",
                     name_secondary="beta"),
            make_row(address_primary=0x9, name_primary="gamma",
                     name_secondary="delta"),
        ]
        found = filter_rows(rows, MatchFilter(text=query))
        assert len(found) == 1 and found[0].address_primary == 0x401000

    def test_thresholds_are_inclusive(self):
        rows = [make_row(similarity=0.5), make_row(similarity=0.49)]
        assert len(filter_rows(rows, MatchFilter(min_similarity=0.5))) == 1

    def test_manual_and_changed_filters(self):
        rows = [
            make_row(manual=True, change_flags=0),
            make_row(manual=False, change_flags=int(ChangeType.CALLS)),
        ]
        assert len(filter_rows(rows, MatchFilter(manual_only=True))) == 1
        assert len(filter_rows(rows, MatchFilter(changed_only=True))) == 1

    def test_filters_combine(self):
        rows = [
            make_row(name_primary="encrypt", similarity=0.9, manual=True),
            make_row(name_primary="encrypt", similarity=0.2, manual=True),
            make_row(name_primary="other", similarity=0.9, manual=True),
        ]
        found = filter_rows(rows, MatchFilter(text="encrypt", min_similarity=0.5,
                                              manual_only=True))
        assert len(found) == 1


class TestFormatting:
    def test_address_is_padded_hex(self):
        assert format_address(0x401000) == "0x00401000"

    def test_similarity_colour_runs_red_to_green(self):
        low = similarity_color(0.0)
        high = similarity_color(1.0)
        assert low == (0xFF, 0x57, 0x22)
        assert high == (0x84, 0xFA, 0x02)
        # Green rises with similarity across the whole ramp.
        greens = [similarity_color(v / 10)[1] for v in range(11)]
        assert greens == sorted(greens)

    def test_similarity_colour_clamps(self):
        assert similarity_color(-1.0) == similarity_color(0.0)
        assert similarity_color(2.0) == similarity_color(1.0)

    def test_identical_requires_full_similarity_and_no_changes(self):
        assert make_row(similarity=1.0, change_flags=0).identical
        assert not make_row(similarity=1.0,
                            change_flags=int(ChangeType.CALLS)).identical
        assert not make_row(similarity=0.99, change_flags=0).identical


class _FakeFile:
    def __init__(self, name, functions):
        self.filename = name
        self.hash = "0" * 40
        self.functions = functions
        self.basic_blocks = functions * 3
        self.instructions = functions * 30
        self.edges = functions * 2
        self.calls = functions


class TestStatistics:
    def test_unmatched_is_derived_from_totals(self):
        rows = build_statistics([_FakeFile("a", 100), _FakeFile("b", 80)],
                                num_matches=60)
        by_label = {row.label: row for row in rows}
        assert by_label["Unmatched functions"].primary == "40"
        assert by_label["Unmatched functions"].secondary == "20"

    def test_requires_exactly_two_files(self):
        with pytest.raises(ValueError, match="expected two input files"):
            build_statistics([_FakeFile("a", 1)], num_matches=0)

    def test_similarity_is_shown_as_a_percentage_when_given(self):
        rows = build_statistics([_FakeFile("a", 10), _FakeFile("b", 10)],
                                num_matches=5, similarity=0.4723)
        assert any(r.label == "Similarity" and r.primary == "47.23%"
                   for r in rows)


@pytest.mark.requires_extension
def test_rows_from_a_real_database(bindiff_module, insider_pair, tmp_path):
    """The adapter has to line up with what BinDiffDatabase actually returns."""
    from bindiff import BinDiffDatabase

    primary, secondary = insider_pair
    out = tmp_path / "ui.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(out)) == 0

    with BinDiffDatabase.open(str(out)) as db:
        rows = rows_from_database(db)
        assert len(rows) == db.num_matches()

    assert rows
    for row in rows:
        assert isinstance(row, MatchRow)
        assert row.address_primary > 0
        assert 0.0 <= row.similarity <= 1.0
        assert len(row.change_text) == 7
        assert row.algorithm


class TestFlowGraphDiff:
    """The model behind the ida_graph view. Pure, so it is testable here."""

    BLOCKS = [(0x1000, ["push rbp"]), (0x1010, ["mov eax, 1"]),
              (0x1020, ["ret"])]
    EDGES = [(0x1000, 0x1010), (0x1010, 0x1020)]

    def test_marks_matched_blocks(self):
        from ida_plugin.ui_logic import build_flow_graph_diff

        diff = build_flow_graph_diff(self.BLOCKS, self.EDGES,
                                     [(0x1000, 0x2000), (0x1020, 0x2020)])
        assert diff.matched_count == 2
        by_address = {node.address: node for node in diff.nodes}
        assert by_address[0x1000].matched
        assert by_address[0x1000].secondary_address == 0x2000
        assert not by_address[0x1010].matched
        assert by_address[0x1010].secondary_address is None

    def test_edges_are_resolved_to_indices(self):
        from ida_plugin.ui_logic import build_flow_graph_diff

        diff = build_flow_graph_diff(self.BLOCKS, self.EDGES, [])
        assert diff.edges == [(0, 1), (1, 2)]

    def test_dangling_edges_are_dropped(self):
        """An edge to a block that was not supplied means inconsistent inputs;
        inventing the node would hide that."""
        from ida_plugin.ui_logic import build_flow_graph_diff

        diff = build_flow_graph_diff(
            self.BLOCKS, self.EDGES + [(0x1020, 0xDEAD)], [])
        assert diff.edges == [(0, 1), (1, 2)]
        assert len(diff.nodes) == 3

    def test_titles_name_the_counterpart(self):
        from ida_plugin.ui_logic import build_flow_graph_diff

        diff = build_flow_graph_diff(self.BLOCKS, [], [(0x1000, 0x2000)])
        by_address = {node.address: node for node in diff.nodes}
        assert "0x00002000" in by_address[0x1000].title
        assert "unmatched" in by_address[0x1010].title

    def test_summary_counts_both_sides(self):
        from ida_plugin.ui_logic import build_flow_graph_diff

        diff = build_flow_graph_diff(self.BLOCKS, self.EDGES, [(0x1000, 0x2000)])
        assert "1 of 3" in diff.summary and "2 changed" in diff.summary

    def test_an_empty_function_is_not_an_error(self):
        from ida_plugin.ui_logic import build_flow_graph_diff

        diff = build_flow_graph_diff([], [], [])
        assert diff.nodes == [] and diff.edges == []
        assert diff.matched_count == 0


class TestColumnVisibility:
    """Eighteen columns is more than fits; the table hides most by default."""

    def test_defaults_are_the_core_columns(self):
        from ida_plugin.ui_logic import COLUMNS, ColumnVisibility

        visibility = ColumnVisibility()
        assert visibility.is_visible("similarity")
        assert visibility.is_visible("name_primary")
        # The per-side counts are reference figures, not something to scan.
        assert not visibility.is_visible("basic_blocks_primary")
        assert not visibility.is_visible("comments_ported")
        assert len(visibility.visible_columns()) < len(COLUMNS)

    def test_toggle_round_trips(self):
        from ida_plugin.ui_logic import ColumnVisibility

        visibility = ColumnVisibility()
        assert not visibility.is_visible("edges_primary")
        visibility.toggle("edges_primary")
        assert visibility.is_visible("edges_primary")
        visibility.toggle("edges_primary")
        assert not visibility.is_visible("edges_primary")

    def test_cannot_hide_every_column(self):
        """A table with no columns cannot be recovered from: the menu used to
        undo it lives on the header."""
        from ida_plugin.ui_logic import ColumnVisibility

        visibility = ColumnVisibility(["similarity"])
        assert visibility.set_visible("similarity", False) is False
        assert visibility.is_visible("similarity")

    def test_unknown_column_is_an_error(self):
        from ida_plugin.ui_logic import ColumnVisibility

        with pytest.raises(ValueError, match="unknown column"):
            ColumnVisibility().set_visible("nonsense", True)

    def test_visible_columns_keep_table_order(self):
        from ida_plugin.ui_logic import COLUMNS, ColumnVisibility

        visibility = ColumnVisibility(["algorithm", "similarity"])
        assert [name for name, _ in visibility.visible_columns()] == [
            "similarity", "algorithm"]
        order = [name for name, _ in COLUMNS]
        assert order.index("similarity") < order.index("algorithm")

    def test_serialisation_round_trips(self):
        from ida_plugin.ui_logic import ColumnVisibility

        original = ColumnVisibility()
        original.toggle("edges_primary")
        restored = ColumnVisibility.from_list(original.to_list())
        assert restored.to_list() == original.to_list()

    def test_a_saved_set_naming_a_dropped_column_still_loads(self):
        """A set saved by an older version may name a column that no longer
        exists; keeping it would leave is_visible answering for a column the
        table has no index for."""
        from ida_plugin.ui_logic import ColumnVisibility

        visibility = ColumnVisibility(["similarity", "column_we_removed"])
        assert visibility.to_list() == ["similarity"]

    def test_an_empty_saved_set_falls_back_to_defaults(self):
        from ida_plugin.ui_logic import ColumnVisibility

        assert (ColumnVisibility([]).to_list()
                == ColumnVisibility().to_list())

    def test_show_all_and_reset(self):
        from ida_plugin.ui_logic import COLUMNS, ColumnVisibility

        visibility = ColumnVisibility()
        visibility.show_all()
        assert len(visibility.visible_columns()) == len(COLUMNS)
        visibility.reset()
        assert len(visibility.visible_columns()) < len(COLUMNS)
