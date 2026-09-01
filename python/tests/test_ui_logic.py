"""Tests for the plugin's presentation logic.

These import no Qt and no IDA. That is the point of keeping the logic in its own
module: the sorting, filtering and formatting that a UI actually gets wrong are
checked here, in the headless harness, instead of by clicking.
"""

import pytest

from ida_plugin.ui_logic import (
    COLUMNS,
    ChangeType,
    DiffProgress,
    MatchFilter,
    MatchRow,
    build_statistics,
    describe_change_flags,
    filter_rows,
    format_address,
    format_change_flags,
    format_elapsed,
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


class TestDiffProgress:
    def test_reads_a_worker_record(self):
        progress = DiffProgress.from_record({
            "stage": "diff", "message": "function: MD index matching",
            "fraction": 0.75, "step_index": 3, "step_count": 8,
            "matches": 412})

        assert progress.percentage == 75
        assert progress.describe() == (
            "function: MD index matching - step 4/8 - 412 matched")

    def test_an_export_has_no_percentage(self):
        """idalib's auto-analysis does not call back, so there is no fraction
        to report. An indeterminate bar is the honest rendering; a made-up
        number is not."""
        progress = DiffProgress.from_record(
            {"stage": "export", "message": "exporting primary: a.exe",
             "fraction": None})

        assert progress.percentage is None
        assert progress.describe() == "exporting primary: a.exe"

    def test_percentage_is_clamped(self):
        assert DiffProgress(fraction=-0.5).percentage == 0
        assert DiffProgress(fraction=1.4).percentage == 100

    def test_an_empty_record_still_describes_itself(self):
        """A status label with nothing in it reads as a hang."""
        assert DiffProgress.from_record({}).describe() == "working"

    def test_step_number_is_shown_one_based(self):
        """The engine counts steps from zero; nobody reads a progress line
        that starts at 'step 0'."""
        assert "step 1/9" in DiffProgress(message="x", step_index=0,
                                          step_count=9).describe()

    def test_zero_matches_is_shown_rather_than_hidden(self):
        """0 and 'not reported' are different facts, and early steps really do
        match nothing."""
        assert "0 matched" in DiffProgress(message="x", matches=0).describe()


class TestFormatElapsed:
    @pytest.mark.parametrize("seconds,expected", [
        (0, "0s"),
        (47, "47s"),
        (59.9, "59s"),
        (60, "1m 00s"),
        (185, "3m 05s"),
        (3600, "1h 00m"),
        (7325, "2h 02m"),
    ])
    def test_reads_as_a_duration(self, seconds, expected):
        assert format_elapsed(seconds) == expected

    def test_a_negative_clock_does_not_produce_nonsense(self):
        assert format_elapsed(-5) == "0s"


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


class TestCellValues:
    def test_one_value_per_column(self):
        from ida_plugin.ui_logic import COLUMNS, cell_values
        row = _match_row()
        assert len(cell_values(row)) == len(COLUMNS)

    def test_scores_are_two_decimals_and_addresses_are_hex(self):
        from ida_plugin.ui_logic import cell_values
        values = cell_values(_match_row(similarity=1.0, confidence=0.985,
                                        address_primary=0x401000))
        assert values[0] == "1.00"
        assert values[1] == "0.98"
        assert "401000" in values[3].lower()


class TestNarrowing:
    """Re-filtering the previous result instead of every row.

    Unsound in one case, and the case is easy to miss: text matches names by
    substring but addresses exactly, so extending the query can *add* a row.
    """

    def test_extending_the_text_narrows(self):
        from ida_plugin.ui_logic import MatchFilter
        assert MatchFilter(text="acrt_x").narrows(MatchFilter(text="acrt"))

    def test_starting_from_nothing_narrows(self):
        from ida_plugin.ui_logic import MatchFilter
        assert MatchFilter(text="acrt").narrows(MatchFilter())

    def test_a_different_text_does_not(self):
        from ida_plugin.ui_logic import MatchFilter
        assert not MatchFilter(text="zzz").narrows(MatchFilter(text="acrt"))

    def test_deleting_a_character_does_not(self):
        from ida_plugin.ui_logic import MatchFilter
        assert not MatchFilter(text="acr").narrows(MatchFilter(text="acrt"))

    def test_a_hex_query_never_narrows(self):
        """0x401 does not match "40" and does match "401": extending the
        query adds the row, so the previous result is not a superset."""
        from ida_plugin.ui_logic import MatchFilter
        assert not MatchFilter(text="401").narrows(MatchFilter(text="40"))
        assert not MatchFilter(text="beef").narrows(MatchFilter(text="bee"))

    def test_a_loosened_threshold_does_not(self):
        from ida_plugin.ui_logic import MatchFilter
        assert not MatchFilter(min_similarity=0.1).narrows(
            MatchFilter(min_similarity=0.5))

    def test_a_tightened_threshold_does(self):
        from ida_plugin.ui_logic import MatchFilter
        assert MatchFilter(min_similarity=0.9).narrows(
            MatchFilter(min_similarity=0.5))

    def test_dropping_a_flag_does_not(self):
        from ida_plugin.ui_logic import MatchFilter
        assert not MatchFilter().narrows(MatchFilter(manual_only=True))
        assert not MatchFilter().narrows(MatchFilter(changed_only=True))

    def test_narrowing_agrees_with_filtering_from_scratch(self):
        """The property that matters: when narrows() says yes, filtering the
        previous result must equal filtering everything."""
        from ida_plugin.ui_logic import MatchFilter, filter_rows
        rows = [_match_row(match_id=i, name_primary=n, similarity=s)
                for i, (n, s) in enumerate(
                    [("acrt_add_locale", 1.0), ("acrt_free", 0.9),
                     ("zzz_other", 0.4), ("acrt_zzz", 0.7)])]
        previous, current = MatchFilter(text="acrt"), MatchFilter(text="acrt_z")
        assert current.narrows(previous)
        assert (filter_rows(filter_rows(rows, previous), current)
                == filter_rows(rows, current))


def _match_row(**overrides):
    """A MatchRow with every field defaulted, for tests that care about one."""
    from ida_plugin.ui_logic import MatchRow
    fields = dict(match_id=1, similarity=1.0, confidence=1.0, change_flags=0,
                  address_primary=0x401000, name_primary="a",
                  address_secondary=0x501000, name_secondary="b",
                  algorithm="hash matching", manual=False,
                  comments_ported=False, basic_blocks=1, edges=1,
                  instructions=1)
    fields.update(overrides)
    return MatchRow(**fields)


class TestUnmatchedCellValues:
    def test_one_value_per_column(self):
        from ida_plugin.ui_logic import UNMATCHED_COLUMNS, UnmatchedRow, \
            unmatched_cell_values
        row = UnmatchedRow(address=0x401000, name="sub_401000",
                           is_library=False, has_real_name=False)
        assert len(unmatched_cell_values(row)) == len(UNMATCHED_COLUMNS)

    @pytest.mark.parametrize("is_library,has_real_name,expected", [
        (True, True, "library"),
        (False, True, "named"),
        (False, False, "unnamed"),
    ])
    def test_kind(self, is_library, has_real_name, expected):
        from ida_plugin.ui_logic import UnmatchedRow, unmatched_cell_values
        row = UnmatchedRow(address=0x401000, name="x", is_library=is_library,
                           has_real_name=has_real_name)
        assert unmatched_cell_values(row)[2] == expected


class TestSharedNarrowingRule:
    """Both views filter the same way, so they share the rule and its trap."""

    def test_extending_a_name_narrows(self):
        from ida_plugin.ui_logic import text_query_narrows
        assert text_query_narrows("acrt", "acrt_zz")

    def test_a_hex_query_never_narrows(self):
        from ida_plugin.ui_logic import text_query_narrows
        assert not text_query_narrows("40", "401")

    def test_unmatched_filtering_agrees_when_it_says_yes(self):
        from ida_plugin.ui_logic import (UnmatchedRow, filter_unmatched,
                                         text_query_narrows)
        rows = [UnmatchedRow(address=0x400000 + i, name=n, is_library=False,
                             has_real_name=True)
                for i, n in enumerate(["acrt_one", "acrt_two", "zz", "acrt_z"])]
        assert text_query_narrows("acrt", "acrt_z")
        assert (filter_unmatched(filter_unmatched(rows, "acrt"), "acrt_z")
                == filter_unmatched(rows, "acrt_z"))


class TestIncrementalFilter:
    """The caching both list views share.

    Written once because they each had their own copy, and the copies had
    already drifted -- one carried an address parser the other duplicated.
    """

    def _filter(self):
        from ida_plugin.ui_logic import IncrementalFilter, text_query_narrows
        calls = []

        def apply(rows, key):
            calls.append(len(rows))
            return [r for r in rows if key in r]

        return IncrementalFilter(text_query_narrows, apply), calls

    # Queries here avoid hex digits on purpose: "abc" is a valid address and
    # text_query_narrows refuses to narrow such a query, so hex-looking test
    # data would exercise the wrong branch. That is the rule working, and it
    # caught these tests before they caught anything else.

    def test_first_call_uses_everything(self):
        f, calls = self._filter()
        assert f(["quo", "qux", "zz"], "qu") == ["quo", "qux"]
        assert calls == [3]

    def test_a_narrowing_key_reuses_the_previous_result(self):
        f, calls = self._filter()
        f(["quo", "qux", "zz"], "qu")
        assert f(["quo", "qux", "zz"], "quo") == ["quo"]
        # Second pass saw two rows, not three.
        assert calls == [3, 2]

    def test_a_widening_key_goes_back_to_everything(self):
        f, calls = self._filter()
        f(["quo", "qux", "zz"], "quo")
        f(["quo", "qux", "zz"], "qu")
        assert calls == [3, 3]

    def test_a_hex_query_is_never_narrowed(self):
        """Not a quirk of the cache -- addresses match exactly, so a longer
        query can select a row the shorter one did not."""
        f, calls = self._filter()
        f(["abc", "abd"], "ab")
        f(["abc", "abd"], "abc")
        assert calls == [2, 2]

    def test_invalidate_forces_a_full_pass(self):
        """The cache holds a result, so new rows must not be filtered through
        the old one -- that hides rows the new data contains."""
        f, calls = self._filter()
        f(["quo"], "qu")
        f.invalidate()
        assert f(["quo", "quz"], "quz") == ["quz"]
        assert calls == [1, 2]

    def test_without_invalidate_new_rows_would_be_lost(self):
        """Demonstrates why invalidate() is not optional."""
        f, _ = self._filter()
        f(["quo"], "qu")
        # No invalidate: "quz" narrows "qu", so the stale one-row result is
        # filtered and the new row never appears.
        assert f(["quo", "quz"], "quz") == []

    def test_it_matches_filtering_from_scratch_when_used_correctly(self):
        from ida_plugin.ui_logic import (MatchFilter, IncrementalFilter,
                                         filter_rows)
        rows = [_match_row(match_id=i, name_primary=n)
                for i, n in enumerate(["acrt_a", "acrt_b", "zz"])]
        f = IncrementalFilter(lambda p, c: c.narrows(p), filter_rows)
        f(rows, MatchFilter(text="acrt"))
        current = MatchFilter(text="acrt_b")
        assert f(rows, current) == filter_rows(rows, current)


class TestChangeLegend:
    """The Change column shows "GI--EL-" and nothing on screen says what the
    positions are; the letters are the engine's, so they can only be
    explained, not renamed."""

    def test_every_code_is_listed(self):
        from ida_plugin.ui_logic import _CHANGE_CODES, change_legend
        legend = change_legend()
        for _bit, code, name in _CHANGE_CODES:
            assert f"  {code}   {name}" in legend

    def test_it_says_what_a_dash_means(self):
        from ida_plugin.ui_logic import change_legend
        assert "dash" in change_legend().lower()

    def test_the_legend_covers_the_format(self):
        """One position per code, so the legend accounts for every character
        the column can show."""
        from ida_plugin.ui_logic import _CHANGE_CODES, format_change_flags
        assert len(format_change_flags(0)) == len(_CHANGE_CODES)
        assert format_change_flags(0) == "-" * len(_CHANGE_CODES)
