"""What the entry module promises without IDA: the ids survive, every
action is registered enable-always, and the old forms are not referenced."""

import re
from pathlib import Path

import ida_plugin.bindiff_plugin as plugin


def test_action_ids_are_unchanged():
    expected = {
        "bindiff:main", "bindiff:diff_database", "bindiff:load_results",
        "bindiff:save_results", "bindiff:show_matched", "bindiff:show_statistics",
        "bindiff:show_primary_unmatched", "bindiff:show_secondary_unmatched",
        "bindiff:match_delete", "bindiff:confirm_matches",
        "bindiff:import_symbols_comments", "bindiff:import_types", "bindiff:import_all",
        "bindiff:import_symbols_comments_external",
        "bindiff:import_symbols_comments_global",
        "bindiff:primary_unmatched_add_match", "bindiff:secondary_unmatched_add_match",
        "bindiff:primary_unmatched_copy_address", "bindiff:secondary_unmatched_copy_address",
        "bindiff:port_comments", "bindiff:copy_primary_address",
        "bindiff:copy_secondary_address", "bindiff:view_flow_graphs",
        "bindiff:configure_algorithms",
    }
    found = {value for name, value in vars(plugin).items()
             if name.startswith("ACTION_") and isinstance(value, str)}
    assert found == expected


def test_no_action_is_ever_disabled_by_ida():
    source = Path(plugin.__file__).read_text(encoding="utf-8")
    assert "AST_DISABLE" not in source
    assert "AST_ENABLE\b" not in source and "ida_kernwin.AST_ENABLE\n" not in source
    assert source.count("AST_ENABLE_ALWAYS") >= 1


def test_the_old_forms_are_not_referenced():
    source = Path(plugin.__file__).read_text(encoding="utf-8")
    for name in ("ControlPanel", "MatchedFunctionsForm", "StatisticsForm",
                 "UnmatchedFunctionsForm", "DiffProgressForm", "_control_panel",
                 "_matched_form", "_unmatched_forms", "_statistics_form"):
        assert name not in source, name


def test_the_port_floors_are_not_read_out_of_the_threshold():
    """The footer previews with the constant coverage floor, and its slider
    reaches 0.00. A handler that dropped the floor whenever the threshold was
    0.0 made the footer undercount what the same click would write -- by
    exactly the low-coverage pairs it said it would skip."""
    source = Path(plugin.__file__).read_text(encoding="utf-8")
    assert "floors_for_comments" not in source
    assert "0.0 if ignore_floors else DEFAULT_PORT_MIN_CONFIDENCE" in source


def test_a_restore_reports_what_ida_answered():
    """set_name refuses by returning False. A restore that forgot the ledger
    entry regardless would lose the only record of the old name."""
    source = Path(plugin.__file__).read_text(encoding="utf-8")
    assert "result.applied != 1" in source
    assert "refused to restore" in source
    assert "restoring_rename" in source


def test_every_way_of_losing_a_result_asks_the_same_question():
    """Replacing an edited result is closing it: open_result reopens the
    connection, and what was not committed is gone. Close, Open result... and
    a finished comparison all go through the one question."""
    source = Path(plugin.__file__).read_text(encoding="utf-8")
    assert '_confirm_discard("Close")' in source
    assert source.count('_confirm_discard("Replace the open result")') == 2


def test_a_result_that_will_not_open_is_a_message_either_way():
    """Both paths that open a .BinDiff warn with the path. The one inside the
    comparison runs in execute_sync, where a traceback reaches nobody."""
    source = Path(plugin.__file__).read_text(encoding="utf-8")
    assert source.count('f"Could not open {path}:\\n{exc}"') == 2


def test_every_handler_the_workbench_calls_is_supplied():
    """The handlers dict is the contract between the plugin and its two
    forms; a missing key is a click that does nothing, quietly."""
    plugin_source = Path(plugin.__file__).read_text(encoding="utf-8")
    needed = set()
    for module in ("workbench", "inspector"):
        source = (Path(plugin.__file__).parent / f"{module}.py").read_text(encoding="utf-8")
        needed |= set(re.findall(r'_handlers\["(\w+)"\]', source))
    supplied = set(re.findall(r'^\s+"(\w+)":', plugin_source, flags=re.M))
    assert needed <= supplied, sorted(needed - supplied)
