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
