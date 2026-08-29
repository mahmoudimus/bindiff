"""Exercises the plugin inside a real IDA GUI. Runs *in* IDA, not in pytest.

Started as `ida -A -S<this script> <binary>` under Xvfb by
tools/scripts/run_gui_tests_docker.sh. Writes a JSON report to
$BINDIFF_GUI_REPORT and quits.

This is the only thing that renders a widget. Every other test in the suite is
headless, so the Qt layer, the action handlers and the graph view are otherwise
completely unexercised -- they are also the code most likely to be wrong, since
none of it can be reasoned about from the model alone.

Two details that the d810 harness gets right and are easy to get wrong:

* Work is deferred with a timer. At script time IDA's UI is not up, so
  registering actions or looking for widgets immediately either fails or
  silently does nothing.
* Everything runs on the main thread. Touching IDA or Qt from anywhere else is
  not safe, and the failure is a crash rather than an exception.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import traceback

import ida_auto
import ida_funcs
import ida_kernwin
import ida_pro

REPORT_PATH = os.environ.get("BINDIFF_GUI_REPORT", "/tmp/gui-report.json")

results = []
failures = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    """Records a check. `detail` explains a *failure*, so it is dropped on
    success -- otherwise every passing line prints the reason it would have
    failed, which reads as a contradiction."""
    ok = bool(condition)
    results.append({"name": name, "ok": ok, "detail": "" if ok else detail})
    if not ok:
        failures.append(f"{name}: {detail}")
    return ok


def note(name: str, detail: str) -> None:
    """Informational, always shown: environment facts worth having in the log."""
    results.append({"name": name, "ok": True, "detail": detail})


def build_database(path: str, matches) -> None:
    """Writes a minimal .BinDiff whose primary addresses are real.

    The fixture result files point at addresses from other binaries, so a view
    built from one would render rows that go nowhere and the graph view would
    have nothing to draw. Synthesising against the functions actually in this
    database is what makes the test meaningful.

    Only the tables the plugin reads are created; the schema mirrors
    DatabaseWriter::PrepareDatabase.
    """
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE file (id INT, filename TEXT, exefilename TEXT,
            hash CHARACTER(40), functions INT, libfunctions INT, calls INT,
            basicblocks INT, libbasicblocks INT, edges INT, libedges INT,
            instructions INT, libinstructions INT);
        CREATE TABLE metadata (version TEXT, file1 INT, file2 INT,
            description TEXT, created DATE, modified DATE,
            similarity DOUBLE PRECISION, confidence DOUBLE PRECISION);
        CREATE TABLE functionalgorithm (id SMALLINT, name TEXT);
        CREATE TABLE basicblockalgorithm (id SMALLINT, name TEXT);
        CREATE TABLE function (id INT, address1 BIGINT, name1 TEXT,
            address2 BIGINT, name2 TEXT, similarity DOUBLE PRECISION,
            confidence DOUBLE PRECISION, flags INTEGER, algorithm SMALLINT,
            evaluate BOOLEAN, commentsported BOOLEAN, basicblocks INTEGER,
            edges INTEGER, instructions INTEGER);
        CREATE TABLE basicblock (id INT, functionid INT, address1 BIGINT,
            address2 BIGINT, algorithm SMALLINT, evaluate BOOLEAN);
        CREATE TABLE instruction (basicblockid INT, address1 BIGINT,
            address2 BIGINT);
    """)
    connection.execute("INSERT INTO functionalgorithm VALUES (1, ?)",
                       ("function: hash matching",))
    connection.execute("INSERT INTO functionalgorithm VALUES (2, ?)",
                       ("function: manual",))
    for index, (label, count) in enumerate(
            (("primary", len(matches)), ("secondary", len(matches))), start=1):
        connection.execute(
            "INSERT INTO file VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (index, f"{label}.BinExport", label, "0" * 40, count, 0, count,
             count * 3, 0, count * 2, 0, count * 10, 0))
    connection.execute(
        "INSERT INTO metadata VALUES (?,?,?,?,?,?,?,?)",
        ("8", 1, 2, "gui test", "2026-01-01", "2026-01-01", 0.5, 0.9))

    for index, (primary_address, name, blocks) in enumerate(matches, start=1):
        connection.execute(
            "INSERT INTO function VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (index, primary_address, name, primary_address + 0x100000,
             name + "_v2", 0.8, 0.9, 0b0000101, 1, 0, 0, len(blocks), 1, 5))
        # Pair every second block, so the graph view has both states to draw.
        for block_index, block_address in enumerate(blocks):
            if block_index % 2 == 0:
                connection.execute(
                    "INSERT INTO basicblock VALUES (?,?,?,?,?,?)",
                    (block_index + index * 1000, index, block_address,
                     block_address + 0x100000, 1, 0))
    connection.commit()
    connection.close()


def collect_functions(limit: int = 5):
    """Real functions from the open database, with their basic blocks."""
    import ida_gdl

    collected = []
    for index in range(min(ida_funcs.get_func_qty(), limit)):
        function = ida_funcs.getn_func(index)
        if function is None:
            continue
        blocks = [block.start_ea
                  for block in ida_gdl.FlowChart(function)]
        collected.append((function.start_ea,
                          ida_funcs.get_func_name(function.start_ea), blocks))
    return collected


def run_checks() -> None:
    sys.path.insert(0, "/work/python")

    from ida_plugin import panels
    from ida_plugin.bindiff_plugin import (
        ACTION_SHOW_MATCHES,
        ACTION_SHOW_STATISTICS,
        ACTION_VIEW_FLOW_GRAPHS,
        BinDiffPlugin,
    )

    # The environment the plugin actually runs in.
    from bindiff.ida_env import is_interactive, qt_widgets_usable

    check("detects the GUI", is_interactive(),
          "is_interactive() was False inside a running IDA GUI")
    check("allows widgets", qt_widgets_usable())
    check("qt binding loaded", panels.IDA_AVAILABLE,
          "panels.IDA_AVAILABLE was False, so no widget class was defined")

    from bindiff.qt_shim import QT_BINDING, QT_VERSION

    note("qt binding", f"{QT_BINDING} (Qt{QT_VERSION})")

    plugin = BinDiffPlugin()
    plugin.init()
    check("registers actions", len(plugin._registered) >= 19,
          f"only registered {len(plugin._registered)}: {plugin._registered}")
    note("actions registered", str(len(plugin._registered)))

    functions = collect_functions()
    check("found functions to diff", bool(functions),
          "the database contains no functions")
    note("functions in database", str(ida_funcs.get_func_qty()))
    if not functions:
        return

    database_path = "/tmp/gui-test.BinDiff"
    if os.path.exists(database_path):
        os.unlink(database_path)
    build_database(database_path, functions)

    plugin.controller.open_database(database_path)
    check("opens a result file", plugin.controller.loaded)
    rows = plugin.controller.match_rows()
    check("builds match rows", len(rows) == len(functions),
          f"{len(rows)} rows for {len(functions)} matches")

    # -- the part nothing else covers: real widgets --------------------------

    plugin._show_matches()
    widget = ida_kernwin.find_widget("BinDiff - Matched Functions")
    check("matched functions dock exists", widget is not None)

    form = plugin.controller._matched_form
    check("match table populated",
          form is not None and form._table is not None
          and form._table.rowCount() == len(rows),
          f"table had {form._table.rowCount() if form and form._table else None} rows")
    check("all 18 columns rendered",
          form._table.columnCount() == 18,
          f"columnCount() was {form._table.columnCount()}")

    # Filtering is wired through the pure logic, but the widgets carrying it
    # have never been constructed before now.
    form._filter_bar._text.setText("no-such-function-name-xyz")
    check("filter empties the table", form._table.rowCount() == 0,
          f"{form._table.rowCount()} rows survived an impossible filter")
    form._filter_bar._text.setText("")
    check("clearing the filter restores rows",
          form._table.rowCount() == len(rows))

    # Sorting by every column: a bad column name raises in the model, and the
    # header click path has never run.
    for section in range(form._table.columnCount()):
        try:
            form._table._on_header_clicked(section)
        except Exception as exc:
            check(f"sort by column {section}", False, repr(exc))
            break
    else:
        check("sorting by every column", True)

    plugin._show_statistics_widget_check = True
    try:
        from ida_plugin.panels import StatisticsDialog

        dialog = StatisticsDialog(plugin.controller.statistic_rows())
        check("statistics dialog builds", dialog is not None)
        dialog.close()
    except Exception as exc:
        check("statistics dialog builds", False, traceback.format_exc(limit=3))

    # The algorithm config dialog reads the live engine config.
    try:
        import bindiff

        from ida_plugin.panels import AlgorithmConfigDialog

        dialog = AlgorithmConfigDialog(bindiff.get_config(), lambda _c: None)
        check("algorithm dialog lists steps",
              dialog._function_list.count() > 0,
              f"{dialog._function_list.count()} function algorithms listed")
        dialog.close()
    except Exception:
        check("algorithm dialog lists steps", False,
              traceback.format_exc(limit=3))

    # -- the flow graph view -------------------------------------------------

    check("graph api available", getattr(panels, "GRAPH_AVAILABLE", False))
    if getattr(panels, "GRAPH_AVAILABLE", False):
        try:
            viewer = panels.show_flow_graph_diff(rows[0],
                                                 plugin.controller.database)
            check("flow graph viewer opens", viewer is not None)
            graph_widget = ida_kernwin.find_widget(
                f"BinDiff - {rows[0].name_primary or hex(rows[0].address_primary)}")
            check("flow graph widget exists", graph_widget is not None)
        except Exception:
            check("flow graph viewer opens", False,
                  traceback.format_exc(limit=5))

    # -- unmatched view ------------------------------------------------------

    try:
        from ida_plugin.panels import UnmatchedFunctionsForm
        from ida_plugin.ui_logic import UnmatchedRow

        unmatched = [UnmatchedRow(address=0x401000, name="orphan",
                                  is_library=False, has_real_name=True)]
        unmatched_form = UnmatchedFunctionsForm(unmatched, "primary")
        unmatched_form.Show()
        check("unmatched dock exists",
              ida_kernwin.find_widget("BinDiff - Unmatched (primary)") is not None)
    except Exception:
        check("unmatched dock exists", False, traceback.format_exc(limit=3))

    plugin.term()


def finish() -> int:
    """Timer callback: everything runs here, on the main thread."""
    try:
        run_checks()
    except Exception:
        failures.append(traceback.format_exc())
        results.append({"name": "driver", "ok": False,
                        "detail": traceback.format_exc()})

    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump({"ok": not failures, "results": results,
                   "failures": failures}, handle, indent=2)

    ida_pro.qexit(1 if failures else 0)
    return -1


ida_auto.auto_wait()
# Deferred: at script time the UI is not up, so widgets cannot be found and
# actions cannot be registered meaningfully.
ida_kernwin.register_timer(1000, finish)
