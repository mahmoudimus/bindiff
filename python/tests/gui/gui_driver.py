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
import tempfile
import time
import traceback
from pathlib import Path

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
    from ida_plugin.bindiff_plugin import BinDiffPlugin

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
    check("registers actions", len(plugin._registered) >= 24,
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

    plugin.session.open_result(database_path)
    check("opens a result file", plugin.controller.loaded)
    check("session opens the result", plugin.session.state.value == "open",
          f"state was {plugin.session.state}")
    rows = plugin.session.rows()
    check("builds match rows", len(rows) == len(functions),
          f"{len(rows)} rows for {len(functions)} matches")

    # -- the part nothing else covers: real widgets --------------------------

    plugin._open_workbench()
    widget = ida_kernwin.find_widget("BinDiff")
    check("workbench dock exists", widget is not None)
    bench = plugin.workbench
    check("table populated",
          bench is not None and bench.parent is not None
          and bench._table.model().rowCount() == len(rows),
          "table row count differs from the session's rows")
    check("seven columns visible",
          sum(1 for i in range(bench._table.model().columnCount())
              if not bench._table.isColumnHidden(i)) == 7)

    # The visible set belongs to the lens, so choosing columns by hand and
    # then switching lens has to put the lens's own set back.
    bench._table.set_columns(["trust", "similarity"])
    check("choosing columns hides the rest",
          sum(1 for i in range(bench._table.model().columnCount())
              if not bench._table.isColumnHidden(i)) == 2)

    # Lenses and search go through the pure logic; here only that the
    # widgets carry them.
    bench.set_lens("all")
    check("the lens restores its columns",
          sum(1 for i in range(bench._table.model().columnCount())
              if not bench._table.isColumnHidden(i)) == 7)
    bench._search.setText("nomatch_zzz")
    bench._apply_search()   # bypass the debounce
    check("search narrows", bench._table.model().rowCount() == 0)
    bench._search.setText("")
    bench._apply_search()

    bench._table.select_ids([rows[0].match_id])
    check("selection reaches the session",
          plugin.session.selected_ids == (rows[0].match_id,),
          f"the session holds {plugin.session.selected_ids!r}")
    check("verify is available with a selection", plugin.session.can("verify"))

    plugin._inspect()
    check("inspector dock exists",
          ida_kernwin.find_widget("Match inspector") is not None)

    # The four scopes are tabs on the one dock now, so each has to be
    # reachable without a second widget existing.
    for scope in ("only_here", "only_there", "overview", "matches"):
        try:
            bench.show_scope(scope)
        except Exception:
            check(f"scope {scope} opens", False, traceback.format_exc(limit=3))
            break
    else:
        check("every scope opens", True)

    # The algorithm config dialog reads the live engine config.
    try:
        import bindiff

        from ida_plugin.panels import AlgorithmConfigDialog

        dialog = AlgorithmConfigDialog(bindiff.get_config(), lambda _c: None)
        check("algorithm dialog lists steps",
              dialog._function_list.rowCount() > 0,
              "no function algorithms listed")
        note("function algorithms listed",
             str(dialog._function_list.rowCount()))

        # Confidence is editable now, and the edit has to survive being read
        # back out of the table.
        confidence_cell = dialog._function_list.item(0, 1)
        check("confidence cell exists", confidence_cell is not None)
        if confidence_cell is not None:
            confidence_cell.setText("0.33")
            steps = dialog._selected_steps(dialog._function_list)
            check("edited confidence is read back",
                  bool(steps) and steps[0]["confidence"] == 0.33,
                  f"read {steps[0]['confidence'] if steps else None}")

            # A value that will not parse, or is out of range, drops the row
            # rather than substituting something the user did not type.
            confidence_cell.setText("not a number")
            rejected = dialog._selected_steps(dialog._function_list)
            check("unparseable confidence drops the row",
                  len(rejected) == len(steps) - 1,
                  f"{len(rejected)} rows vs {len(steps)}")
            confidence_cell.setText("5.0")
            out_of_range = dialog._selected_steps(dialog._function_list)
            check("out of range confidence drops the row",
                  len(out_of_range) == len(steps) - 1)
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

    # -- progress through the run strip --------------------------------------
    #
    # The strip is the panel protocol DiffRun expects: start, update_progress,
    # finish. This is the only place that code runs at all -- headless there
    # is no QProgressBar to set a range on. What the headless suite checks is
    # the arithmetic behind it (ui_logic.DiffProgress); what is checked here
    # is that the widget reflects it.

    try:
        from ida_plugin.ui_logic import DiffProgress

        # None until OnCreate has run, which _open_workbench above did.
        check("run strip exists", bench.run_strip is not None,
              "the workbench has no run strip, so OnCreate did not run")
        if bench.run_strip is not None:
            bench.run_strip.start("probe")
            check("starting shows the running page",
                  bench.run_strip._stack.currentIndex() == 1)

            bench.run_strip.update_progress(DiffProgress.from_record(
                {"stage": "export", "message": "exporting", "fraction": None}))
            # 0/0 is Qt's indeterminate bar, which is what an export
            # deserves: idalib's auto-analysis reports nothing to make a
            # fraction from.
            check("export shows an indeterminate bar",
                  bench.run_strip._bar.maximum() == 0,
                  f"maximum was {bench.run_strip._bar.maximum()}")

            bench.run_strip.update_progress(DiffProgress.from_record(
                {"stage": "diff", "message": "matching", "fraction": 0.5}))
            check("diff shows a fraction",
                  bench.run_strip._bar.value() == 50,
                  f"value was {bench.run_strip._bar.value()} of "
                  f"{bench.run_strip._bar.maximum()}")

            bench.run_strip.finish("probe done")
            check("compare button returns",
                  bench.run_strip._stack.currentIndex() == 0)
    except Exception:
        check("run strip exists", False, traceback.format_exc(limit=5))

    # -- the asynchronous service client -------------------------------------
    #
    # This is the only place it can run. The client needs a Qt binding already
    # loaded, and importing one inside a headless IDA takes the interpreter
    # down -- so the headless suite skips these and they are checked here,
    # where Qt is up because IDA's UI is.

    try:
        from bindiff.client import qt_already_loaded

        check("a Qt binding is loaded in the GUI", qt_already_loaded())
    except Exception:
        check("a Qt binding is loaded in the GUI", False,
              traceback.format_exc(limit=3))

    try:
        from bindiff.qt_shim import QtCore

        check("shim exposes both signal spellings",
              all(hasattr(QtCore, n)
                  for n in ("Signal", "Slot", "pyqtSignal", "pyqtSlot")))
    except Exception:
        check("shim exposes both signal spellings", False,
              traceback.format_exc(limit=3))

    try:
        import threading

        from bindiff.client import make_async_client
        from bindiff.server import BinDiffService, make_server

        service = BinDiffService(Path(tempfile.mkdtemp()) / "cache")
        server = make_server(service, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]

        primary = Path(tempfile.mkdtemp()) / "a.BinExport"
        secondary = primary.with_name("b.BinExport")
        # Deliberately not real exports: this checks that the failure path
        # comes back as a signal rather than an exception on the UI thread,
        # which is the property that matters for not taking IDA down.
        primary.write_bytes(b"not an export")
        secondary.write_bytes(b"also not an export")

        AsyncClient = make_async_client("127.0.0.1", port)
        async_client = AsyncClient()
        outcome = {}
        async_client.finished.connect(lambda r: outcome.setdefault("reply", r))
        async_client.failed.connect(lambda m: outcome.setdefault("error", m))
        async_client.submit_diff(str(primary), str(secondary))

        # Spin the UI event loop briefly rather than blocking it: a blocking
        # wait here would deadlock against the very thing being tested.
        deadline = time.time() + 30
        while not outcome and time.time() < deadline:
            QtCore.QCoreApplication.processEvents()
            time.sleep(0.05)

        check("async client reports through a signal", bool(outcome),
              "neither finished nor failed fired within 30s")
        check("a bad diff fails without raising on the UI thread",
              "error" in outcome, f"outcome was {outcome!r}")
        async_client.shutdown()
        server.shutdown()
    except Exception:
        check("async client reports through a signal", False,
              traceback.format_exc(limit=5))

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
