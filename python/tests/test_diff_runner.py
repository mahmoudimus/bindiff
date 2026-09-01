"""Tests for the plugin's diff sequence.

Every piece this wires together is tested elsewhere -- the worker protocol in
test_headless, the progress arithmetic in test_ui_logic, the panel widgets in
the GUI harness. What was not tested is the wiring, because it lived inside the
plugin class, which only exists when IDA is present.

So the sequence moved into ida_plugin.diff_runner with its collaborators
injected, and this drives it with fakes. The property worth protecting is that
**nothing touches the UI except through a post**, which a fake can check by
simply not running the actions.
"""

from __future__ import annotations

import pytest

from ida_plugin.diff_runner import (DiffRun, classify, default_output_name,
                                    panel_title,
                                    worker_arguments, primary_export_source)


class Result:
    """Stands in for a worker StageResult."""

    def __init__(self, ok=True, message="", matches=0, **details):
        self.ok = ok
        self.message = message
        self.matches = matches
        self.details = dict(details)


class Panel:
    def __init__(self):
        self.progress = []
        self.finished = None

    def update_progress(self, progress):
        self.progress.append(progress)

    def finish(self, message):
        self.finished = message


class Harness:
    """The plugin's collaborators, recorded rather than performed."""

    def __init__(self, result, records=(), post=True):
        self.result = result
        self.records = list(records)
        self.panel = Panel()
        self.events = []
        self.posted = []
        self.run_arguments = None
        # When False, posted actions are captured and never run -- which is how
        # "did anything reach the UI without being posted?" is asked.
        self._run_posted = post

    def runner(self, args, on_progress=None, cancel=None):
        self.run_arguments = (list(args), cancel)
        for record in self.records:
            on_progress(record)
        return self.result

    def _post(self, label):
        def post(action):
            self.posted.append(label)
            if self._run_posted:
                action()
        return post

    def build(self):
        return DiffRun(
            runner=self.runner, panel=self.panel,
            post_progress=self._post("progress"),
            post_result=self._post("result"),
            report=lambda text: self.events.append(("report", text)),
            warn=lambda text: self.events.append(("warn", text)),
            load=lambda path: self.events.append(("load", path)))

    def execute(self, cancel=None):
        return self.build().execute(worker_arguments("a.exe", "b.exe", "o.BinDiff"),
                                    "o.BinDiff", cancel)


class TestClassify:
    def test_a_finished_diff_is_opened(self):
        outcome = classify(Result(ok=True, matches=116))
        assert outcome.status == "complete"
        assert outcome.open_result
        assert "116 matches" in outcome.panel_message
        assert outcome.warning == ""

    def test_a_cancelled_diff_that_wrote_a_result_is_still_opened(self):
        """The matching steps run strongest first, so what a cancelled diff
        holds is the matches worth having. Labelled, not discarded."""
        outcome = classify(Result(ok=True, matches=74, cancelled=True))
        assert outcome.status == "partial"
        assert outcome.open_result
        assert "partial" in outcome.panel_message
        assert outcome.warning == ""

    def test_a_cancel_with_no_result_is_not_a_failure(self):
        """A cancel during an export has nothing to open, and the user asked
        for it -- so no warning box."""
        outcome = classify(Result(ok=False, message="cancelled", cancelled=True))
        assert outcome.status == "cancelled"
        assert not outcome.open_result
        assert outcome.warning == ""
        assert outcome.report == "diff cancelled"

    def test_a_real_failure_warns_and_opens_nothing(self):
        outcome = classify(Result(ok=False, message="worker timed out after 3600s"))
        assert outcome.failed
        assert not outcome.open_result
        assert "timed out" in outcome.warning
        assert "timed out" in outcome.panel_message


class TestSequence:
    def test_a_successful_diff_loads_then_reports(self):
        harness = Harness(Result(ok=True, matches=116))
        harness.execute()

        assert harness.panel.finished == "116 matches (complete)"
        assert harness.events == [("load", "o.BinDiff"),
                                  ("report", "diff complete: 116 matches")]

    def test_a_failure_warns_and_loads_nothing(self):
        harness = Harness(Result(ok=False, message="no such file"))
        harness.execute()

        assert [kind for kind, _ in harness.events] == ["warn"]
        assert harness.panel.finished == "failed: no such file"

    def test_a_cancelled_run_reports_without_warning(self):
        harness = Harness(Result(ok=False, message="cancelled", cancelled=True))
        harness.execute()

        assert harness.events == [("report", "diff cancelled")]
        assert harness.panel.finished == "cancelled"

    def test_progress_records_reach_the_panel_in_order(self):
        harness = Harness(Result(ok=True, matches=9), records=[
            {"stage": "export", "message": "exporting primary: a.exe"},
            {"stage": "diff", "message": "function: hash matching",
             "fraction": 0.6, "matches": 3},
        ])
        harness.execute()

        assert [p.message for p in harness.panel.progress] == [
            "exporting primary: a.exe", "function: hash matching"]
        assert harness.panel.progress[0].percentage is None  # export
        assert harness.panel.progress[1].percentage == 60

    def test_nothing_reaches_the_ui_except_through_a_post(self):
        """The property the whole split exists for. With the posts capturing
        rather than running, a UI call that skipped one would still land."""
        harness = Harness(Result(ok=True, matches=5),
                          records=[{"stage": "diff", "message": "x"}],
                          post=False)
        harness.execute()

        assert harness.posted == ["progress", "result"]
        assert harness.panel.progress == []
        assert harness.panel.finished is None
        assert harness.events == []

    def test_a_broken_progress_handler_is_reported_alongside_the_result(self):
        """run_headless keeps going when a handler raises and leaves the reason
        on the result. Silence would look like the worker stopped reporting."""
        harness = Harness(Result(ok=True, matches=5,
                                 progress_error="RuntimeError: widget is gone"))
        harness.execute()

        assert ("report", "progress reporting stopped: "
                          "RuntimeError: widget is gone") in harness.events
        # And the diff itself is still delivered.
        assert ("load", "o.BinDiff") in harness.events

    def test_the_cancel_event_reaches_the_worker(self):
        import threading

        cancel = threading.Event()
        harness = Harness(Result(ok=True, matches=1))
        harness.execute(cancel)

        assert harness.run_arguments[1] is cancel


class TestCommandConstruction:
    def test_the_worker_is_asked_for_the_whole_pipeline(self):
        """Not just the diff: the plugin has two binaries, not two exports."""
        assert worker_arguments("a.exe", "b.exe", "o.BinDiff") == [
            "pipeline", "a.exe", "b.exe", "o.BinDiff"]

    def test_paths_are_stringified(self):
        """A Path must not reach the command line as a Path.

        Compared against str(path) rather than a literal, because a literal
        bakes in the separator: str(WindowsPath("/x/a.exe")) is "\\x\\a.exe",
        and this test failed on Windows for that reason alone while the code
        under it was correct. The claim is that paths are stringified, not that
        they look like POSIX.
        """
        from pathlib import Path

        paths = [Path("/x/a.exe"), Path("/x/b.exe"), Path("/x/o.BinDiff")]
        arguments = worker_arguments(*paths)

        assert arguments == ["pipeline"] + [str(p) for p in paths]
        assert all(isinstance(argument, str) for argument in arguments)

    def test_the_panel_title_names_the_file_not_the_path(self):
        assert panel_title("/very/long/path/to/sample.exe") == (
            "BinDiff - diffing sample.exe")


def test_the_runner_module_stays_free_of_qt_and_ida():
    """The reason it can be tested at all. Easy to undo by adding one import.

    Checked by walking the imports rather than searching the text: this file
    *names* ida_kernwin.execute_sync in its documentation, deliberately, since
    explaining what `post` is for is the whole reason the seam is legible. A
    substring search cannot tell a mention from a dependency, and one that
    fails on prose teaches people to delete the prose.
    """
    import ast
    from pathlib import Path

    import ida_plugin.diff_runner as runner

    tree = ast.parse(Path(runner.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    for name in sorted(imported):
        root = name.split(".")[0]
        assert root not in {"ida_kernwin", "ida_idaapi", "ida_nalt", "idaapi",
                            "idc", "PyQt5", "PySide6"}, (
            f"diff_runner.py imports {name}")
        assert not name.endswith("qt_shim"), f"diff_runner.py imports {name}"


@pytest.mark.requires_extension
def test_the_sequence_runs_against_the_real_worker(bindiff_module, insider_pair,
                                                   tmp_path):
    """Same sequence, with run_headless actually spawning a worker.

    The fakes above check the wiring; this checks the wiring is to something
    real -- that run_headless still accepts the arguments DiffRun passes, which
    is exactly the seam a signature change would break silently.

    Takes `bindiff_module` purely to be skipped without it: the marker alone is
    a label, and importing run_headless pulls in the package, which pulls in the
    extension. Everything above this line runs on a bare Python.
    """
    import functools
    import sys
    from pathlib import Path

    from bindiff.headless import run_headless

    primary, secondary = insider_pair
    output = tmp_path / "runner.BinDiff"

    harness = Harness(None)
    harness.runner = functools.partial(
        run_headless, interpreter=Path(sys.executable), timeout=300)

    outcome = harness.build().execute(
        ["diff", str(primary), str(secondary), str(output)], str(output))

    assert outcome.status == "complete", outcome.panel_message
    assert harness.panel.progress, "no progress reached the panel"
    assert ("load", str(output)) in harness.events
    assert output.is_file()


class TestPrimaryExportSource:
    """Which file the primary side is exported from.

    The plugin used to hand the worker ida_nalt.get_input_file_path(), the
    original binary, so every diff re-analysed it from scratch and compared
    against a database nobody had worked in.
    """

    def test_the_saved_database_wins(self, tmp_path):
        idb = tmp_path / "sample.i64"
        idb.write_bytes(b"IDA1")
        assert primary_export_source(idb, tmp_path / "sample.dll") == str(idb)

    def test_the_binary_is_the_fallback_when_nothing_is_saved(self, tmp_path):
        binary = tmp_path / "sample.dll"
        assert primary_export_source("", binary) == str(binary)
        assert primary_export_source(None, binary) == str(binary)

    def test_a_database_path_that_does_not_exist_is_not_used(self, tmp_path):
        """get_path can name an .i64 that was never written."""
        binary = tmp_path / "sample.dll"
        assert primary_export_source(tmp_path / "missing.i64", binary) == str(
            binary)

    def test_nothing_to_export_reads_as_none(self):
        assert primary_export_source(None, None) is None


class TestDefaultOutputName:
    def test_it_names_both_sides(self):
        assert default_output_name(
            "/a/Wow_loader-12.1.0.69404-devirt.dll.i64",
            "/b/Wow_loader-12.1.0.69497-devirt.dll.i64"
        ) == ("Wow_loader-12.1.0.69404-devirt.dll_vs_"
              "Wow_loader-12.1.0.69497-devirt.dll.BinDiff")

    def test_only_the_last_suffix_goes(self):
        """Version numbers contain dots, so stripping every suffix would turn
        Wow_loader-12.1.0.69404-devirt.dll into Wow_loader-12."""
        assert default_output_name("/a/x-12.1.0.dll", "/b/y-12.2.0.dll") == (
            "x-12.1.0_vs_y-12.2.0.BinDiff")

    def test_a_binexport_pair_reads_sensibly(self):
        assert default_output_name("/a/one.BinExport", "/b/two.BinExport") == (
            "one_vs_two.BinDiff")

    def test_a_name_without_a_suffix_survives(self):
        assert default_output_name("/a/primary", "/b/secondary") == (
            "primary_vs_secondary.BinDiff")
