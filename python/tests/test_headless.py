"""Tests for the out-of-process diff pipeline.

The diff stage is exercised for real, through an actual subprocess. The export
stage needs the BinExport plugin, which is not installed in the test image, so
its idalib lifecycle is tested with an injected exporter and the BinExport call
itself is not covered here -- see test_export_opens_and_closes_a_database.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from bindiff.headless import (
    StageResult,
    find_python_interpreter,
    main,
    run_headless,
)


class TestStageResult:
    def test_round_trips(self):
        original = StageResult(ok=True, stage="diff", output="/tmp/x.BinDiff",
                               matches=116, details={"code": 0})
        restored = StageResult.from_json(original.to_json())
        assert restored == original

    def test_json_is_a_single_line(self):
        """The launcher scans stdout backwards for a line starting with "{",
        so a pretty-printed result would not be found."""
        text = StageResult(ok=False, stage="export", message="a\nb").to_json()
        assert "\n" not in text


class TestInterpreterDiscovery:
    def test_prefers_base_executable(self, monkeypatch):
        monkeypatch.setattr(sys, "_base_executable", "/usr/bin/python3.13",
                            raising=False)
        assert find_python_interpreter() == Path("/usr/bin/python3.13")

    def test_ignores_base_executable_when_it_is_ida(self, monkeypatch, tmp_path):
        """Inside the GUI these point at the ida binary. Re-running that would
        start a second IDA instead of a worker."""
        monkeypatch.setattr(sys, "_base_executable", "/opt/ida/ida64",
                            raising=False)
        monkeypatch.setattr(sys, "executable", "/opt/ida/ida64")
        # Falls through to a prefix-relative interpreter, which exists here.
        assert "python" in find_python_interpreter().name.lower()

    def test_raises_when_nothing_looks_like_python(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "_base_executable", "/opt/ida/ida64",
                            raising=False)
        monkeypatch.setattr(sys, "executable", "/opt/ida/ida64")
        monkeypatch.setattr(sys, "prefix", str(tmp_path))
        with pytest.raises(RuntimeError, match="no Python interpreter"):
            find_python_interpreter()


class TestRunHeadless:
    def test_builds_the_command(self):
        seen = {}

        def runner(command, **kwargs):
            seen["command"] = command
            return subprocess.CompletedProcess(
                command, 0,
                stdout=StageResult(ok=True, stage="diff").to_json(), stderr="")

        result = run_headless(["diff", "a", "b", "c"],
                              interpreter=Path("/usr/bin/python3"),
                              runner=runner)
        assert result.ok
        assert seen["command"] == ["/usr/bin/python3", "-m", "bindiff.headless",
                                   "diff", "a", "b", "c"]

    def test_finds_the_result_after_ida_chatter(self):
        """idalib writes freely to stdout, so the result is not the only line."""
        noisy = ("Loading processor module...\n"
                 "autoanalysis complete\n"
                 + StageResult(ok=True, stage="diff", matches=7).to_json())

        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout=noisy,
                                               stderr="")

        result = run_headless(["diff"], interpreter=Path("/x"), runner=runner)
        assert result.ok and result.matches == 7

    def test_reports_a_worker_that_produced_nothing(self):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 139, stdout="",
                                               stderr="Segmentation fault")

        result = run_headless(["diff"], interpreter=Path("/x"), runner=runner)
        assert not result.ok
        assert "139" in result.message and "Segmentation fault" in result.message

    def test_ignores_a_non_result_brace_line(self):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(
                command, 0,
                stdout='{"unrelated": true}\n'
                       + StageResult(ok=True, stage="diff").to_json(),
                stderr="")

        assert run_headless(["diff"], interpreter=Path("/x"),
                            runner=runner).ok


class TestProgressProtocol:
    """Progress records share stdout with the result and must never be
    confused for one, in either direction."""

    def _runner_for(self, lines):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0,
                                               stdout="\n".join(lines),
                                               stderr="")
        return runner

    def test_records_reach_the_handler_and_the_result_still_arrives(self):
        seen = []
        runner = self._runner_for([
            "Loading processor module...",
            json.dumps({"progress": {"stage": "export", "message": "a"}}),
            json.dumps({"progress": {"stage": "diff", "message": "b"}}),
            StageResult(ok=True, stage="diff", matches=3).to_json(),
        ])

        result = run_headless(["pipeline"], interpreter=Path("/x"),
                              runner=runner, on_progress=seen.append)

        assert result.ok and result.matches == 3
        assert [r["message"] for r in seen] == ["a", "b"]

    def test_a_progress_record_is_never_taken_for_a_result(self):
        """A record arriving after the result must not replace it."""
        runner = self._runner_for([
            StageResult(ok=True, stage="diff", matches=9).to_json(),
            json.dumps({"progress": {"stage": "diff", "message": "late"}}),
        ])

        result = run_headless(["diff"], interpreter=Path("/x"), runner=runner)
        assert result.ok and result.matches == 9

    def test_no_handler_is_not_an_error(self):
        """An older caller passes no handler; the records are just skipped."""
        runner = self._runner_for([
            json.dumps({"progress": {"stage": "diff"}}),
            StageResult(ok=True, stage="diff").to_json(),
        ])
        assert run_headless(["diff"], interpreter=Path("/x"), runner=runner).ok

    def test_a_broken_handler_does_not_cost_the_result(self):
        """The handler draws; the launcher delivers. A drawing bug must not
        turn a finished diff into no result at all -- but it must be visible,
        or it looks like the worker stopped reporting on its own."""
        calls = []

        def explode(record):
            calls.append(record)
            raise RuntimeError("widget is gone")

        runner = self._runner_for([
            json.dumps({"progress": {"stage": "diff", "message": "one"}}),
            json.dumps({"progress": {"stage": "diff", "message": "two"}}),
            StageResult(ok=True, stage="diff", matches=5).to_json(),
        ])

        result = run_headless(["diff"], interpreter=Path("/x"), runner=runner,
                              on_progress=explode)

        assert result.ok and result.matches == 5
        assert "widget is gone" in result.details["progress_error"]
        # Called once, not once per record: a handler that failed will fail
        # again, and repeating it buries the real output.
        assert len(calls) == 1


class TestWorkerProgressRecords:
    def test_diff_reports_each_step(self, monkeypatch):
        """The engine's step dicts become records with an overall fraction."""
        import bindiff.headless as headless

        def fake_diff(primary, secondary, output, progress=None):
            progress({"step_index": 0, "step_count": 4,
                      "step_name": "function: hash matching", "matches": 0})
            progress({"step_index": 2, "step_count": 4,
                      "step_name": "function: call sequence", "matches": 40})
            return 0

        module = type(sys)("bindiff")
        module.diff = fake_diff
        module.load_matches = lambda path: [1, 2, 3]
        monkeypatch.setitem(sys.modules, "bindiff", module)

        seen = []
        result = headless.diff("a", "b", "c", progress=seen.append)

        assert result.ok and result.matches == 3
        assert [r["stage"] for r in seen] == ["diff", "diff"]
        assert seen[0]["message"] == "function: hash matching"
        # Work finished before the step starts, so the first report is 0 and
        # the bar never claims a running step is done.
        assert seen[0]["fraction"] == 0.0
        assert seen[1]["fraction"] == 0.5
        assert seen[1]["matches"] == 40

    def test_pipeline_weights_the_exports_ahead_of_the_diff(self, monkeypatch,
                                                            tmp_path):
        """Exports are the slow half; a bar that ignored them would sit near
        zero for most of the run and then jump."""
        import bindiff.headless as headless

        def fake_diff(primary, secondary, output, progress=None):
            progress({"step_index": 0, "step_count": 2, "step_name": "s",
                      "matches": 0})
            return 0

        module = type(sys)("bindiff")
        module.diff = fake_diff
        module.load_matches = lambda path: []
        monkeypatch.setitem(sys.modules, "bindiff", module)

        # Stubbed rather than driven with an injected exporter: export() still
        # opens a real database through idalib, and what is under test here is
        # how the stages are weighted, not the disassembler.
        monkeypatch.setattr(headless, "export", lambda source, target, **kw:
                            StageResult(ok=True, stage="export",
                                        output=str(target)))

        seen = []
        result = headless.pipeline(
            str(tmp_path / "one"), str(tmp_path / "two"),
            str(tmp_path / "out.BinDiff"), progress=seen.append)

        assert result.ok, result.message
        stages = [r["stage"] for r in seen]
        assert stages == ["export", "export", "diff"]
        assert [r["fraction"] for r in seen] == [0.0, 0.3, 0.6]

    def test_emit_writes_one_flushed_line(self, capsys):
        """One line, because the launcher reads line by line -- and flushed,
        because stdout is a pipe there and would otherwise deliver every
        record at once when the worker exits."""
        from bindiff.headless import emit_progress

        emit_progress({"stage": "diff", "message": "x"})
        out = capsys.readouterr().out
        assert out.count("\n") == 1
        assert json.loads(out)["progress"]["message"] == "x"


class TestStreamingWorker:
    """The streaming path, exercised directly.

    run_headless always runs `python -m bindiff.headless`, so a worker that
    hangs or is slow on purpose cannot be expressed through it. _stream is
    where the timeout, the cancellation and the incremental reads live.
    """

    def _stream(self, script, **kwargs):
        from bindiff.headless import _ProgressSink, _stream

        kwargs.setdefault("timeout", None)
        kwargs.setdefault("cancel", None)
        sink = kwargs.pop("sink", None) or _ProgressSink(None)
        return _stream([sys.executable, "-c", script], sink=sink, **kwargs)

    def test_records_arrive_while_the_worker_is_still_running(self):
        """The point of the whole exercise: a record read at exit is not
        progress, it is history."""
        from bindiff.headless import _ProgressSink

        script = (
            "import json, time\n"
            "print(json.dumps({'progress': {'stage': 'diff'}}), flush=True)\n"
            "time.sleep(3)\n"
            "print(json.dumps({'ok': True, 'stage': 'diff'}), flush=True)\n"
        )
        arrivals = []
        started = time.monotonic()
        result = self._stream(
            script, sink=_ProgressSink(
                lambda record: arrivals.append(time.monotonic() - started)))

        assert result.ok
        assert arrivals, "no progress record arrived"
        assert arrivals[0] < 2.0, (
            f"record arrived after {arrivals[0]:.1f}s; the worker sleeps for "
            f"3s before exiting, so this was read from a buffer at exit")

    def test_timeout_returns_a_result_rather_than_raising(self):
        """A caller on a worker thread has nowhere to catch an exception, and
        a thread that dies quietly leaves the UI waiting forever."""
        started = time.monotonic()
        result = self._stream("import time; time.sleep(60)", timeout=1.0)

        assert not result.ok
        assert "timed out" in result.message
        assert time.monotonic() - started < 30

    def test_cancel_ends_the_worker(self):
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()

        started = time.monotonic()
        result = self._stream("import time; time.sleep(60)", cancel=cancel)

        assert not result.ok and result.message == "cancelled"
        assert time.monotonic() - started < 30

    def test_chatter_is_kept_for_a_worker_that_reports_nothing(self):
        script = ("import sys\n"
                  "print('autoanalysis complete')\n"
                  "sys.stderr.write('terminated by signal\\n')\n"
                  "sys.exit(3)\n")
        result = self._stream(script)

        assert not result.ok
        assert "exit 3" in result.message
        # stderr is merged into stdout rather than read afterwards, so a
        # crash message written there is not lost.
        assert "terminated by signal" in result.message


class TestCli:
    def test_no_arguments_is_an_error(self, capsys):
        assert main([]) == 2
        assert not json.loads(capsys.readouterr().out)["ok"]

    def test_bad_arity_is_reported_not_raised(self, capsys):
        assert main(["diff", "only-one-arg"]) == 1
        result = json.loads(capsys.readouterr().out)
        assert not result["ok"] and result["stage"] == "cli"

    def test_exceptions_become_results(self, capsys):
        """A worker must always print a result; a traceback would leave the
        launcher reporting "produced no result"."""
        assert main(["diff", "/nope/a", "/nope/b", "/nope/c"]) == 1
        result = json.loads(capsys.readouterr().out)
        assert not result["ok"]


@pytest.mark.requires_extension
@pytest.mark.e2e
def test_diff_runs_in_a_real_subprocess(insider_pair, tmp_path):
    """End to end through the actual worker entry point.

    This is the stage that needs no IDA, so it is fully exercisable: the
    launcher spawns a real interpreter, the worker diffs, and the result comes
    back over the JSON protocol.
    """
    primary, secondary = insider_pair
    output = tmp_path / "headless.BinDiff"

    result = run_headless(["diff", str(primary), str(secondary), str(output)],
                          interpreter=Path(sys.executable), timeout=300)

    assert result.ok, result.message
    assert result.stage == "diff"
    assert Path(result.output).is_file()
    assert result.matches and result.matches > 0


@pytest.mark.requires_extension
@pytest.mark.e2e
def test_progress_reaches_the_launcher_from_a_real_worker(insider_pair,
                                                          tmp_path):
    """The whole path: engine callback -> worker stdout -> launcher handler."""
    primary, secondary = insider_pair
    records = []

    result = run_headless(
        ["diff", str(primary), str(secondary),
         str(tmp_path / "progress.BinDiff")],
        interpreter=Path(sys.executable), timeout=300,
        on_progress=records.append)

    assert result.ok, result.message
    assert records, "the worker reported no progress at all"
    assert {r["stage"] for r in records} == {"diff"}
    assert all(r["message"] for r in records), "a step reported no name"

    fractions = [r["fraction"] for r in records if r["fraction"] is not None]
    assert fractions == sorted(fractions), "progress went backwards"
    assert max(fractions) < 1.0, (
        "a step reported itself complete while it was still running")
    # The engine reports before each step and on each propagation round, so
    # there is more than one report even for a small pair.
    assert len(records) > 1


@pytest.mark.requires_extension
def test_diff_failure_is_reported_through_the_protocol(tmp_path):
    result = run_headless(
        ["diff", str(tmp_path / "missing.BinExport"),
         str(tmp_path / "also-missing.BinExport"), str(tmp_path / "o.BinDiff")],
        interpreter=Path(sys.executable), timeout=120)

    assert not result.ok
    assert result.details.get("code") in (-1, -2)


@pytest.mark.slow
def test_export_opens_and_closes_a_database(tmp_path):
    """The idalib half of the export stage, with the exporter injected.

    BinExport is not installed in the test image, so the real BinExportBinary
    call cannot be covered here. What this does check is the part that is easy
    to get wrong: that a database opens headlessly, that the exporter runs
    while it is open, and that it is closed again without saving.
    """
    import importlib.util

    if importlib.util.find_spec("idapro") is None:
        pytest.skip("idalib not available")

    source = tmp_path / "sample.c"
    source.write_text("int helper(int x){return x*3;}\nint main(){return helper(14);}\n")
    binary = tmp_path / "sample"
    try:
        subprocess.run(["gcc", "-O0", "-o", str(binary), str(source)],
                       check=True, capture_output=True, timeout=120)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("no C compiler to build a sample binary")

    from bindiff.headless import export

    observed = {}

    def fake_exporter(output_path):
        # Runs while the database is open, so IDA's API must work here.
        import ida_funcs

        observed["functions"] = ida_funcs.get_func_qty()
        Path(output_path).write_bytes(b"not a real BinExport")

    result = export(str(binary), str(tmp_path / "out.BinExport"),
                    exporter=fake_exporter)

    assert result.ok, result.message
    assert observed["functions"] > 0, "the database was not analysed"
    assert Path(result.output).is_file()


@pytest.mark.slow
def test_export_reports_an_unopenable_input(tmp_path):
    """A missing input must be reported, not handed to the disassembler.

    On IDA 9.1 idapro.open_database() with a nonexistent path terminates the
    process rather than returning non-zero, so this used to kill the whole
    pytest run on the 9.1 leg -- with no summary and no traceback, which looked
    from the outside like a hang rather than a failure.
    """
    import importlib.util

    if importlib.util.find_spec("idapro") is None:
        pytest.skip("idalib not available")

    from bindiff.headless import export

    result = export(str(tmp_path / "does-not-exist"),
                    str(tmp_path / "out.BinExport"),
                    exporter=lambda path: None)
    assert not result.ok
    assert result.stage == "export"
    assert "could not open" in result.message
    assert "no such file" in result.message
