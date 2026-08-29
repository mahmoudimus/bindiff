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
