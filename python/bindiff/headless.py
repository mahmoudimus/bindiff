"""Running the whole diff outside the IDA GUI.

Diffing two binaries needs a .BinExport for each. Producing one needs IDA, and
the C++ plugin gets it by exporting the secondary from inside the GUI process --
which is why the IDB freezes for the length of it.

idalib removes that constraint: a separate process can open a database, export
it and exit, with the GUI never blocking. This module is both halves of that:

    worker side    export(), diff(), pipeline(), and a `python -m
                   bindiff.headless` entry point that speaks JSON on stdout.
    launcher side  find_python_interpreter() and run_headless(), which the
                   plugin uses to start a worker and read its result.

The two halves never run in the same process. The worker imports `idapro`,
which must not be imported inside the GUI; the launcher runs in the GUI, where
it must not. See bindiff.ida_env for why probing for that is unsafe.

Modelled on ida-taskr, which does the same thing for general CPU work.
"""

from __future__ import annotations

import collections
import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence

__all__ = [
    "StageResult",
    "export",
    "diff",
    "pipeline",
    "emit_progress",
    "find_python_interpreter",
    "run_headless",
    "main",
]

# Progress records travel on the same stdout as the result, one JSON object per
# line, under this key. A result carries "ok" and "stage" and a progress record
# does not, so the two could be told apart without a tag -- it is here so that
# neither can ever be mistaken for the other by accident, and so a launcher too
# old to know about progress skips these lines instead of failing on them.
_PROGRESS_KEY = "progress"

# Of the pipeline's work, the share attributed to the two exports. They are the
# slow half by a wide margin -- an export runs a full auto-analysis, the diff
# reads two protobufs -- so a bar that gave them equal weight would sit near
# zero for almost the whole run and then jump.
_EXPORT_SHARE = 0.6

# How much worker chatter to keep for the message when no result arrives. IDA
# writes a great deal of it and only the last few lines say why it stopped.
_TAIL_LINES = 20


@dataclass
class StageResult:
    """What a worker reports back. Serialised as JSON on stdout."""

    ok: bool
    stage: str
    output: Optional[str] = None
    message: str = ""
    matches: Optional[int] = None
    details: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "ok": self.ok,
            "stage": self.stage,
            "output": self.output,
            "message": self.message,
            "matches": self.matches,
            "details": self.details,
        })

    @classmethod
    def from_json(cls, text: str) -> "StageResult":
        data = json.loads(text)
        return cls(ok=data["ok"], stage=data["stage"], output=data.get("output"),
                   message=data.get("message", ""),
                   matches=data.get("matches"),
                   details=data.get("details") or {})


# --------------------------------------------------------------------------
# Worker side. Runs in its own process; never import this half in the GUI.
# --------------------------------------------------------------------------

def _record(stage: str, message: str, *, fraction: Optional[float] = None,
            step_index: Optional[int] = None,
            step_count: Optional[int] = None,
            matches: Optional[int] = None) -> dict:
    """One progress record.

    `fraction` is progress through the *whole* command, not through the stage,
    because only the worker knows how the stages are weighted. The launcher
    renders what it is given.
    """
    return {"stage": stage, "message": message, "fraction": fraction,
            "step_index": step_index, "step_count": step_count,
            "matches": matches}


def emit_progress(record: dict) -> None:
    """Writes one progress record to stdout.

    Flushed, and that is the whole point: the launcher reads this over a pipe,
    and Python block-buffers a pipe. Without the flush every record would
    arrive in one burst when the worker exits, which is exactly when progress
    reporting stops being of any use.
    """
    print(json.dumps({_PROGRESS_KEY: record}), flush=True)


def _rescale(record: dict, base: float, span: float) -> dict:
    """Maps a stage-local fraction onto its slice of the whole command."""
    fraction = record.get("fraction")
    record["fraction"] = base + span * (0.0 if fraction is None else fraction)
    return record


def _invoke_binexport(output_path: str) -> None:
    """Asks the loaded BinExport plugin to write a .BinExport.

    BinExport registers an IDC function, BinExportBinary, which is what the
    C++ BinDiff plugin calls. Going through IDC rather than the plugin's run()
    is deliberate: run() shows UI, the IDC function takes the output path.
    """
    import ida_expr

    escaped = output_path.replace("\\", "\\\\").replace('"', '\\"')
    error = ida_expr.eval_idc_expr(
        None, 0, f'BinExportBinary("{escaped}");')
    if error:
        raise RuntimeError(
            f"BinExportBinary failed: {error}. Is the BinExport plugin "
            f"installed for this IDA?")


def export(input_path: str, output_path: str,
           exporter: Optional[Callable[[str], None]] = None) -> StageResult:
    """Opens `input_path` with idalib and writes a .BinExport.

    `input_path` may be a binary or an existing IDA database. `exporter` is
    injectable so the idalib lifecycle can be exercised without BinExport
    installed.

    Must run in a worker process: it imports idapro, which is not permitted
    inside the IDA GUI.
    """
    import idapro

    if exporter is None:
        exporter = _invoke_binexport

    # Checked here rather than left to idalib: on IDA 9.1 open_database() with a
    # path that does not exist terminates the process outright instead of
    # returning non-zero, which takes the whole worker down and leaves the
    # caller with no result to report. 9.4 returns an error. Either way a
    # missing input is the caller's mistake and needs no disassembler to detect.
    if not Path(input_path).exists():
        return StageResult(ok=False, stage="export",
                           message=f"could not open {input_path}: no such file")

    if idapro.open_database(str(input_path), True) != 0:
        return StageResult(ok=False, stage="export",
                           message=f"could not open {input_path}")
    try:
        exporter(str(output_path))
    except Exception as exc:
        return StageResult(ok=False, stage="export", message=str(exc))
    finally:
        # Never save: exporting must not modify the database it read.
        idapro.close_database(False)

    if not Path(output_path).is_file():
        return StageResult(ok=False, stage="export",
                           message=f"exporter wrote nothing to {output_path}")
    return StageResult(ok=True, stage="export", output=str(output_path))


def diff(primary: str, secondary: str, output: str,
         progress: Optional[Callable[[dict], None]] = None) -> StageResult:
    """Diffs two .BinExport files. Needs no IDA at all.

    `progress` is called with a record per matching step and per round of
    propagating matches through the call graph. The engine's step index only
    advances between steps, so during a long propagation the fraction holds
    still while the match count keeps climbing -- which is the honest picture.
    """
    import bindiff

    def engine_progress(update: dict) -> None:
        count = update.get("step_count") or 0
        index = update.get("step_index")
        progress(_record(
            "diff", update.get("step_name", ""),
            # Work finished *before* this step, so the bar never claims a step
            # is done while it is running. 100% is shown when the result
            # arrives, not before.
            fraction=(index / count) if count and index is not None else None,
            step_index=index, step_count=update.get("step_count"),
            matches=update.get("matches")))

    code = bindiff.diff(str(primary), str(secondary), str(output),
                        progress=engine_progress if progress else None)
    if code != 0:
        return StageResult(ok=False, stage="diff",
                           message=f"diff failed with {code}",
                           details={"code": code})
    return StageResult(ok=True, stage="diff", output=str(output),
                       matches=len(bindiff.load_matches(str(output))))


def pipeline(primary_input: str, secondary_input: str, output: str,
             work_dir: Optional[str] = None,
             exporter: Optional[Callable[[str], None]] = None,
             progress: Optional[Callable[[dict], None]] = None) -> StageResult:
    """Exports both inputs and diffs them.

    Each export opens and closes its own database in turn, in this one process.
    They are not parallelised here: idalib holds one database at a time, so
    overlapping them means more worker processes, which is the launcher's
    decision to make, not this function's.

    An export reports only that it has started. There is no progress to be had
    from inside one: idalib's auto-analysis does not call back, and inventing a
    fraction for it would be a lie told to a progress bar.
    """
    work = Path(work_dir) if work_dir else Path(output).parent
    work.mkdir(parents=True, exist_ok=True)

    sources = (("primary", primary_input), ("secondary", secondary_input))
    exports = []
    for index, (label, source) in enumerate(sources):
        if progress is not None:
            progress(_record("export", f"exporting {label}: {Path(source).name}",
                             fraction=_EXPORT_SHARE * index / len(sources),
                             step_index=index, step_count=len(sources)))
        target = work / f"{Path(source).stem}.{label}.BinExport"
        result = export(source, str(target), exporter=exporter)
        if not result.ok:
            result.details["input"] = source
            return result
        exports.append(str(target))

    def diff_progress(record: dict) -> None:
        progress(_rescale(record, _EXPORT_SHARE, 1.0 - _EXPORT_SHARE))

    result = diff(exports[0], exports[1], output,
                  progress=diff_progress if progress else None)
    result.details["exports"] = exports
    return result


# --------------------------------------------------------------------------
# Launcher side. Runs inside the GUI.
# --------------------------------------------------------------------------

def find_python_interpreter() -> Path:
    """Locates a real Python interpreter to run a worker with.

    sys.executable is *not* it inside IDA: there it points at the ida binary,
    and re-running that would start another IDA rather than a worker.
    sys._base_executable is the underlying interpreter and is what IDA's
    embedded Python leaves behind. Approach taken from ida-taskr.
    """
    base = getattr(sys, "_base_executable", None)
    if base and "python" in Path(base).name.lower():
        return Path(base)

    # Fall back to a python next to sys.prefix, then to sys.executable if it
    # actually looks like an interpreter.
    for candidate in (
        Path(sys.prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}",
        Path(sys.prefix) / "bin" / "python3",
        Path(sys.prefix) / "bin" / "python",
    ):
        if candidate.is_file():
            return candidate

    executable = Path(sys.executable or "")
    if "python" in executable.name.lower():
        return executable

    raise RuntimeError(
        "no Python interpreter found to run a headless worker; set one "
        "explicitly (sys.executable is IDA itself when running in the GUI)")


class _ProgressSink:
    """Delivers progress records, and survives a handler that raises.

    The launcher's contract is to deliver the worker's result. A progress
    handler draws, and drawing code fails in ways that have nothing to do with
    the diff -- so a broken one must not turn a finished diff into no result at
    all. It must not be silent either: the failure is recorded on the result
    under `details["progress_error"]` and the handler is not called again,
    rather than raising the same exception once per step.
    """

    def __init__(self, callback: Optional[Callable[[dict], None]]) -> None:
        self._callback = callback
        self.error = ""

    def __call__(self, record: dict) -> None:
        if self._callback is None:
            return
        try:
            self._callback(record)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self._callback = None


def _classify(line: str, sink: _ProgressSink) -> Optional[StageResult]:
    """Reads one line of worker stdout.

    Returns a StageResult if the line is one. Progress records go to the sink;
    IDA's chatter, which idalib writes freely, is neither and returns None.
    """
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if isinstance(data, dict) and _PROGRESS_KEY in data:
        sink(data[_PROGRESS_KEY])
        return None
    try:
        return StageResult.from_json(line)
    except (ValueError, KeyError):
        return None


def _stream(command: List[str], timeout: Optional[float], sink: _ProgressSink,
            cancel: Optional[threading.Event]) -> StageResult:
    """Runs the worker, reading its output as it arrives."""
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE,
        # Merged rather than piped separately and read afterwards: a worker
        # that fills the stderr pipe while this is still reading stdout would
        # deadlock, and idalib is easily chatty enough to do it. Lines are
        # filtered by shape, so mixing the two streams costs nothing.
        stderr=subprocess.STDOUT, text=True, bufsize=1)

    # Both of these have to act from another thread: this one spends the run
    # blocked in readline, and ending the worker is what unblocks it.
    timed_out = threading.Event()

    def on_timeout() -> None:
        timed_out.set()
        process.kill()

    def on_cancel() -> None:
        # Polled rather than a plain wait() so this thread ends with the worker
        # instead of outliving every diff that was never cancelled.
        while process.poll() is None:
            if cancel.wait(0.2):
                if process.poll() is None:
                    process.terminate()
                return

    watchers = []
    if timeout is not None:
        watchdog = threading.Timer(timeout, on_timeout)
        watchdog.daemon = True
        watchers.append(watchdog)
    if cancel is not None:
        watchers.append(threading.Thread(target=on_cancel, daemon=True))
    for watcher in watchers:
        watcher.start()

    result = None
    tail = collections.deque(maxlen=_TAIL_LINES)
    try:
        for line in process.stdout:
            parsed = _classify(line, sink)
            if parsed is not None:
                result = parsed
            elif not line.strip().startswith("{"):
                tail.append(line.rstrip())
        process.wait()
    finally:
        for watcher in watchers:
            if isinstance(watcher, threading.Timer):
                watcher.cancel()
        process.stdout.close()

    if timed_out.is_set():
        return StageResult(ok=False, stage="worker",
                           message=f"worker timed out after {timeout:g}s")
    if cancel is not None and cancel.is_set():
        # Terminating the worker loses whatever it had matched. The engine can
        # cancel to a smaller but coherent result, but that only reaches a
        # caller in the same process; across a process boundary there is
        # nothing to hand back.
        return StageResult(ok=False, stage="worker", message="cancelled")
    if result is not None:
        return result
    return StageResult(
        ok=False, stage="worker",
        message=(f"worker produced no result (exit {process.returncode}): "
                 f"{' | '.join(tail)[-500:]}"))


def run_headless(args: Sequence[str], *,
                 interpreter: Optional[Path] = None,
                 timeout: Optional[float] = None,
                 runner: Optional[Callable] = None,
                 on_progress: Optional[Callable[[dict], None]] = None,
                 cancel: Optional[threading.Event] = None) -> StageResult:
    """Runs one worker command and returns its result.

    Blocking. In the GUI, call it from a worker thread or a QProcess -- this is
    the piece that must not sit on the UI thread, which is the whole reason the
    work is out of process.

    `on_progress` is called with each record the worker emits, on this thread,
    as the lines arrive. Anything it touches in the UI has to be posted to the
    UI thread; it is not called there.

    `cancel` is an event that terminates the worker when set.

    A timeout returns a failing result rather than raising: a caller running
    this on a worker thread has nowhere to catch an exception, and a thread
    that dies quietly leaves the UI waiting for an answer that never comes.

    `runner` is injectable so the command construction and result parsing can
    be tested without spawning anything. It is handed the finished output in
    one piece, so progress arrives all at once -- the streaming path is the
    real one.
    """
    if interpreter is None:
        interpreter = find_python_interpreter()
    command = [str(interpreter), "-m", "bindiff.headless", *args]
    sink = _ProgressSink(on_progress)

    if runner is None:
        result = _stream(command, timeout, sink, cancel)
    else:
        completed = runner(command, capture_output=True, text=True,
                           timeout=timeout)
        result = None
        for line in (completed.stdout or "").splitlines():
            parsed = _classify(line, sink)
            if parsed is not None:
                result = parsed
        if result is None:
            result = StageResult(
                ok=False, stage="worker",
                message=(f"worker produced no result "
                         f"(exit {completed.returncode}): "
                         f"{(completed.stderr or '').strip()[:500]}"))

    if sink.error:
        result.details["progress_error"] = sink.error
    return result


def main(argv: Optional[List[str]] = None) -> int:
    """Worker entry point: `python -m bindiff.headless <command> ...`."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(StageResult(ok=False, stage="cli",
                          message="usage: export|diff|pipeline ...").to_json())
        return 2

    command, rest = argv[0], argv[1:]
    try:
        if command == "export" and len(rest) == 2:
            result = export(rest[0], rest[1])
        elif command == "diff" and len(rest) == 3:
            result = diff(rest[0], rest[1], rest[2], progress=emit_progress)
        elif command == "pipeline" and len(rest) == 3:
            result = pipeline(rest[0], rest[1], rest[2],
                              progress=emit_progress)
        else:
            result = StageResult(ok=False, stage="cli",
                                 message=f"bad arguments for {command!r}")
    except Exception as exc:  # a worker must always report, never traceback out
        result = StageResult(ok=False, stage=command,
                             message=f"{type(exc).__name__}: {exc}")

    print(result.to_json())
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
