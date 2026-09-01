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
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence

__all__ = [
    "StageResult",
    "export",
    "diff",
    "pipeline",
    "emit_progress",
    "interpreter_candidates",
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

# Cancelling is a conversation, not a kill. The launcher writes this token on
# the worker's stdin; the worker answers with a "cancelling" progress record,
# stops the diff at its next callback, and writes out the smaller result it is
# already holding -- which reaches the launcher the same way a complete one
# does, as a .BinDiff on disk named by a JSON line on stdout.
#
# stdin rather than a signal because signals are not portable: SIGINT cannot be
# delivered to a single child on Windows, and CTRL_BREAK_EVENT needs a separate
# process group. A line on a pipe behaves the same everywhere.
_CANCEL_TOKEN = "cancel"
_CANCEL_FLAG = "--cancel-on-stdin"
_CANCELLING_STAGE = "cancelling"

# How long to wait for the worker to say it heard the cancel. Only an export
# stays silent this long: idalib does not call back during auto-analysis, so
# there is no callback to notice the request and nothing partial to save.
_CANCEL_ACK_TIMEOUT = 5.0

# Having heard it, how long to let the worker finish writing. Generous, because
# what it buys is the matches already made; the alternative is throwing them
# away to save a few seconds.
_CANCEL_GRACE = 300.0


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


_emit_lock = threading.Lock()


def emit_progress(record: dict) -> None:
    """Writes one progress record to stdout.

    Flushed, and that is the whole point: the launcher reads this over a pipe,
    and Python block-buffers a pipe. Without the flush every record would
    arrive in one burst when the worker exits, which is exactly when progress
    reporting stops being of any use.

    Written as one string under a lock because the cancel listener emits from
    its own thread while the diff is emitting from the matching thread, and a
    line torn in half by an interleaved write is a line the launcher cannot
    parse.
    """
    line = json.dumps({_PROGRESS_KEY: record}) + "\n"
    with _emit_lock:
        sys.stdout.write(line)
        sys.stdout.flush()


def watch_stdin_for_cancel(flag: threading.Event,
                           stream=None) -> threading.Thread:
    """Sets `flag` when the launcher asks the worker to stop.

    The acknowledgement goes out before the flag is set, so the launcher knows
    the request was heard while the diff is still winding down. Without it the
    launcher could not tell "finishing the current step" from "wedged inside an
    export", and would have to guess how long to wait before killing.
    """
    if stream is None:
        stream = sys.stdin

    def watch() -> None:
        try:
            for line in stream:
                if line.strip() == _CANCEL_TOKEN:
                    emit_progress(_record(
                        _CANCELLING_STAGE,
                        "cancelling: writing out what has been matched"))
                    flag.set()
                    return
        except Exception:
            return  # stdin closed or unreadable; there is nothing to watch.

    thread = threading.Thread(target=watch, daemon=True,
                              name="bindiff-cancel-listener")
    thread.start()
    return thread


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


def dump_types(input_path: str, output_path: str) -> StageResult:
    """Opens a database with idalib and writes its types beside it.

    A .BinExport cannot carry a type -- BinExport2 has no type table and no
    prototypes -- so porting types reads the database directly. Done here
    rather than from a second running IDA because the worker already knows how
    to open one headlessly, and because it then works from a file rather than
    requiring the other side to be open.

    Must run in a worker process: it imports idapro.
    """
    import json

    import idapro

    from bindiff.typeinfo import to_json

    if not Path(input_path).exists():
        return StageResult(ok=False, stage="types",
                           message=f"could not open {input_path}: no such file")

    # Opened through a copy. IDA holds a database that is open in a GUI, and
    # the one you want types from is usually the one you have open -- that is
    # how you know it has types worth taking. Copying is cheap next to
    # opening, and it also means this never has the other IDA's file open for
    # writing.
    source = Path(input_path)
    holder = tempfile.mkdtemp(prefix="bindiff-types-")
    working = str(Path(holder) / source.name)
    try:
        shutil.copyfile(source, working)
        # An .i64 is not self-contained for a database IDA has not packed; the
        # companion files sit beside it under the same stem.
        for companion in source.parent.glob(f"{source.stem}.*"):
            if companion != source and companion.is_file():
                shutil.copyfile(companion, str(Path(holder) / companion.name))
    except OSError as exc:
        shutil.rmtree(holder, ignore_errors=True)
        return StageResult(ok=False, stage="types",
                           message=f"could not copy {input_path}: {exc}")

    if idapro.open_database(working, True) != 0:
        shutil.rmtree(holder, ignore_errors=True)
        return StageResult(ok=False, stage="types",
                           message=f"could not open {input_path}")
    try:
        from bindiff.typeinfo_ida import read_types

        declarations, functions = read_types()
    except Exception as exc:  # an IDA API this build does not have
        idapro.close_database(False)
        shutil.rmtree(holder, ignore_errors=True)
        return StageResult(ok=False, stage="types",
                           message=f"reading types failed: {exc}")
    idapro.close_database(False)
    shutil.rmtree(holder, ignore_errors=True)

    Path(output_path).write_text(
        json.dumps(to_json(declarations, functions, source=input_path),
                   indent=1),
        encoding="utf-8")
    return StageResult(
        ok=True, stage="types", output=output_path,
        message=(f"{len(declarations)} type(s), "
                 f"{len(functions)} prototype(s)"),
        details={"types": len(declarations), "functions": len(functions)})


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
    types_written = 0
    try:
        exporter(str(output_path))
        # Written here because the database is already open. Reading types
        # costs an idalib open, and that open has just been paid for -- doing
        # it later, on demand, pays it a second time for nothing. A
        # .BinExport cannot carry a type, so this is the only moment it is
        # free.
        types_written = _write_types_beside(output_path)
    except Exception as exc:
        return StageResult(ok=False, stage="export", message=str(exc))
    finally:
        # Never save: exporting must not modify the database it read.
        idapro.close_database(False)

    if not Path(output_path).is_file():
        return StageResult(ok=False, stage="export",
                           message=f"exporter wrote nothing to {output_path}")
    return StageResult(ok=True, stage="export", output=str(output_path),
                       details={"types": types_written})


def _write_types_beside(export_path) -> int:
    """Writes the type sidecar next to a .BinExport just written.

    Best effort. An export that succeeded is worth keeping even if the type
    API on this build is not what this expects -- types are an extra, and
    failing the export over them would trade the thing the caller asked for
    against the thing they did not.
    """
    import json

    try:
        from bindiff.typeinfo import to_json, types_path_for
        from bindiff.typeinfo_ida import read_types

        declarations, functions = read_types()
        if not declarations and not functions:
            return 0
        Path(types_path_for(export_path)).write_text(
            json.dumps(to_json(declarations, functions,
                               source=str(export_path)), indent=1),
            encoding="utf-8")
        return len(declarations)
    except Exception:
        return 0


def try_import(primary_database: str, result_path: str,
               limit: Optional[int] = None,
               save: bool = False) -> StageResult:
    """Runs the importers against a real database, headlessly.

    Opens the primary with idalib and applies names, comments and prototypes
    for the first `limit` matches, then reports what happened. Nothing is
    saved unless asked: the database is opened from a copy and closed without
    writing, so this can be run against a database somebody has open.

    This exists because the import path could only be exercised by clicking.
    Every bug in it so far -- a list handed to set_cmt, a comment that was the
    function's own name, an action that dispatched nothing -- was found by a
    person using it, and each would have shown up here in seconds.
    """
    import idapro

    source = Path(primary_database)
    if not source.exists():
        return StageResult(ok=False, stage="import",
                           message=f"no such database: {primary_database}")

    holder = tempfile.mkdtemp(prefix="bindiff-import-")
    working = str(Path(holder) / source.name)
    try:
        shutil.copyfile(source, working)
        for companion in source.parent.glob(f"{source.stem}.*"):
            if companion != source and companion.is_file():
                shutil.copyfile(companion, str(Path(holder) / companion.name))
    except OSError as exc:
        shutil.rmtree(holder, ignore_errors=True)
        return StageResult(ok=False, stage="import",
                           message=f"could not copy the database: {exc}")

    if idapro.open_database(working, True) != 0:
        shutil.rmtree(holder, ignore_errors=True)
        return StageResult(ok=False, stage="import",
                           message=f"could not open {primary_database}")

    try:
        details = _run_import(result_path, limit)
    except Exception as exc:
        idapro.close_database(False)
        shutil.rmtree(holder, ignore_errors=True)
        return StageResult(ok=False, stage="import", message=str(exc))

    idapro.close_database(bool(save))
    shutil.rmtree(holder, ignore_errors=True)
    return StageResult(
        ok=True, stage="import",
        message=(f"{details['renamed']}/{details['renames_planned']} renamed, "
                 f"{details['comments']} comment(s), "
                 f"{details['prototypes']} prototype(s)"),
        details=details)


def _run_import(result_path: str, limit: Optional[int]) -> dict:
    """The import itself, with a database already open."""
    import json

    from bindiff.comments import portable_comments
    from bindiff.database import BinDiffDatabase
    from bindiff.binexport import find_binexports_for
    from bindiff.typeinfo import from_json, plan_types, types_path_for
    from bindiff.typeinfo_ida import (apply_prototype, existing_type_names,
                                      parse_declarations)
    from ida_plugin.porting import (apply_comment_ports, apply_symbol_ports,
                                    plan_comment_ports, plan_symbol_ports)

    database = BinDiffDatabase.open(result_path, read_only=True)
    try:
        matches = database.matches()
        if limit:
            matches = matches[:limit]
        ids = [m.id for m in matches]

        symbols = plan_symbol_ports(matches, overwrite_existing=True)
        symbol_result = apply_symbol_ports(symbols)
        renamed, rename_failures = symbol_result.applied, symbol_result.failed

        _primary, secondary = find_binexports_for(result_path)
        comments = 0
        if secondary:
            ports = plan_comment_ports(database, portable_comments(secondary),
                                       match_ids=ids)
            comments = apply_comment_ports(ports).applied

        prototypes = defined = 0
        sidecar = types_path_for(secondary) if secondary else None
        if sidecar and Path(sidecar).is_file():
            declarations, functions = from_json(
                json.loads(Path(sidecar).read_text(encoding="utf-8")))
            by_address = {f.address: f for f in functions}
            needed, ports = [], []
            for match in matches:
                source = by_address.get(match.address_secondary)
                if source is None:
                    continue
                needed.append(source)
                ports.append((match.address_primary, source.declaration))
            plan = plan_types(declarations, needed,
                              already_present=existing_type_names())
            if plan.statements:
                defined, _failed = parse_declarations(plan.statements)
            prototypes = sum(1 for address, declaration in ports
                             if apply_prototype(address, declaration))

        # Planned against applied, because they disagreed and nothing said
        # so: 3 renames planned, 0 applied, reported as "0 renamed".
        return {"matches": len(matches),
                "renames_planned": len(symbols), "renamed": renamed,
                "renames_failed": rename_failures,
                "comments": comments, "prototypes": prototypes,
                "types_defined": defined,
                "secondary_export": secondary or "",
                "types_sidecar": sidecar if sidecar and
                Path(sidecar).is_file() else ""}
    finally:
        database.close()


def diff(primary: str, secondary: str, output: str,
         progress: Optional[Callable[[dict], None]] = None,
         should_continue: Optional[Callable[[], bool]] = None) -> StageResult:
    """Diffs two .BinExport files. Needs no IDA at all.

    `progress` is called with a record per matching step and per round of
    propagating matches through the call graph. The engine's step index only
    advances between steps, so during a long propagation the fraction holds
    still while the match count keeps climbing -- which is the honest picture.

    `should_continue` is asked at each of those points. Returning False stops
    the diff, and the result is still written and still reported: the steps run
    strongest first, so what a cancelled diff holds is the matches worth
    having. It comes back ok, marked `details["cancelled"]`, because a partial
    .BinDiff is a usable .BinDiff -- callers that must know it is short have
    the flag, and callers that just want the matches need not care.
    """
    import bindiff

    # Set only when the engine was actually told to stop. Asking after the
    # diff has returned would be a different question with a different answer:
    # a request arriving as the last step finishes cancels nothing, and a
    # result that lost no matches must not be labelled as if it had.
    stopped = False

    def engine_progress(update: dict):
        nonlocal stopped
        count = update.get("step_count") or 0
        index = update.get("step_index")
        if progress is not None:
            progress(_record(
                "diff", update.get("step_name", ""),
                # Work finished *before* this step, so the bar never claims a
                # step is done while it is running. 100% is shown when the
                # result arrives, not before.
                fraction=(index / count) if count and index is not None
                else None,
                step_index=index, step_count=update.get("step_count"),
                matches=update.get("matches")))
        # Only an explicit False cancels, so returning None here -- when the
        # caller asked for no cancellation -- keeps the diff running.
        if should_continue is None or should_continue():
            return None
        stopped = True
        return False

    needs_callback = progress is not None or should_continue is not None
    code = bindiff.diff(str(primary), str(secondary), str(output),
                        progress=engine_progress if needs_callback else None)
    if code != 0:
        return StageResult(ok=False, stage="diff",
                           message=f"diff failed with {code}",
                           details={"code": code})

    cancelled = stopped
    return StageResult(
        ok=True, stage="diff", output=str(output),
        message="cancelled; results are partial" if cancelled else "",
        matches=len(bindiff.load_matches(str(output))),
        details={"cancelled": True} if cancelled else {})


def pipeline(primary_input: str, secondary_input: str, output: str,
             work_dir: Optional[str] = None,
             exporter: Optional[Callable[[str], None]] = None,
             progress: Optional[Callable[[dict], None]] = None,
             should_continue: Optional[Callable[[], bool]] = None
             ) -> StageResult:
    """Exports both inputs and diffs them.

    Each export opens and closes its own database in turn, in this one process.
    They are not parallelised here: idalib holds one database at a time, so
    overlapping them means more worker processes, which is the launcher's
    decision to make, not this function's.

    An export reports only that it has started. There is no progress to be had
    from inside one: idalib's auto-analysis does not call back, and inventing a
    fraction for it would be a lie told to a progress bar. For the same reason
    a cancellation is only noticed between exports -- there is nothing partial
    to keep from a half-finished one, so nothing is lost by that.
    """
    work = Path(work_dir) if work_dir else Path(output).parent
    work.mkdir(parents=True, exist_ok=True)

    def cancelled() -> bool:
        return should_continue is not None and not should_continue()

    sources = (("primary", primary_input), ("secondary", secondary_input))
    exports = []
    for index, (label, source) in enumerate(sources):
        if cancelled():
            return StageResult(ok=False, stage="export",
                               message="cancelled before the export finished",
                               details={"cancelled": True})
        if progress is not None:
            progress(_record("export", f"exporting {label}: {Path(source).name}",
                             fraction=_EXPORT_SHARE * index / len(sources),
                             step_index=index, step_count=len(sources)))
        # Already an export: nothing to disassemble. Re-exporting one would
        # mean opening a .BinExport as a database, which is not a thing, and
        # a user who has just spent a minute exporting by hand should not be
        # made to wait through it again.
        if Path(source).suffix.lower() == ".binexport":
            exports.append(str(source))
            continue

        target = work / f"{Path(source).stem}.{label}.BinExport"
        result = export(source, str(target), exporter=exporter)
        if not result.ok:
            result.details["input"] = source
            return result
        exports.append(str(target))

    if cancelled():
        return StageResult(ok=False, stage="export",
                           message="cancelled before the diff started",
                           details={"cancelled": True, "exports": exports})

    def diff_progress(record: dict) -> None:
        progress(_rescale(record, _EXPORT_SHARE, 1.0 - _EXPORT_SHARE))

    result = diff(exports[0], exports[1], output,
                  progress=diff_progress if progress else None,
                  should_continue=should_continue)
    result.details["exports"] = exports
    return result


# --------------------------------------------------------------------------
# Launcher side. Runs inside the GUI.
# --------------------------------------------------------------------------

def interpreter_candidates(prefix=None, windows: Optional[bool] = None
                           ) -> List[Path]:
    """Where an interpreter sits relative to sys.prefix, on this platform.

    Windows has no `bin/` and no extensionless executables: a base install puts
    python.exe directly in the prefix and a virtual environment puts it under
    Scripts. A launcher that only tried the POSIX layout found none of them and
    fell through to "no Python interpreter found" with a perfectly good
    interpreter sitting next to it.

    Split out from the search below, and taking the platform as an argument
    rather than reading os.name, so the layouts can be checked from anywhere --
    which is the only way this gets tested at all, since the plugin's own tests
    run on Linux. Monkeypatching os.name instead is not an option: pathlib
    reads it to choose between PosixPath and WindowsPath, so faking it globally
    breaks every path in the process, including the test runner's own.
    """
    prefix = Path(sys.prefix if prefix is None else prefix)
    major, minor = sys.version_info.major, sys.version_info.minor
    if windows is None:
        windows = os.name == "nt"

    if windows:
        return [
            prefix / "python.exe",
            prefix / "Scripts" / "python.exe",
            prefix / f"python{major}{minor}.exe",
            prefix / f"python{major}.exe",
        ]
    return [
        prefix / "bin" / f"python{major}.{minor}",
        prefix / "bin" / "python3",
        prefix / "bin" / "python",
    ]


def find_python_interpreter() -> Path:
    """Locates a real Python interpreter to run a worker with.

    sys.executable is *not* it inside IDA: there it points at the ida binary,
    and re-running that would start another IDA rather than a worker.
    sys._base_executable is the underlying interpreter and is what IDA's
    embedded Python leaves behind. Approach taken from ida-taskr.

    The name check is what keeps IDA out: `ida`, `ida64` and `ida.exe` do not
    contain "python", and an interpreter does on every platform.
    """
    base = getattr(sys, "_base_executable", None)
    if base and "python" in Path(base).name.lower():
        return Path(base)

    # Then a python next to sys.prefix, then sys.executable if it actually
    # looks like an interpreter.
    for candidate in interpreter_candidates():
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


def _parse_line(line: str):
    """Classifies one line of worker stdout.

    Returns ("result", StageResult), ("progress", record) or (None, None) for
    IDA's chatter, which idalib writes freely.
    """
    line = line.strip()
    if not line.startswith("{"):
        return None, None
    try:
        data = json.loads(line)
    except ValueError:
        return None, None
    if isinstance(data, dict) and _PROGRESS_KEY in data:
        return "progress", data[_PROGRESS_KEY]
    try:
        return "result", StageResult.from_json(line)
    except (ValueError, KeyError):
        return None, None


def _wait_for_exit(process, grace: float) -> bool:
    """Polls for the worker to exit. True if it did within `grace`.

    Polled rather than Popen.wait(timeout=...) because the thread reading
    stdout reaps the same process, and two threads waiting on one child is a
    race worth simply not having.
    """
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return True
        time.sleep(0.1)
    return process.poll() is not None


def _ask_worker_to_stop(process, acknowledged: threading.Event) -> None:
    """Cancels the worker, keeping its partial result if it can produce one.

    Terminating would throw away every match already made. Asked instead, the
    worker stops the diff at its next callback, writes the smaller result it is
    already holding and reports it like any other -- the engine's
    cancel-to-partial, delivered across the process boundary by the same
    .BinDiff file and the same JSON line a complete run uses.

    It is killed only when it does not answer, which means it is inside an
    export: idalib does not call back during auto-analysis, so there is no
    callback to hear the request, and a half-finished export holds nothing
    worth keeping anyway.
    """
    try:
        process.stdin.write(_CANCEL_TOKEN + "\n")
        process.stdin.flush()
    except (OSError, ValueError, AttributeError):
        # No pipe to ask over. Nothing to negotiate with.
        if process.poll() is None:
            process.terminate()
        return

    if not acknowledged.wait(_CANCEL_ACK_TIMEOUT):
        if process.poll() is None:
            process.terminate()
        return

    if not _wait_for_exit(process, _CANCEL_GRACE) and process.poll() is None:
        process.terminate()


def worker_environment(base=None) -> dict:
    """The child's environment, with this package reachable.

    The worker is `python -m bindiff.headless`, and the interpreter it runs is
    IDA's -- which can import bindiff only because the plugin put the package
    directory on sys.path at load time. A subprocess inherits the environment,
    not sys.path, so the child looked for an installed bindiff, found none, and
    died with ModuleNotFoundError before it could report anything.

    Prepended rather than replacing PYTHONPATH: a caller who set one meant it.
    Harmless when bindiff is properly installed in the child, which is the case
    for a wheel install -- the path is simply already satisfied.
    """
    environment = dict(os.environ if base is None else base)
    package_root = str(Path(__file__).resolve().parents[1])
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        package_root + os.pathsep + existing if existing else package_root)
    return environment


def _stream(command: List[str], timeout: Optional[float], sink: _ProgressSink,
            cancel: Optional[threading.Event]) -> StageResult:
    """Runs the worker, reading its output as it arrives."""
    process = subprocess.Popen(
        command, env=worker_environment(), stdout=subprocess.PIPE,
        # Merged rather than piped separately and read afterwards: a worker
        # that fills the stderr pipe while this is still reading stdout would
        # deadlock, and idalib is easily chatty enough to do it. Lines are
        # filtered by shape, so mixing the two streams costs nothing.
        stderr=subprocess.STDOUT,
        # Only opened when it can be used: an unread pipe on a worker that was
        # not told to listen is just a handle to leak.
        stdin=subprocess.PIPE if cancel is not None else None,
        text=True, bufsize=1)

    # Both of these have to act from another thread: this one spends the run
    # blocked in readline, and the worker ending is what unblocks it.
    timed_out = threading.Event()
    acknowledged = threading.Event()

    def on_timeout() -> None:
        timed_out.set()
        process.kill()

    def on_cancel() -> None:
        # Polled rather than a plain wait() so this thread ends with the worker
        # instead of outliving every diff that was never cancelled.
        while process.poll() is None:
            if cancel.wait(0.2):
                _ask_worker_to_stop(process, acknowledged)
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
            kind, payload = _parse_line(line)
            if kind == "result":
                result = payload
            elif kind == "progress":
                if payload.get("stage") == _CANCELLING_STAGE:
                    acknowledged.set()
                sink(payload)
            else:
                tail.append(line.rstrip())
        process.wait()
    finally:
        for watcher in watchers:
            if isinstance(watcher, threading.Timer):
                watcher.cancel()
        process.stdout.close()
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass

    if timed_out.is_set():
        return StageResult(ok=False, stage="worker",
                           message=f"worker timed out after {timeout:g}s")
    if result is not None:
        # Left exactly as the worker reported it. Asking to cancel is not the
        # same as having cancelled anything: a short diff can finish between
        # the request and the next callback, and marking that result partial
        # would send the reader looking for matches that are not missing.
        return result
    if cancel is not None and cancel.is_set():
        # Only reached when the worker never answered and had to be killed --
        # during an export, or wedged.
        return StageResult(ok=False, stage="worker",
                           message="cancelled before the worker reported",
                           details={"cancelled": True})
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

    `cancel` is an event that stops the worker when set. It asks rather than
    kills: a cancelled diff still writes the matches it had made, and comes
    back as an ordinary result marked `details["cancelled"]`. Only a worker
    that does not answer -- which means it is inside an export -- is
    terminated, and then there is nothing partial to lose.

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
    command = [str(interpreter), "-m", "bindiff.headless"]
    if cancel is not None:
        # Passed only when cancellation is actually possible, so a worker run
        # any other way leaves stdin alone.
        command.append(_CANCEL_FLAG)
    command += list(args)
    sink = _ProgressSink(on_progress)

    if runner is None:
        result = _stream(command, timeout, sink, cancel)
    else:
        completed = runner(command, capture_output=True, text=True,
                           timeout=timeout, env=worker_environment())
        result = None
        for line in (completed.stdout or "").splitlines():
            kind, payload = _parse_line(line)
            if kind == "result":
                result = payload
            elif kind == "progress":
                sink(payload)
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
    """Worker entry point.

    `python -m bindiff.headless [--cancel-on-stdin] <command> ...`

    The flag is passed only by a launcher that opened a pipe to write on, so
    stdin is left alone when the worker is run by hand in a terminal.
    """
    argv = list(sys.argv[1:] if argv is None else argv)

    should_continue = None
    if argv and argv[0] == _CANCEL_FLAG:
        argv = argv[1:]
        stop = threading.Event()
        watch_stdin_for_cancel(stop)
        should_continue = lambda: not stop.is_set()  # noqa: E731

    if not argv:
        print(StageResult(ok=False, stage="cli",
                          message="usage: export|diff|types|import|pipeline ...").to_json())
        return 2

    command, rest = argv[0], argv[1:]
    try:
        if command == "export" and len(rest) == 2:
            result = export(rest[0], rest[1])
        elif command == "diff" and len(rest) == 3:
            result = diff(rest[0], rest[1], rest[2], progress=emit_progress,
                          should_continue=should_continue)
        elif command == "import" and len(rest) >= 2:
            result = try_import(rest[0], rest[1],
                                limit=int(rest[2]) if len(rest) > 2 else None)
        elif command == "types" and len(rest) == 2:
            result = dump_types(rest[0], rest[1])
        elif command == "pipeline" and len(rest) == 3:
            result = pipeline(rest[0], rest[1], rest[2],
                              progress=emit_progress,
                              should_continue=should_continue)
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
