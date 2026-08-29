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

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence

__all__ = [
    "StageResult",
    "export",
    "diff",
    "pipeline",
    "find_python_interpreter",
    "run_headless",
    "main",
]


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


def diff(primary: str, secondary: str, output: str) -> StageResult:
    """Diffs two .BinExport files. Needs no IDA at all."""
    import bindiff

    code = bindiff.diff(str(primary), str(secondary), str(output))
    if code != 0:
        return StageResult(ok=False, stage="diff",
                           message=f"diff failed with {code}",
                           details={"code": code})
    return StageResult(ok=True, stage="diff", output=str(output),
                       matches=len(bindiff.load_matches(str(output))))


def pipeline(primary_input: str, secondary_input: str, output: str,
             work_dir: Optional[str] = None,
             exporter: Optional[Callable[[str], None]] = None) -> StageResult:
    """Exports both inputs and diffs them.

    Each export opens and closes its own database in turn, in this one process.
    They are not parallelised here: idalib holds one database at a time, so
    overlapping them means more worker processes, which is the launcher's
    decision to make, not this function's.
    """
    work = Path(work_dir) if work_dir else Path(output).parent
    work.mkdir(parents=True, exist_ok=True)

    exports = []
    for label, source in (("primary", primary_input),
                          ("secondary", secondary_input)):
        target = work / f"{Path(source).stem}.{label}.BinExport"
        result = export(source, str(target), exporter=exporter)
        if not result.ok:
            result.details["input"] = source
            return result
        exports.append(str(target))

    result = diff(exports[0], exports[1], output)
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


def run_headless(args: Sequence[str], *,
                 interpreter: Optional[Path] = None,
                 timeout: Optional[float] = None,
                 runner: Optional[Callable] = None) -> StageResult:
    """Runs one worker command and returns its result.

    Blocking. In the GUI, call it from a worker thread or a QProcess -- this is
    the piece that must not sit on the UI thread, which is the whole reason the
    work is out of process.

    `runner` is injectable so the command construction and result parsing can
    be tested without spawning anything.
    """
    if interpreter is None:
        interpreter = find_python_interpreter()
    command = [str(interpreter), "-m", "bindiff.headless", *args]

    if runner is None:
        runner = subprocess.run
    completed = runner(command, capture_output=True, text=True, timeout=timeout)

    # The worker prints one JSON object as its last line of stdout. Anything
    # before it is IDA's own chatter, which idalib writes freely.
    for line in reversed((completed.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return StageResult.from_json(line)
            except (ValueError, KeyError):
                continue

    return StageResult(
        ok=False, stage="worker",
        message=(f"worker produced no result (exit {completed.returncode}): "
                 f"{(completed.stderr or '').strip()[:500]}"))


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
            result = diff(rest[0], rest[1], rest[2])
        elif command == "pipeline" and len(rest) == 3:
            result = pipeline(rest[0], rest[1], rest[2])
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
