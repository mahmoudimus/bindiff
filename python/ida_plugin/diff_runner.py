"""Driving one out-of-process diff, without Qt and without IDA.

This is the sequence between "the user picked two files" and "the results are
on screen": start a worker, stream its progress into a panel, and decide what
to do with whatever comes back. It lived inside the plugin class, which meant
it only existed when IDA was present and could therefore only be checked by
running IDA -- and the pieces it wires together are all tested individually, so
what breaks is the wiring.

Everything that touches IDA or Qt is injected. The plugin supplies the real
ones; a test supplies fakes and asserts the order of what happened. Same split
as ui_logic.py, for the same reason.

The one rule this file exists to enforce: **nothing touches the UI from the
worker thread.** Every call that would is handed to `post`, which the plugin
implements with ida_kernwin.execute_sync.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from ida_plugin.ui_logic import DiffProgress


@dataclass(frozen=True)
class DiffOutcome:
    """What should happen once a diff has ended.

    Derived from the worker's result and nothing else, so the decision can be
    checked without a UI in the room.
    """

    status: str          # complete | partial | cancelled | failed
    panel_message: str   # shown on the progress panel, which stays open
    report: str          # for the output window; empty for none
    warning: str         # modal warning; empty for none
    open_result: bool    # whether the .BinDiff is worth loading

    @property
    def failed(self) -> bool:
        return self.status == "failed"


def classify(result) -> DiffOutcome:
    """Turns a worker StageResult into what the UI should do about it.

    A cancelled diff that produced a database is **not** a failure: the
    matching steps run strongest first, so what it holds is the matches worth
    having. It is opened like any other result and labelled so nobody reads it
    as the whole picture.

    A cancellation that arrived during an export has no result to open, and is
    not something to raise a warning about either -- the user asked for it.
    """
    cancelled = bool(result.details.get("cancelled"))

    if not result.ok:
        if cancelled:
            return DiffOutcome(status="cancelled", panel_message="cancelled",
                               report="diff cancelled", warning="",
                               open_result=False)
        return DiffOutcome(status="failed",
                           panel_message=f"failed: {result.message}",
                           report="",
                           warning=f"Diff failed:\n{result.message}",
                           open_result=False)

    label = "partial" if cancelled else "complete"
    return DiffOutcome(
        status=label,
        panel_message=f"{result.matches} matches ({label})",
        report=f"diff {label}: {result.matches} matches",
        warning="", open_result=True)


class DiffRun:
    """One diff, from worker launch to results on screen.

    `runner`   called with (args, on_progress, cancel); returns a StageResult.
    `panel`    something with update_progress(DiffProgress) and finish(str).
    `post_progress` runs a callable on the UI thread and waits for it. Used
               many times per diff, so the plugin posts it with MFF_FAST --
               repainting a label must not queue behind a database lock the
               user's own analysis is holding.
    `post_result`   the same, for the single call at the end. That one loads a
               file and opens windows, so the plugin posts it with MFF_WRITE.
    `report`   writes a line to the output window.
    `warn`     shows a modal warning.
    `load`     opens the finished .BinDiff and shows the matches. Called
               with the output path and the exports the worker used, so the
               caller need not guess where they were.
    """

    def __init__(self, *, runner: Callable, panel, post_progress: Callable,
                 post_result: Callable,
                 report: Callable[[str], None],
                 warn: Callable[[str], None],
                 load: Callable[..., None]) -> None:
        self._runner = runner
        self._panel = panel
        self._post_progress = post_progress
        self._post_result = post_result
        self._report = report
        self._warn = warn
        self._load = load

    def on_progress(self, record: dict) -> None:
        """Called on the worker thread, once per record the worker emits."""
        progress = DiffProgress.from_record(record)
        # Posted rather than applied here. Blocking until the UI thread has
        # drawn it also stops a fast worker queueing up more repaints than the
        # UI can keep up with.
        self._post_progress(
            lambda: self._panel.update_progress(progress))

    def execute(self, args: Sequence[str], output: str,
                cancel=None) -> DiffOutcome:
        """Runs the worker to completion. Blocking; call it off the UI thread.

        Returns the outcome so a caller can assert on it. The plugin ignores
        the return value -- everything it needs has already been posted.
        """
        result = self._runner(args, on_progress=self.on_progress,
                              cancel=cancel)
        outcome = classify(result)

        def finish() -> None:
            # The launcher keeps going when a progress handler raises, rather
            # than losing a finished diff to a drawing bug, and leaves the
            # reason on the result. Reporting it first means it is visible even
            # when the diff itself succeeded.
            broken = result.details.get("progress_error")
            if broken:
                self._report(f"progress reporting stopped: {broken}")

            self._panel.finish(outcome.panel_message)
            if outcome.open_result:
                # The worker knows where the exports were, and a .BinDiff does
                # not record them. Without this the plugin has to guess from
                # the result filename, which only works when the exports
                # happen to sit beside it -- and when the guess fails, comment
                # porting and the unmatched lists degrade with a message about
                # a file the user never named.
                self._load(output, tuple(result.details.get("exports") or ()))
            if outcome.report:
                self._report(outcome.report)
            if outcome.warning:
                self._warn(outcome.warning)

        self._post_result(finish)
        return outcome


def panel_title(primary: str) -> str:
    """Title for the progress panel: the file being diffed, not its path."""
    from pathlib import Path

    return f"BinDiff - diffing {Path(primary).name}"


def primary_export_source(idb_path, input_path):
    """Which file the worker should export for the primary side.

    The saved database, whenever there is one. Handing over the input binary
    instead makes the worker re-analyse it from scratch, which throws away
    everything the database holds that the bytes do not: renamed functions,
    applied types, and anything a deobfuscation pass rewrote. A diff of a
    deobfuscated database against a fresh disassembly of the same bytes
    compares two different programs, and does it silently -- the export
    succeeds, the diff succeeds, and the answer is about a binary nobody was
    looking at.

    The input binary is the fallback for a database that has never been saved,
    where there is nothing else to export.
    """
    if idb_path:
        candidate = Path(idb_path)
        if candidate.is_file():
            return str(candidate)
    return str(input_path) if input_path else None


def default_output_name(primary, secondary) -> str:
    """A .BinDiff filename built from the two sides.

    "Save results as" opened on whatever directory IDA was last in, with an
    empty name, so every diff had to be named by hand -- and the one thing the
    name should record, which two files it compares, is exactly what the user
    would have to retype.
    """
    def stem(path):
        name = Path(path).name
        # .dll.i64 and .BinExport both leave a stem worth keeping, so strip
        # only the last suffix rather than every one.
        return Path(name).stem if Path(name).suffix else name

    return f"{stem(primary)}_vs_{stem(secondary)}.BinDiff"


# The files this tool writes. Nothing here can be a side of a diff, and
# handing one over does not fail -- which is the problem. IDA loads anything
# as raw bytes, so a .BinDiff is disassembled as a flat blob of SQLite,
# exported, and diffed: a real run against a 10,000-match pair came back with
# 499 matches and no error, named "<primary>_vs_<primary>_vs_<secondary>".
#
# It is a refusal list rather than an allow list because a binary may carry
# any extension or none at all. Only the names this tool chose are knowable.
_OUR_OWN_OUTPUT = {
    ".bindiff": "a result file",
    ".results": "a diff log",
    ".truth": "a ground-truth file",
    ".meta": "a metadata sidecar",
}


def reject_reason(path) -> Optional[str]:
    """Why `path` cannot be a side of a diff, or None when it can be.

    Names the file, because the two fields sit next to each other and picking
    the result you just loaded instead of the binary it came from is an easy
    slip to make and an expensive one to diagnose.
    """
    what = _OUR_OWN_OUTPUT.get(Path(path).suffix.lower())
    if what is None:
        return None
    return f"{Path(path).name} is {what} this tool produced, not an input."


def worker_arguments(primary: str, secondary: str, output: str) -> list:
    """The command handed to the headless worker."""
    return ["pipeline", str(primary), str(secondary), str(output)]


# Long enough that a large pair is not cut off mid-diff, short enough that a
# wedged worker does not hold a thread for the life of the IDA session.
DEFAULT_TIMEOUT_SECONDS: Optional[float] = 3600.0
