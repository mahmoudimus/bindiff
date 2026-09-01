"""DiffSession: the one object that knows what is going on.

Five of the six defects in the design brief were the same failure -- a fact
with no owner, inferred or cached or delegated to IDA, surfacing somewhere
that did not know it. Every fact the interface shows is owned here: what is
open, what state it is in, what is selected, what a port did, whether an
action is possible right now. Views subscribe, render, and call methods.

Signals are plain callback lists, synchronous, on the thread that emits.
The session lives on the UI thread. The worker's progress records reach it
through diff_runner.DiffRun, which posts each one with execute_sync; that
is the only thread boundary in the plugin and it is not here.

No Qt and no IDA.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from ida_plugin.porting import PortLedger
from ida_plugin.ui_logic import (STATE_PORTED, STATE_REPLACED, DiffProgress,
                                 MatchRow, rows_from_database)


class State(str, Enum):
    IDLE = "idle"
    COMPARING = "comparing"
    OPEN_CLEAN = "open"
    OPEN_EDITED = "edited"
    OPEN_PARTIAL = "partial"


OPEN_STATES = (State.OPEN_CLEAN, State.OPEN_EDITED, State.OPEN_PARTIAL)

COMPARE = "compare"
CANCEL = "cancel"
SAVE = "save"
CLOSE = "close"
UNMATCH = "unmatch"
VERIFY = "verify"
PORT = "port"
PAIR = "pair"
GRAPHS = "graphs"
INSPECT = "inspect"
CONFIGURE = "configure"
LOCATE_EXPORT = "locate_export"
COPY = "copy"
RESTORE_NAME = "restore_name"


class Signal:
    """A callback list. A handler that raises is not swallowed: a view bug
    that vanished into a signal would be the old silence in a new place."""

    def __init__(self) -> None:
        self._handlers: List[Callable] = []

    def connect(self, handler: Callable) -> None:
        self._handlers.append(handler)

    def disconnect(self, handler: Callable) -> None:
        self._handlers = [h for h in self._handlers if h != handler]

    def emit(self, *args) -> None:
        # Over a copy: a handler is allowed to disconnect itself, and a view
        # closing in response to result_closed does exactly that.
        for handler in list(self._handlers):
            handler(*args)


@dataclass(frozen=True)
class ResultMeta:
    """What is open, in the words the title bar and the status line use."""

    path: str
    this_name: str
    other_name: str
    matched: int
    only_here: Optional[int]
    only_there: Optional[int]
    partial: bool

    def describe(self, edits: int) -> str:
        """The one-line summary. A count nobody can know is left out rather
        than shown as zero: without that side's .BinExport the number of
        functions only in it is unknown, and "0 only there" is a claim."""
        parts = [f"{self.this_name} ↔ {self.other_name}",
                 f"{self.matched:,} matched"]
        if self.only_here is not None:
            parts.append(f"{self.only_here:,} only here")
        if self.only_there is not None:
            parts.append(f"{self.only_there:,} only there")
        if self.partial:
            parts.append("partial")
        if edits:
            parts.append(f"{edits:,} unsaved edit{'s' if edits != 1 else ''}")
        return " · ".join(parts)


class DiffSession:
    """Owns the open result and everything the views ask about it."""

    def __init__(self, controller) -> None:
        self._controller = controller
        self.state = State.IDLE
        self.meta: Optional[ResultMeta] = None
        self.edits = 0
        self.selected_ids: Tuple[int, ...] = ()
        self.ledger = PortLedger()
        self.by_hand: Set[int] = set()
        self.chosen_unmatched: Dict[int, Optional[int]] = {0: None, 1: None}
        self.compare_started = 0.0
        self.last_progress: Optional[DiffProgress] = None
        self._before_compare = State.IDLE
        self._rows: Optional[List[MatchRow]] = None

        self.state_changed = Signal()
        self.progress = Signal()
        self.result_opened = Signal()
        self.result_closed = Signal()
        self.matches_changed = Signal()
        self.dirty_changed = Signal()
        self.selection_changed = Signal()
        self.ported = Signal()

    @property
    def controller(self):
        return self._controller

    # -- state ---------------------------------------------------------------

    def _set_state(self, state: State) -> None:
        if state is self.state:
            return
        self.state = state
        self.state_changed.emit(state)

    @property
    def is_open(self) -> bool:
        return self.state in OPEN_STATES

    def _rest_state(self) -> State:
        """Where an open result settles when it has no edits."""
        return State.OPEN_PARTIAL if self.meta and self.meta.partial else State.OPEN_CLEAN

    # -- results -------------------------------------------------------------

    def open_result(self, path: str, exports=None, *,
                    partial: bool = False) -> ResultMeta:
        self._controller.open_database(path)
        if exports and len(exports) == 2:
            self._controller.set_binexports(exports[0], exports[1])
        self.edits = 0
        self.by_hand = set()
        # A fresh ledger, not a cleared one: what a previous result's port did
        # says nothing about this one's rows, and the ids collide.
        self.ledger = PortLedger()
        self.selected_ids = ()
        self.chosen_unmatched = {0: None, 1: None}
        self._rows = None
        self.meta = self._build_meta(path, partial)
        self.result_opened.emit(self.meta)
        self.matches_changed.emit(())
        self.dirty_changed.emit(False, 0)
        self._set_state(self._rest_state())
        return self.meta

    def _build_meta(self, path: str, partial: bool) -> ResultMeta:
        database = self._controller.database
        files = database.files()
        names = [Path(f.filename).name if f.filename else "?" for f in files]
        while len(names) < 2:
            names.append("?")
        counts: List[Optional[int]] = []
        for side in (0, 1):
            try:
                counts.append(len(self.unmatched(side)))
            except FileNotFoundError:
                counts.append(None)
        return ResultMeta(path=path, this_name=names[0], other_name=names[1],
                          matched=database.num_matches(), only_here=counts[0],
                          only_there=counts[1], partial=partial)

    def _refresh_meta(self) -> None:
        if self.meta is not None:
            self.meta = self._build_meta(self.meta.path, self.meta.partial)

    def exports_located(self) -> None:
        """A .BinExport that was missing has been pointed at.

        Not open_result again: reopening clears the edits, the ledger and the
        selection, and naming a file the result always described is not a
        reason to forget what has been done to it. What changes is what can
        now be counted -- the unmatched lists -- so meta is rebuilt and the
        views are told to redraw from it.
        """
        if self.meta is None:
            return
        self._refresh_meta()
        self.result_opened.emit(self.meta)
        self.matches_changed.emit(())

    def close_result(self) -> None:
        self._controller.close()
        self.meta = None
        self._rows = None
        self.selected_ids = ()
        self.chosen_unmatched = {0: None, 1: None}
        self.result_closed.emit()
        self._set_state(State.IDLE)

    def rows(self) -> List[MatchRow]:
        """The table's rows, cached until something changes them.

        Guarded on `meta` rather than on the state, because a diff started
        over an open result leaves that result readable while it runs.
        """
        if self.meta is None:
            return []
        if self._rows is None:
            primary, secondary = self._controller.function_details()
            self._rows = rows_from_database(
                self._controller.database, primary, secondary,
                ledger=self.ledger, by_hand=self.by_hand,
                comment_counts=self._controller.comment_counts())
        return self._rows

    def row(self, match_id: int) -> Optional[MatchRow]:
        for row in self.rows():
            if row.match_id == match_id:
                return row
        return None

    def unmatched(self, side: int):
        """The functions only on one side. Raises FileNotFoundError when that
        side's .BinExport is missing -- the caller asks, rather than being
        handed an empty list that reads as "there are none"."""
        return (self._controller.unmatched_primary() if side == 0
                else self._controller.unmatched_secondary())

    def export_missing(self, side: int) -> bool:
        return not self._controller.export_available(side)

    def statistics(self):
        return self._controller.statistic_rows()

    # -- comparing -----------------------------------------------------------

    def begin_compare(self, title: str) -> None:
        self._before_compare = self.state
        self.compare_started = time.monotonic()
        self.last_progress = None
        self._set_state(State.COMPARING)

    def report_progress(self, progress: DiffProgress) -> None:
        self.last_progress = progress
        self.progress.emit(progress, time.monotonic() - self.compare_started)

    def finish_compare(self, outcome) -> None:
        if self.state is State.COMPARING:
            # Nothing was opened, so the diff failed or was cancelled during
            # an export: whatever was open before is still the truth.
            self._set_state(self._before_compare)

    # -- selection -----------------------------------------------------------

    @property
    def current_id(self) -> Optional[int]:
        """The one selected match, or None when that is not what is selected."""
        return self.selected_ids[0] if len(self.selected_ids) == 1 else None

    def set_selection(self, ids: Sequence[int]) -> None:
        """Records the selection, and announces the single row when it moves.

        selection_changed carries the one match a detail view can show, so it
        fires when *that* changes -- not on every reshuffle of a multi-row
        selection, which would tell the inspector to clear itself repeatedly
        while the user is still dragging. `selected_ids` is updated either
        way, and can() reads it directly.
        """
        ids = tuple(ids)
        if ids == self.selected_ids:
            return
        previous = self.current_id
        self.selected_ids = ids
        if self.current_id != previous:
            self.selection_changed.emit(self.current_id)

    def choose_unmatched(self, side: int, address: Optional[int]) -> None:
        self.chosen_unmatched[side] = address

    # -- edits ---------------------------------------------------------------

    def _edited(self, count: int, ids: Sequence[int]) -> None:
        if count <= 0:
            return
        self.edits += count
        self._rows = None
        self._refresh_meta()
        self.dirty_changed.emit(True, self.edits)
        self.matches_changed.emit(tuple(ids))
        self._set_state(State.OPEN_EDITED)

    def unmatch(self, ids: Sequence[int]) -> int:
        ids = list(ids)
        count = self._controller.delete_matches(ids)
        # Deselect what no longer exists before anyone redraws on it.
        self.set_selection(tuple(i for i in self.selected_ids if i not in ids))
        self._edited(count, ids)
        return count

    def verify(self, ids: Sequence[int]) -> int:
        ids = list(ids)
        count = self._controller.confirm_matches(ids)
        self._edited(count, ids)
        return count

    def pair(self, primary_address: int, secondary_address: int):
        new = self._controller.add_manual_match(primary_address,
                                                secondary_address)
        self.by_hand.add(new.id)
        self.chosen_unmatched = {0: None, 1: None}
        self._edited(1, [new.id])
        return new

    def note_ports(self, ledger_delta: PortLedger) -> None:
        """Folds what a port just did into the session's own ledger.

        The .BinDiff has one flag for this and the schema is not extended, so
        the per-row outcome lives here; the flag is set only for the rows
        something was actually written to, which is what "imported" means when
        the file is opened again.
        """
        ids: List[int] = []
        for entry in ledger_delta:
            self.ledger.record(entry)
            ids.append(entry.match_id)
        written = []
        for match_id in ids:
            entry = self.ledger.entry(match_id)
            if entry is None:
                continue
            if entry.outcome in (STATE_PORTED, STATE_REPLACED) or entry.comments_written:
                written.append(match_id)
        if written:
            self._controller.mark_imported(written)
        self.ported.emit(self.ledger)
        # Every entry is new information for the State column -- "skipped" as
        # much as "ported" -- so the rows are rebuilt and announced either
        # way. What counts as an *edit* is narrower: only what was written
        # into the result file. A port that wrote nothing and left "3 unsaved
        # edits" behind was a claim the .BinDiff did not support, and it lit
        # up Save over a file with nothing to save.
        self._rows = None
        if written:
            self._edited(len(written), ids)
        else:
            self.matches_changed.emit(tuple(ids))

    def forget_port(self, match_id: int) -> None:
        self.ledger.forget(match_id)
        self._edited(1, [match_id])

    def save(self) -> None:
        self._controller.save()
        self.edits = 0
        self.dirty_changed.emit(False, 0)
        self._set_state(self._rest_state())

    def revert(self) -> None:
        self._controller.revert()
        self.edits = 0
        self._rows = None
        self._refresh_meta()
        self.dirty_changed.emit(False, 0)
        self.matches_changed.emit(())
        self._set_state(self._rest_state())

    # -- availability --------------------------------------------------------

    def can(self, action: str) -> bool:
        """Whether an action makes sense right now. Evaluated on every ask,
        never cached: caching this is how three views spent a session
        greyed out."""
        one = len(self.selected_ids) == 1
        some = len(self.selected_ids) >= 1
        if action in (COMPARE, CONFIGURE):
            return self.state is not State.COMPARING
        if action == CANCEL:
            return self.state is State.COMPARING
        if action == SAVE:
            return self.state is State.OPEN_EDITED
        if action in (CLOSE, LOCATE_EXPORT):
            return self.is_open
        if action in (UNMATCH, VERIFY, PORT, COPY):
            return self.is_open and some
        if action in (GRAPHS, INSPECT):
            return self.is_open and one
        if action == PAIR:
            return self.is_open and all(
                value is not None for value in self.chosen_unmatched.values())
        if action == RESTORE_NAME:
            return (self.is_open and one
                    and self.ledger.reversal(self.selected_ids[0]) is not None)
        return False
