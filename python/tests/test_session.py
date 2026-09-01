"""The session owns every fact the interface shows. These drive it with a
fake controller and assert on the signals, because the views are dumb by
design and a test of them would be a test of Qt."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_plugin.diff_runner import DiffOutcome
from ida_plugin.porting import LedgerEntry, PortLedger
from ida_plugin.session import (
    CANCEL, CLOSE, COMPARE, GRAPHS, PAIR, PORT, RESTORE_NAME, SAVE, UNMATCH,
    DiffSession, ResultMeta, Signal, State)
from ida_plugin.ui_logic import STATE_PORTED, DiffProgress


class FakeMatch(SimpleNamespace):
    @property
    def manual(self):
        return self.confidence == 1.0 and "manual" in self.algorithm


def match(id, **over):
    fields = dict(id=id, address_primary=0x1000 * id, name_primary=f"sub_{id}",
                  address_secondary=0x2000 * id, name_secondary=f"f{id}",
                  similarity=0.9, confidence=0.9, flags=0,
                  algorithm="function: hash matching", comments_ported=False,
                  basic_blocks=1, edges=1, instructions=1)
    fields.update(over)
    return FakeMatch(**fields)


class FakeDatabase:
    def __init__(self, matches):
        self._matches = {m.id: m for m in matches}
        self.path = "/tmp/a_vs_b.BinDiff"
        self.committed = self.rolled_back = 0

    def matches(self):
        return sorted(self._matches.values(), key=lambda m: -m.similarity)

    def num_matches(self):
        return len(self._matches)

    def files(self):
        return [SimpleNamespace(filename="/x/a.BinExport", hash="", functions=10,
                                calls=0, basic_blocks=0, instructions=0, edges=0),
                SimpleNamespace(filename="/y/b.BinExport", hash="", functions=12,
                                calls=0, basic_blocks=0, instructions=0, edges=0)]


class FakeController:
    """Just enough of BinDiffController for the session to drive."""

    def __init__(self, matches, exports=(False, False)):
        self.database = FakeDatabase(matches)
        self.loaded = True
        self._exports = list(exports)
        self.closed = False
        self.imported = []

    def open_database(self, path, read_only=False):
        return self.database

    def close(self):
        self.closed = True

    def set_binexports(self, primary, secondary):
        self._exports = [primary is not None, secondary is not None]

    def export_available(self, side):
        return self._exports[side]

    def function_details(self):
        return ({}, {})

    def comment_counts(self):
        return {}

    def unmatched_primary(self):
        if not self._exports[0]:
            raise FileNotFoundError("no primary export")
        return ["p1", "p2"]

    def unmatched_secondary(self):
        if not self._exports[1]:
            raise FileNotFoundError("no secondary export")
        return ["s1"]

    def statistic_rows(self):
        return ["stat"]

    def delete_matches(self, ids):
        for i in ids:
            self.database._matches.pop(i)
        return len(ids)

    def confirm_matches(self, ids):
        for i in ids:
            m = self.database._matches[i]
            m.confidence, m.algorithm = 1.0, "function: manual"
        return len(ids)

    def add_manual_match(self, primary, secondary):
        new = match(max(self.database._matches) + 1, address_primary=primary,
                    address_secondary=secondary, confidence=1.0,
                    algorithm="function: manual")
        self.database._matches[new.id] = new
        return new

    def mark_imported(self, ids):
        self.imported.extend(ids)
        return len(ids)

    def save(self):
        self.database.committed += 1

    def revert(self):
        self.database.rolled_back += 1


class Recorder:
    def __init__(self, session):
        self.events = []
        for name in ("state_changed", "progress", "result_opened", "result_closed",
                     "matches_changed", "dirty_changed", "selection_changed", "ported"):
            getattr(session, name).connect(
                lambda *args, name=name: self.events.append((name, args)))

    def names(self):
        return [name for name, _ in self.events]


@pytest.fixture
def session():
    return DiffSession(FakeController([match(1), match(2), match(3, similarity=0.3)],
                                      exports=(True, False)))


class TestSignal:
    def test_connect_emit_disconnect(self):
        heard = []
        signal = Signal()
        signal.connect(heard.append)
        signal.emit(1)
        signal.disconnect(heard.append)
        signal.emit(2)
        assert heard == [1]

    def test_a_raising_handler_is_not_swallowed(self):
        signal = Signal()
        signal.connect(lambda: 1 / 0)
        with pytest.raises(ZeroDivisionError):
            signal.emit()


class TestOpening:
    def test_starts_idle_and_cannot_do_anything_with_a_result(self, session):
        assert session.state is State.IDLE
        assert session.can(COMPARE)
        assert not session.can(SAVE) and not session.can(CLOSE) and not session.can(UNMATCH)

    def test_open_enters_clean_and_describes_the_result(self, session):
        recorder = Recorder(session)
        meta = session.open_result("/tmp/a_vs_b.BinDiff")
        assert session.state is State.OPEN_CLEAN
        assert meta == ResultMeta(path="/tmp/a_vs_b.BinDiff", this_name="a.BinExport",
                                  other_name="b.BinExport", matched=3, only_here=2,
                                  only_there=None, partial=False)
        assert meta.describe(0) == "a.BinExport ↔ b.BinExport · 3 matched · 2 only here"
        assert meta.describe(3).endswith(" · 3 unsaved edits")
        assert recorder.names()[:3] == ["result_opened", "matches_changed", "dirty_changed"]
        assert "state_changed" in recorder.names()

    def test_a_cancelled_diff_opens_partial(self, session):
        session.open_result("/tmp/x.BinDiff", partial=True)
        assert session.state is State.OPEN_PARTIAL
        assert session.meta.partial

    def test_rows_carry_trust_and_are_cached(self, session):
        session.open_result("/tmp/x.BinDiff")
        first = session.rows()
        assert [r.trust for r in first] == ["strong", "strong", "weak"]
        assert session.rows() is first
        assert session.row(3).match_id == 3
        assert session.row(99) is None

    def test_missing_export_is_a_state_not_an_error(self, session):
        session.open_result("/tmp/x.BinDiff")
        assert session.export_missing(1) and not session.export_missing(0)
        assert session.unmatched(0) == ["p1", "p2"]
        with pytest.raises(FileNotFoundError):
            session.unmatched(1)

    def test_locating_an_export_updates_the_counts_without_losing_edits(self, session):
        session.open_result("/tmp/x.BinDiff")
        session.unmatch([1])
        session.controller.set_binexports("p", "s")
        session.exports_located()
        assert session.meta.only_there == 1
        assert session.edits == 1

    def test_close_returns_to_idle(self, session):
        session.open_result("/tmp/x.BinDiff")
        recorder = Recorder(session)
        session.close_result()
        assert session.state is State.IDLE and session.meta is None
        assert recorder.names() == ["result_closed", "state_changed"]


class TestEdits:
    def test_unmatch_counts_edits_and_invalidates_rows(self, session):
        session.open_result("/tmp/x.BinDiff")
        before = session.rows()
        recorder = Recorder(session)
        assert session.unmatch([2]) == 1
        assert session.state is State.OPEN_EDITED and session.edits == 1
        assert session.rows() is not before and len(session.rows()) == 2
        assert ("dirty_changed", (True, 1)) in recorder.events
        assert ("matches_changed", ((2,),)) in recorder.events

    def test_verify_and_pair_mark_by_hand_correctly(self, session):
        from ida_plugin.ui_logic import STATE_BY_HAND, STATE_VERIFIED
        session.open_result("/tmp/x.BinDiff")
        session.verify([1])
        new = session.pair(0x9000, 0xA000)
        rows = {r.match_id: r for r in session.rows()}
        assert rows[1].state == STATE_VERIFIED
        assert rows[new.id].state == STATE_BY_HAND
        assert session.edits == 2

    def test_save_and_revert_clear_dirty(self, session):
        session.open_result("/tmp/x.BinDiff")
        session.unmatch([1])
        session.save()
        assert session.state is State.OPEN_CLEAN and session.edits == 0
        session.unmatch([2])
        session.revert()
        assert session.edits == 0 and session.state is State.OPEN_CLEAN

    def test_save_from_partial_returns_to_partial(self, session):
        session.open_result("/tmp/x.BinDiff", partial=True)
        session.unmatch([1])
        session.save()
        assert session.state is State.OPEN_PARTIAL

    def test_ports_land_in_the_ledger_and_the_rows(self, session):
        session.open_result("/tmp/x.BinDiff")
        recorder = Recorder(session)
        delta = PortLedger()
        delta.record(LedgerEntry(1, STATE_PORTED, 0x1000, "sub_1", "f1"))
        session.note_ports(delta)
        assert session.row(1).state == STATE_PORTED
        assert session.ledger.outcome(1) == STATE_PORTED
        assert "ported" in recorder.names()
        assert session.edits == 1
        session.set_selection([1])
        assert session.can(RESTORE_NAME)
        session.forget_port(1)
        assert not session.can(RESTORE_NAME)


class TestSelectionAndCan:
    def test_selection_drives_availability(self, session):
        session.open_result("/tmp/x.BinDiff")
        recorder = Recorder(session)
        assert not session.can(UNMATCH) and not session.can(GRAPHS)
        session.set_selection([1, 2])
        assert session.can(UNMATCH) and session.can(PORT) and not session.can(GRAPHS)
        session.set_selection([2])
        assert session.can(GRAPHS)
        assert ("selection_changed", (None,)) not in recorder.events
        assert ("selection_changed", (2,)) in recorder.events
        session.set_selection([])
        assert ("selection_changed", (None,)) in recorder.events

    def test_pair_needs_one_on_each_side(self, session):
        session.open_result("/tmp/x.BinDiff")
        session.choose_unmatched(0, 0x1)
        assert not session.can(PAIR)
        session.choose_unmatched(1, 0x2)
        assert session.can(PAIR)

    def test_unknown_action_is_false(self, session):
        assert session.can("fly") is False


class TestComparing:
    def test_compare_blocks_compare_and_allows_cancel(self, session):
        session.open_result("/tmp/x.BinDiff")
        session.begin_compare("diffing a")
        assert session.state is State.COMPARING
        assert session.can(CANCEL) and not session.can(COMPARE) and not session.can(SAVE)

    def test_progress_is_relayed_with_elapsed(self, session):
        recorder = Recorder(session)
        session.begin_compare("diffing a")
        progress = DiffProgress(stage="diff", message="matching", fraction=0.5)
        session.report_progress(progress)
        name, args = [e for e in recorder.events if e[0] == "progress"][0]
        assert args[0] is progress and args[1] >= 0.0
        assert session.last_progress is progress

    def test_a_failed_compare_restores_the_previous_state(self, session):
        session.open_result("/tmp/x.BinDiff")
        session.unmatch([1])
        session.begin_compare("diffing a")
        session.finish_compare(DiffOutcome("failed", "failed: x", "", "x", False))
        assert session.state is State.OPEN_EDITED

    def test_a_finished_compare_that_opened_a_result_stays_open(self, session):
        session.begin_compare("diffing a")
        session.open_result("/tmp/new.BinDiff")
        session.finish_compare(DiffOutcome("complete", "3 matches", "", "", True))
        assert session.state is State.OPEN_CLEAN
