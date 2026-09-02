"""The single place that reaches into IDA.

Two rules it exists to hold, both of which are fatal rather than raising if
broken, and so cannot be discovered by trying:

  * `idaapi` does `from ida_ida import *`, and `ida_ida` evaluates database
    state at import time. With no database open that is INTERR 3123, which
    asks you to restart IDA.
  * in an idalib process `idapro` must be imported first -- it loads libida
    with global symbols before `ida_pro` imports `_ida_pro`. Going the other
    way is "Fatal error before kernel init" on 9.1. 9.4 tolerates it, so a
    9.4-only run does not show the bug.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bindiff import ida


@pytest.fixture
def no_kernel(monkeypatch):
    """A process that has established neither kernel.

    Set explicitly rather than assumed: other tests in this suite stub IDA
    modules into sys.modules, and a test that reads ambient process state
    passes alone and fails in the full run -- which is what this one did.
    """
    monkeypatch.delitem(sys.modules, "ida_kernwin", raising=False)
    monkeypatch.delitem(sys.modules, "idapro", raising=False)
    monkeypatch.setattr(ida, "_api", None)


class TestItRefusesBeforeAKernel:
    def test_api_raises_rather_than_importing(self, no_kernel):
        """The whole point: an import here would take the process down, so
        the state is checked instead of attempted."""
        with pytest.raises(ida.Unavailable, match="kernel is not up"):
            ida.api()

    def test_the_message_says_what_to_do(self, no_kernel):
        with pytest.raises(ida.Unavailable, match="import idapro"):
            ida.api()

    def test_module_is_guarded_the_same_way(self, no_kernel):
        """Reaching past the facade is still a call into this module, so it
        gets the same protection."""
        with pytest.raises(ida.Unavailable, match="kernel is not up"):
            ida.module("ida_frame")

    def test_a_worker_that_imported_idapro_is_allowed_through(self, no_kernel, monkeypatch):
        """Not that the import succeeds here -- only that the guard stops
        being the thing in the way."""
        monkeypatch.setitem(sys.modules, "idapro", object())
        with pytest.raises(ida.Unavailable, match="not importable"):
            ida.module("ida_frame_that_does_not_exist")

    def test_the_gui_is_allowed_through(self, no_kernel, monkeypatch):
        monkeypatch.setitem(sys.modules, "ida_kernwin", object())
        with pytest.raises(ida.Unavailable, match="not importable"):
            ida.module("ida_frame_that_does_not_exist")


class TestTheQuietAccessors:
    """Callers that ask "is this available" must never be the thing that
    brings the process down, so these swallow the refusal."""

    def test_available_is_false_rather_than_raising(self, no_kernel):
        assert ida.available("get_func_frame") is False

    def test_decompiler_is_none_rather_than_raising(self, no_kernel):
        assert ida.decompiler() is None


class TestSpellingChoice:
    def test_first_available_prefers_the_earlier_name(self, monkeypatch):
        class Facade:
            old_name = "old"
            new_name = "new"

        monkeypatch.setattr(ida, "_api", Facade)
        assert ida.first_available("old_name", "new_name") == "old"

    def test_it_falls_through_to_a_later_one(self, monkeypatch):
        class Facade:
            new_name = "new"

        monkeypatch.setattr(ida, "_api", Facade)
        assert ida.first_available("old_name", "new_name") == "new"

    def test_none_of_them_names_all_the_spellings_tried(self, monkeypatch):
        class Facade:
            pass

        monkeypatch.setattr(ida, "_api", Facade)
        with pytest.raises(ida.Unavailable, match="old_name, new_name"):
            ida.first_available("old_name", "new_name")


class TestEntryPointsBackport:
    """9.4 deprecates getn_func for get_func_ea_by_num, which 9.1 does not
    have at all. The caller asks for entry points and does not learn which
    spelling answered."""

    class _New:
        BADADDR = 0xFFFFFFFFFFFFFFFF

        @staticmethod
        def get_func_qty():
            return 3

        @staticmethod
        def get_func_ea_by_num(index):
            return [0x1000, 0x2000, 0xFFFFFFFFFFFFFFFF][index]

    class _Old:
        BADADDR = 0xFFFFFFFFFFFFFFFF

        @staticmethod
        def get_func_qty():
            return 3

        @staticmethod
        def getn_func(index):
            from types import SimpleNamespace
            return [SimpleNamespace(start_ea=0x1000),
                    SimpleNamespace(start_ea=0x2000), None][index]

    def test_the_new_spelling_is_used_where_it_exists(self, monkeypatch):
        monkeypatch.setattr(ida, "_api", self._New)
        assert ida.entry_points() == [0x1000, 0x2000]

    def test_the_old_one_answers_where_it_does_not(self, monkeypatch):
        monkeypatch.setattr(ida, "_api", self._Old)
        assert ida.entry_points() == [0x1000, 0x2000]

    def test_both_agree(self, monkeypatch):
        monkeypatch.setattr(ida, "_api", self._New)
        new = ida.entry_points()
        monkeypatch.setattr(ida, "_api", self._Old)
        assert ida.entry_points() == new

    def test_a_limit_is_respected(self, monkeypatch):
        monkeypatch.setattr(ida, "_api", self._New)
        assert ida.entry_points(limit=1) == [0x1000]
