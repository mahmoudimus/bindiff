"""Tests for the vendored Qt shim.

The shim is carried verbatim from d810 so fixes can move in either direction;
these check the properties this repository depends on rather than re-testing
d810's own behaviour. They run headless, where the shim installs stubs instead
of importing a Qt binding -- which is exactly the case that has to keep
working, since it is what lets panels.py and the plugin be imported in the test
harness.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from bindiff import qt_shim

SHIM_SOURCE = Path(qt_shim.__file__).read_text(encoding="utf-8")


def test_headless_does_not_import_a_qt_binding():
    """Nothing here runs in IDA's GUI, so no Qt binding should be pulled in."""
    assert qt_shim._is_ida_gui_available() is False
    assert qt_shim.QT_GRAPHICS_AVAILABLE is False


def test_gui_detection_follows_is_idaq(monkeypatch):
    """Detection reads an already-loaded ida_kernwin; it never imports one."""
    monkeypatch.setitem(sys.modules, "ida_kernwin",
                        types.SimpleNamespace(is_idaq=lambda: True))
    assert qt_shim._is_ida_gui_available() is True

    monkeypatch.setitem(sys.modules, "ida_kernwin",
                        types.SimpleNamespace(is_idaq=lambda: False))
    assert qt_shim._is_ida_gui_available() is False


def test_gui_detection_never_imports_ida(monkeypatch):
    """With ida_kernwin absent from sys.modules the answer is False, and no
    import is attempted -- probing is what breaks idalib on IDA 9.1."""
    monkeypatch.delitem(sys.modules, "ida_kernwin", raising=False)

    def explode(name, *args, **kwargs):
        if name.startswith("ida"):
            raise AssertionError(f"detection must not import {name}")
        return original_import(name, *args, **kwargs)

    import builtins

    original_import = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", explode)
    assert qt_shim._is_ida_gui_available() is False


def test_version_constants_are_consistent():
    """QT_VERSION and QT_BINDING always hold a usable value.

    Headless, no binding is imported and both QT5 and QT6 stay False -- the
    flags answer "which Qt is loaded", and the honest answer is neither. The
    version and binding names keep their defaults so callers reading them at
    import time do not have to special-case it.
    """
    assert qt_shim.QT_VERSION in (5, 6)
    assert qt_shim.QT_BINDING in ("PyQt5", "PySide6")

    if not qt_shim._QT_AVAILABLE:
        assert qt_shim.QT5 is False and qt_shim.QT6 is False
        return

    # With a binding loaded the two flags are mutually exclusive and agree
    # with QT_VERSION.
    assert qt_shim.QT5 != qt_shim.QT6
    assert (qt_shim.QT_VERSION == 5) == qt_shim.QT5


def test_both_bindings_are_attempted():
    """PySide6 first (IDA 9.2+), PyQt5 as the fallback (IDA 9.1)."""
    assert "from PySide6 import" in SHIM_SOURCE
    assert "from PyQt5 import" in SHIM_SOURCE
    assert SHIM_SOURCE.index("from PySide6 import") < SHIM_SOURCE.index(
        "from PyQt5 import"), "PySide6 should be preferred over PyQt5"


def test_provenance_is_recorded():
    """AGPL-3.0 in origin, Apache-2.0 here: the note explaining why the copy is
    allowed must survive edits to this file."""
    assert "Vendored from d810" in SHIM_SOURCE
    assert "AGPL-3.0" in SHIM_SOURCE
    assert "explicit permission" in SHIM_SOURCE


@pytest.mark.parametrize("name", [
    "QtCore", "QtGui", "QtWidgets", "Qt",
    "QT5", "QT6", "QT_VERSION", "QT_BINDING",
])
def test_public_names_exist_headless(name):
    """panels.py imports these at module scope; they must resolve even when no
    Qt binding is installed."""
    assert hasattr(qt_shim, name), f"qt_shim.{name} is missing"


def test_ui_logic_imports_without_qt():
    """The logic layer must not drag Qt in -- that is what makes it testable."""
    import ida_plugin.ui_logic as ui_logic

    source = Path(ui_logic.__file__).read_text(encoding="utf-8")
    for forbidden in ("qt_shim", "QtWidgets", "PyQt5", "PySide6", "ida_kernwin"):
        assert forbidden not in source, (
            f"ui_logic.py should not reference {forbidden}")


def test_qt_modules_import_headless():
    """panels.py and the plugin must import with no Qt and no IDA.

    This is what lets the logic be tested in the harness at all, and it is easy
    to break by moving an import to module scope. Both guard on Exception
    rather than ImportError because IDA's own modules can raise RuntimeError
    from the kernel when no database is open.
    """
    import ida_plugin.bindiff_plugin as plugin
    import ida_plugin.panels as panels

    assert panels.IDA_AVAILABLE is False
    assert plugin.IDA_AVAILABLE is False
    # The controller is deliberately Qt-free, so it is usable here.
    assert plugin.BinDiffController().loaded is False


def test_plugin_loads_the_way_ida_loads_it(tmp_path):
    """IDA runs the entry point as a top-level script, not as a package member.

    Importing it as `ida_plugin.bindiff_plugin`, which every other test does,
    gives it a parent package and hides any relative import. Loading it by file
    path is what IDA actually does, and is the only way to catch that.
    """
    import importlib.util
    from pathlib import Path

    entry_point = Path(__file__).resolve().parents[1] / "ida_plugin" / "bindiff_plugin.py"
    assert entry_point.is_file()

    spec = importlib.util.spec_from_file_location("bindiff_plugin_standalone",
                                                  entry_point)
    module = importlib.util.module_from_spec(spec)
    # __package__ is empty here, exactly as under IDA.
    spec.loader.exec_module(module)

    assert module.PLUGIN_NAME == "BinDiff"

    controller = module.BinDiffController()
    assert controller.loaded is False

    # These are what actually execute the sibling imports -- they sit inside
    # the methods, so merely exec'ing the module would not have touched them
    # and a broken relative import would still look fine.
    assert controller.match_rows() == []
    assert controller.statistic_rows() == []


def test_signal_and_slot_are_spelled_both_ways():
    """Either binding's spelling has to work under either binding.

    The alias used to run one way only, so code written with the PySide6 names
    failed on PyQt5 with a bare AttributeError -- which is the incompatibility
    the shim exists to hide.
    """
    from bindiff.ida_env import is_interactive

    if not is_interactive():
        # The shim keys on the *GUI*, not on whether a binding is importable:
        # outside the IDA GUI it serves a stub with no signals at all. That is
        # true even on IDA 9.1, whose headless interpreter has PyQt5 loaded --
        # so this is checked in the GUI harness, and the async client reads the
        # loaded binding directly rather than going through the shim.
        pytest.skip("the shim only installs a real binding inside the GUI")
    from bindiff.qt_shim import QtCore

    for name in ("Signal", "Slot", "pyqtSignal", "pyqtSlot"):
        assert hasattr(QtCore, name), f"QtCore.{name} is missing"
    assert QtCore.Signal is QtCore.pyqtSignal
    assert QtCore.Slot is QtCore.pyqtSlot
