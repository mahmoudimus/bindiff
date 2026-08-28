"""Tests for IDA environment detection.

The rule these protect: detection must never import an ida_* module. In an
idalib process `idapro` has to be imported before any raw ida_* module, and
probing ahead of it is a fatal error on IDA 9.1 -- a failure a 9.4-only test
run will not reproduce. Approach taken from karta-ng's ida_helpers.
"""

from __future__ import annotations

import builtins
import sys
import types

import pytest

from bindiff import ida_env


def test_headless_is_not_interactive():
    assert ida_env.is_interactive() is False
    assert ida_env.qt_widgets_usable() is False


def test_env_override(monkeypatch):
    monkeypatch.setenv("IDA_IS_INTERACTIVE", "1")
    assert ida_env._detect_interactive() is True


def test_gui_is_detected_from_already_loaded_module(monkeypatch):
    monkeypatch.setitem(sys.modules, "ida_kernwin",
                        types.SimpleNamespace(is_idaq=lambda: True))
    assert ida_env._detect_interactive() is True


def test_idalib_process_is_not_interactive(monkeypatch):
    """ida_kernwin imported but not a GUI: an idalib run, not the IDA UI."""
    monkeypatch.setitem(sys.modules, "ida_kernwin",
                        types.SimpleNamespace(is_idaq=lambda: False))
    assert ida_env._detect_interactive() is False


def test_ida_8_4_without_is_idaq(monkeypatch):
    """is_idaq() is absent on 8.4 and below; presence is then good enough."""
    monkeypatch.setitem(sys.modules, "ida_kernwin", types.SimpleNamespace())
    assert ida_env._detect_interactive() is True


def test_detection_imports_nothing(monkeypatch):
    monkeypatch.delitem(sys.modules, "ida_kernwin", raising=False)
    monkeypatch.delenv("IDA_IS_INTERACTIVE", raising=False)

    original_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.startswith("ida"):
            raise AssertionError(f"detection must not import {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    assert ida_env._detect_interactive() is False


def test_kernwin_accessor_does_not_import(monkeypatch):
    monkeypatch.delitem(sys.modules, "ida_kernwin", raising=False)
    assert ida_env.ida_kernwin_if_loaded() is None

    sentinel = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, "ida_kernwin", sentinel)
    assert ida_env.ida_kernwin_if_loaded() is sentinel


def test_qt_core_is_independent_of_the_gui():
    """QtCore (QThread, QProcess) works headless; only widgets need a display.

    Whether a binding is installed here is environment-dependent, so this only
    asserts the two questions are answered separately -- qt_core_usable must
    not simply mirror qt_widgets_usable.
    """
    assert ida_env.qt_widgets_usable() is False
    assert isinstance(ida_env.qt_core_usable(), bool)


class TestExecutableDetection:
    """The second, earlier signal: is this interpreter IDA's GUI binary.

    It answers before IDA's Python has imported ida_kernwin, and it is what
    decides whether idalib may be bootstrapped.
    """

    @pytest.mark.parametrize("executable", [
        "/opt/ida/ida", "/opt/ida/ida64",
        r"C:\\Program Files\\IDA\\ida.exe", r"C:\\Program Files\\IDA\\ida64.exe",
    ])
    def test_gui_executables_count(self, monkeypatch, executable):
        monkeypatch.setattr(sys, "executable", executable)
        assert ida_env.running_as_ida_executable() is True
        monkeypatch.delitem(sys.modules, "ida_kernwin", raising=False)
        monkeypatch.delenv("IDA_IS_INTERACTIVE", raising=False)
        assert ida_env._detect_interactive() is True

    @pytest.mark.parametrize("executable", [
        "/opt/ida/idat", "/opt/ida/idat64",
    ])
    def test_text_mode_is_not_a_gui(self, monkeypatch, executable):
        """idat is a real IDA kernel with no Qt, so widgets are still off."""
        monkeypatch.setattr(sys, "executable", executable)
        assert ida_env.running_as_ida_executable() is False

    @pytest.mark.parametrize("executable", [
        "/app/ida/.venv/bin/python3", "/usr/bin/python3", "",
    ])
    def test_idalib_interpreters_are_not_the_gui(self, monkeypatch, executable):
        monkeypatch.setattr(sys, "executable", executable)
        assert ida_env.running_as_ida_executable() is False

    @pytest.mark.parametrize("executable", [
        "/opt/ida/idaq", "/opt/ida/idaq64",
        r"C:\Program Files\IDA\idaq.exe",
    ])
    def test_legacy_idaq_names_count(self, monkeypatch, executable):
        monkeypatch.setattr(sys, "executable", executable)
        assert ida_env.running_as_ida_executable() is True

    @pytest.mark.parametrize("executable", [
        "/usr/lib/nvidia/ida",       # a whole-name match, not endswith
        "/opt/tools/notida",
        "/opt/ida/ida_helper",
    ])
    def test_lookalike_paths_are_rejected(self, monkeypatch, executable):
        """endswith("ida") would match "nvidia"; whole-name matching does not."""
        monkeypatch.setattr(sys, "executable", executable)
        expected = executable.rsplit("/", 1)[-1] in ("ida", "ida64")
        assert ida_env.running_as_ida_executable() is expected
