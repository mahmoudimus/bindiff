"""panels.py must import on the host, define no widget, and expose only what
the workbench needs. Everything else about it is exercised in the GUI
harness (tests/gui/gui_driver.py), which is the only place a widget exists."""

import re
from pathlib import Path

import ida_plugin.panels as panels


def test_imports_without_ida():
    assert panels.IDA_AVAILABLE is False


def test_the_forms_are_gone():
    for name in ("ControlPanel", "DiffProgressForm", "UnmatchedFunctionsForm",
                 "FilterBar", "MatchedFunctionsForm", "StatisticsForm", "ActionMenu"):
        assert not hasattr(panels, name), f"{name} should have been deleted"


def test_the_source_declares_no_colour():
    source = Path(panels.__file__).read_text(encoding="utf-8")
    assert "setStyleSheet" not in source
    # Node colours for IDA's graph widget are the one exception: the graph
    # API takes a BGR int and has no palette. Only literals are counted --
    # `f"0x{address:X}"` formats an address for a message, it declares
    # nothing.
    literals = re.findall(r"0x[0-9A-Fa-f]{6}\b", source)
    assert len(literals) <= 3, literals
