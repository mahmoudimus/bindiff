"""The inspector is Qt, so what can be checked here is that it imports
without IDA, defines its widgets only inside the guard, and keeps to the two
rules its Qt code must follow: no stylesheet colours, and a hand-picked row
ports without a floor."""

from pathlib import Path


def test_imports_without_ida():
    import ida_plugin.inspector as inspector
    assert inspector.IDA_AVAILABLE is False
    assert not hasattr(inspector, "InspectorForm")


def test_no_stylesheet_colours():
    import ida_plugin.inspector as inspector
    source = Path(inspector.__file__).read_text(encoding="utf-8")
    assert "setStyleSheet" not in source


def test_the_inspector_ports_a_single_row_without_a_floor():
    """A hand-picked row is the judgement the floor stands in for; the
    inspector's button must call the port handler with threshold 0.0."""
    import ida_plugin.inspector as inspector
    source = Path(inspector.__file__).read_text(encoding="utf-8")
    assert '"port"](0.0' in source
