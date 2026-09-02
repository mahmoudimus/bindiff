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
    """A hand-picked row is the judgement the floors stand in for; the
    inspector's button must call the port handler with threshold 0.0 and say
    so about the floors as well.

    The keyword is the point: the handler used to read "no floors" out of a
    threshold of 0.0, and the footer's slider reaches 0.00 too -- where it
    means the threshold and nothing else, so the footer's preview and the
    port it confirmed disagreed at that end of the range.
    """
    import ida_plugin.inspector as inspector
    source = Path(inspector.__file__).read_text(encoding="utf-8")
    assert '"port"](0.0' in source
    assert "ignore_floors=True" in source
