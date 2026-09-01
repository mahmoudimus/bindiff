"""The workbench is Qt, so what can be checked here is that it imports
without IDA, defines nothing outside the guard, and keeps to the rules the
Qt code must follow (no stylesheet colours, one mask per file dialog --
the second is test_file_dialogs' job)."""

from pathlib import Path


def test_imports_without_ida():
    import ida_plugin.workbench as workbench
    assert workbench.IDA_AVAILABLE is False
    assert not hasattr(workbench, "Workbench")


def test_no_stylesheet_colours():
    import ida_plugin.workbench as workbench
    source = Path(workbench.__file__).read_text(encoding="utf-8")
    assert "setStyleSheet" not in source
    assert "#" not in "".join(line for line in source.splitlines()
                              if "QColor" in line or "color:" in line)


def test_every_action_the_menu_offers_is_a_session_action():
    """The context menu greys entries from session.can(); a typo here would
    silently disable an entry forever, which is the defect being fixed.

    The names are written `can(actions.NAME)`, because the module imports the
    session as `actions` -- so that is what the source is searched for.
    """
    import re
    import ida_plugin.session as session
    import ida_plugin.workbench as workbench
    source = Path(workbench.__file__).read_text(encoding="utf-8")
    used = set(re.findall(r"can\(actions\.(\w+)\)", source))
    assert used, "the menu must consult session.can()"
    # Every action the module names, not only the ones spelled inline: the
    # context menu builds its entries from a table and asks can() through a
    # loop variable, which is exactly where a typo would hide.
    named = set(re.findall(r"\bactions\.([A-Z_]+)\b", source))
    assert used <= named
    for name in named:
        assert hasattr(session, name), f"session has no action {name}"


def test_every_handler_it_calls_is_one_the_plugin_supplies():
    """The handler dict is the whole contract with the plugin (Task 12). A
    key nobody supplies raises KeyError inside a Qt slot, where the traceback
    goes to the output window and the button simply does nothing."""
    import re
    import ida_plugin.workbench as workbench
    source = Path(workbench.__file__).read_text(encoding="utf-8")
    expected = {"compare", "cancel", "browse", "configure", "save", "close",
                "unmatch", "verify", "port", "restore_name", "pair", "graphs",
                "inspect", "copy_here", "copy_there", "locate_export", "jump",
                "autosave"}
    used = set(re.findall(r"_handlers\[\"(\w+)\"\]", source))
    assert used <= expected, f"unknown handler keys: {sorted(used - expected)}"
    assert used == expected, f"never called: {sorted(expected - used)}"
