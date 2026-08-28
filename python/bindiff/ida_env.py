"""Where are we running: the IDA GUI, an idalib process, or neither.

The detection here is taken from karta-ng
(src/karta_ng/disassembler/IDA/ida_helpers.py), which worked it out the hard
way. The rule that matters:

    Never probe-import an ``ida_*`` module to find out whether IDA is around.

In an idalib process ``idapro`` has to be imported before any raw ``ida_*``
module -- it loads libidalib/libida with global symbols before ``ida_pro``
imports ``_ida_pro``. Importing ``ida_kernwin`` first is "Fatal error before
kernel init" on IDA 9.1. (9.4 tolerates it, so a 9.4-only test run will not
show you the bug.)

Inside the IDA GUI the opposite holds: the kernel is already up and ``idapro``
must *not* be imported.

So the GUI is recognised by ``ida_kernwin`` already being present in
``sys.modules``, which IDA's own Python start-up guarantees, and a fresh
process never probes anything.
"""

from __future__ import annotations

import os
import sys
from pathlib import PureWindowsPath

__all__ = [
    "IDA_IS_INTERACTIVE",
    "running_as_ida_executable",
    "is_interactive",
    "ida_kernwin_if_loaded",
    "qt_widgets_usable",
    "qt_core_usable",
]


# The GUI executables, including the pre-7.0 idaq names. idat/idat64 are
# deliberately absent: that is IDA's text mode -- a real IDA kernel with no Qt
# -- so it must not count as interactive.
_GUI_EXECUTABLES = frozenset({
    "ida", "ida64",
    "ida.exe", "ida64.exe",
    "idaq", "idaq64",
    "idaq.exe", "idaq64.exe",
})


def _running_as_ida_executable() -> bool:
    """True when this interpreter *is* IDA's GUI binary.

    Independent of, and earlier than, the sys.modules signal: it answers during
    start-up, before IDA's Python has imported ida_kernwin. It is also the
    check that decides whether `idapro` may be imported -- in an idalib process
    you must import it first, in the GUI you must not import it at all.

    Only the GUI names count. An idalib process runs under a normal or
    venv-backed python (e.g. /app/ida/.venv/bin/python3), which correctly
    fails this test.
    """
    # PureWindowsPath rather than Path: it treats both "/" and "\\" as
    # separators, so it takes the final component of a Windows path even when
    # this code is running on POSIX. Path/PurePosixPath would leave
    # "C:\\...\\ida.exe" as a single component.
    #
    # Compared against a set of whole names rather than str.endswith(): an
    # endswith("ida") test also matches "nvidia" and any path ending in those
    # three letters.
    executable = PureWindowsPath(sys.executable or "").name
    return executable.lower() in _GUI_EXECUTABLES


def _detect_interactive() -> bool:
    if os.getenv("IDA_IS_INTERACTIVE"):
        return True
    if _running_as_ida_executable():
        return True
    # Otherwise: only ask if IDA's own start-up has already imported it.
    # Importing it ourselves is the thing that breaks idalib.
    if "ida_kernwin" not in sys.modules:
        return False
    try:
        import ida_kernwin

        # is_idaq() is absent on IDA 8.4 and below; treat its presence in
        # sys.modules as good enough there.
        return bool(getattr(ida_kernwin, "is_idaq", lambda: True)())
    except Exception:
        return False


IDA_IS_INTERACTIVE: bool = _detect_interactive()


def is_interactive() -> bool:
    """True when running inside the IDA Pro GUI.

    Re-evaluated on each call, unlike the module-level constant: a plugin is
    imported while the GUI is coming up, and the answer can change between
    import time and the point a menu action runs.
    """
    return IDA_IS_INTERACTIVE or _detect_interactive()


def ida_kernwin_if_loaded():
    """Returns the ``ida_kernwin`` module if IDA already loaded it, else None.

    For code that wants to talk to the UI when there is one and stay quiet
    otherwise, without ever triggering the import itself.
    """
    return sys.modules.get("ida_kernwin")


def qt_widgets_usable() -> bool:
    """True when it is safe to construct QtWidgets objects.

    Widgets need the GUI: there is no QApplication and no display in an idalib
    or headless process, so building one there is at best useless and at worst
    a crash. This is the guard for anything visual.
    """
    return is_interactive()


def qt_core_usable() -> bool:
    """True when QtCore is usable -- which includes headless.

    QtCore is not the same as QtWidgets. QThread, QProcess, QObject, signals
    and the event loop primitives work fine without a GUI, and they are what
    you want for running a diff off the UI thread. Only the widget layer needs
    a display, so guard those two separately rather than treating "no GUI" as
    "no Qt".

    Note the vendored qt_shim does not draw this distinction: outside the IDA
    GUI it stubs out QtCore along with everything else. Use this to decide, and
    import the binding's QtCore directly if you need it headless.
    """
    if is_interactive():
        return True

    # Availability is checked without importing. Importing a Qt binding inside
    # a headless IDA process takes the interpreter down -- not an exception,
    # the process dies -- so this is the same hazard as probe-importing ida_*.
    # find_spec locates the top-level package without executing it; asking for
    # "PySide6.QtCore" would import the PySide6 package to find the submodule,
    # which is the part that crashes.
    import importlib.util

    for binding in ("PySide6", "PyQt5"):
        try:
            if importlib.util.find_spec(binding) is not None:
                return True
        except (ImportError, ValueError):
            continue
    return False


def running_as_ida_executable() -> bool:
    """Public form of the executable check.

    This is the one to use when deciding whether to bootstrap idalib:

        if not running_as_ida_executable():
            import idapro          # must precede every raw ida_* import
        import idaapi
    """
    return _running_as_ida_executable()
