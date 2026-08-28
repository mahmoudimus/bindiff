"""BinDiff plugin for IDA Pro.

Replaces the four ida_kernwin.Choose lists with Qt views. The choosers could
not filter, could not sort on anything but the column IDA happened to give
them, and could not show two values side by side without string padding.

Structure:

    ui_logic.py   pure view logic, no Qt and no IDA -- tested headless
    panels.py     Qt views, defined only when IDA is importable
    this file     plugin lifecycle, actions, and the IDA-side glue

Data comes from bindiff.BinDiffDatabase, which reads and writes the .BinDiff
sqlite file directly. The older bindiff.ida_plugin.BindiffResults path is not
used: its write operations are unimplemented and its reads went through queries
that did not match the schema.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# IDA loads this file as a top-level script, not as a package member, so
# `from ida_plugin.panels import ...` fails here with "no known parent package". Putting
# the package directory's parent on sys.path and importing the siblings
# absolutely works under both IDA and pytest (where this is imported as
# ida_plugin.bindiff_plugin).
_PACKAGE_ROOT = str(Path(__file__).resolve().parent.parent)
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

from bindiff.ida_env import qt_widgets_usable

# The plugin's UI only makes sense in the GUI. Detection never probe-imports an
# ida_* module: doing so before `idapro` in an idalib process is fatal on IDA
# 9.1. See bindiff.ida_env.
IDA_AVAILABLE = qt_widgets_usable()

if IDA_AVAILABLE:
    import ida_idaapi
    import ida_kernwin
    import ida_nalt

PLUGIN_NAME = "BinDiff"
PLUGIN_VERSION = "8.0.0"
PLUGIN_HOTKEY = "Ctrl-6"
PLUGIN_COMMENT = "Structural comparison of executable objects"
PLUGIN_HELP = "Load a .BinDiff result file and browse the matches"

ACTION_LOAD = "bindiff:load_results"
ACTION_SHOW_MATCHES = "bindiff:show_matches"
ACTION_SHOW_STATISTICS = "bindiff:show_statistics"
ACTION_CONFIGURE = "bindiff:configure_algorithms"


class BinDiffController:
    """Plugin state and the operations the menu actions invoke.

    Deliberately free of Qt: it opens databases, keeps the current one, and
    hands view objects to the panels. That makes the interesting half testable
    without a display.
    """

    def __init__(self) -> None:
        self._database = None
        self._matched_form = None

    @property
    def database(self):
        return self._database

    @property
    def loaded(self) -> bool:
        return self._database is not None

    def open_database(self, path: str, read_only: bool = False):
        """Opens a .BinDiff file, replacing whatever was open."""
        from bindiff import BinDiffDatabase

        if self._database is not None:
            self._database.close()
            self._database = None
        self._database = BinDiffDatabase.open(path, read_only=read_only)
        return self._database

    def close(self) -> None:
        if self._database is not None:
            self._database.close()
            self._database = None

    def match_rows(self):
        from ida_plugin.ui_logic import rows_from_database

        if self._database is None:
            return []
        return rows_from_database(self._database)

    def statistic_rows(self):
        from ida_plugin.ui_logic import build_statistics

        if self._database is None:
            return []
        return build_statistics(self._database.files(),
                                self._database.num_matches())


if IDA_AVAILABLE:

    def _ask_for_database() -> Optional[str]:
        path = ida_kernwin.ask_file(False, "*.BinDiff",
                                    "Select BinDiff result file")
        if not path:
            return None
        if not Path(path).is_file():
            ida_kernwin.warning(f"No such file: {path}")
            return None
        return path

    def _jump_to(address: int) -> None:
        ida_kernwin.jumpto(address)

    class _Action(ida_kernwin.action_handler_t):
        """Wraps a plain callable so each action is not its own class."""

        def __init__(self, callback, enabled=None) -> None:
            super().__init__()
            self._callback = callback
            self._enabled = enabled

        def activate(self, ctx) -> int:
            self._callback()
            return 1

        def update(self, ctx) -> int:
            if self._enabled is not None and not self._enabled():
                return ida_kernwin.AST_DISABLE_ALWAYS
            return ida_kernwin.AST_ENABLE_ALWAYS

    class BinDiffPlugin(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_FIX
        comment = PLUGIN_COMMENT
        help = PLUGIN_HELP
        wanted_name = PLUGIN_NAME
        wanted_hotkey = PLUGIN_HOTKEY

        def __init__(self) -> None:
            super().__init__()
            self.controller = BinDiffController()
            self._registered: list[str] = []

        # -- lifecycle ------------------------------------------------------

        def init(self):
            self._register_actions()
            return ida_idaapi.PLUGIN_KEEP

        def term(self) -> None:
            for name in self._registered:
                ida_kernwin.unregister_action(name)
            self._registered.clear()
            self.controller.close()

        def run(self, arg) -> bool:
            self._load_results()
            return True

        # -- actions --------------------------------------------------------

        def _register_actions(self) -> None:
            specs = (
                (ACTION_LOAD, "Load BinDiff results...",
                 self._load_results, None),
                (ACTION_SHOW_MATCHES, "Show matched functions",
                 self._show_matches, lambda: self.controller.loaded),
                (ACTION_SHOW_STATISTICS, "Show statistics",
                 self._show_statistics, lambda: self.controller.loaded),
                (ACTION_CONFIGURE, "Matching algorithms...",
                 self._configure_algorithms, None),
            )
            for name, label, callback, enabled in specs:
                if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                        name, label, _Action(callback, enabled))):
                    self._registered.append(name)
                    ida_kernwin.attach_action_to_menu(
                        f"Edit/Plugins/{PLUGIN_NAME}/", name,
                        ida_kernwin.SETMENU_APP)

        def _load_results(self) -> None:
            path = _ask_for_database()
            if path is None:
                return
            try:
                self.controller.open_database(path)
            except Exception as exc:
                ida_kernwin.warning(f"Could not open {path}:\n{exc}")
                return
            ida_kernwin.msg(
                f"[{PLUGIN_NAME}] loaded {path} "
                f"({self.controller.database.num_matches()} matches)\n")
            self._show_matches()

        def _show_matches(self) -> None:
            if not self._require_results():
                return
            from ida_plugin.panels import MatchedFunctionsForm

            if self.controller._matched_form is None:
                self.controller._matched_form = MatchedFunctionsForm(
                    self.controller.match_rows(), on_jump=_jump_to)
                self.controller._matched_form.Show()
            else:
                self.controller._matched_form.set_rows(
                    self.controller.match_rows())
                self.controller._matched_form.Show()

        def _show_statistics(self) -> None:
            if not self._require_results():
                return
            from ida_plugin.panels import StatisticsDialog

            StatisticsDialog(self.controller.statistic_rows()).exec_()

        def _configure_algorithms(self) -> None:
            import bindiff

            from ida_plugin.panels import AlgorithmConfigDialog

            def apply(changes: dict) -> None:
                bindiff.set_config(changes)
                ida_kernwin.msg(
                    f"[{PLUGIN_NAME}] matching configuration updated; "
                    f"it applies to the next diff\n")

            AlgorithmConfigDialog(bindiff.get_config(), apply).exec_()

        def _require_results(self) -> bool:
            if self.controller.loaded:
                return True
            ida_kernwin.warning("Load a .BinDiff result file first.")
            return False

    def PLUGIN_ENTRY():
        return BinDiffPlugin()

else:  # pragma: no cover - exercised only outside IDA

    def PLUGIN_ENTRY():
        raise RuntimeError("BinDiff plugin requires IDA Pro")
