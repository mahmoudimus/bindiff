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

# Names kept identical to the C++ plugin's where the action is the same, so
# muscle memory, saved layouts and any existing scripting keep working.
ACTION_DIFF_DATABASE = "bindiff:diff_database"
ACTION_LOAD = "bindiff:load_results"
ACTION_SAVE = "bindiff:save_results"
ACTION_SHOW_MATCHES = "bindiff:show_matched"
ACTION_SHOW_STATISTICS = "bindiff:show_statistics"
ACTION_SHOW_PRIMARY_UNMATCHED = "bindiff:show_primary_unmatched"
ACTION_SHOW_SECONDARY_UNMATCHED = "bindiff:show_secondary_unmatched"
ACTION_DELETE_MATCHES = "bindiff:match_delete"
ACTION_CONFIRM_MATCHES = "bindiff:confirm_matches"
ACTION_IMPORT_SYMBOLS_COMMENTS = "bindiff:import_symbols_comments"
ACTION_IMPORT_SYMBOLS_COMMENTS_EXTERNAL = "bindiff:import_symbols_comments_external"
ACTION_IMPORT_SYMBOLS_COMMENTS_GLOBAL = "bindiff:import_symbols_comments_global"
ACTION_UNMATCHED_ADD_MATCH_PRIMARY = "bindiff:primary_unmatched_add_match"
ACTION_UNMATCHED_ADD_MATCH_SECONDARY = "bindiff:secondary_unmatched_add_match"
ACTION_UNMATCHED_COPY_PRIMARY = "bindiff:primary_unmatched_copy_address"
ACTION_UNMATCHED_COPY_SECONDARY = "bindiff:secondary_unmatched_copy_address"
ACTION_PORT_COMMENTS = "bindiff:port_comments"
ACTION_COPY_PRIMARY_ADDRESS = "bindiff:copy_primary_address"
ACTION_COPY_SECONDARY_ADDRESS = "bindiff:copy_secondary_address"
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
        self._unmatched_forms = {}
        self._binexports = (None, None)

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
        self._binexports = (None, None)
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

    # -- inputs -------------------------------------------------------------

    def resolve_binexports(self) -> tuple:
        """Finds the two .BinExport inputs for the open result file.

        Unmatched views and the per-side counts need them: a .BinDiff records
        matches only. Guessed from the "<primary>_vs_<secondary>.BinDiff"
        naming the engine uses; either may come back None, and the caller is
        expected to ask rather than guess wrongly.
        """
        from bindiff.binexport import find_binexports_for

        if self._database is None:
            return (None, None)
        if self._binexports == (None, None):
            self._binexports = find_binexports_for(self._database.path)
        return self._binexports

    def set_binexports(self, primary: Optional[str],
                       secondary: Optional[str]) -> None:
        self._binexports = (primary, secondary)

    def _unmatched(self, side: int):
        from bindiff.binexport import read_functions
        from ida_plugin.ui_logic import unmatched_functions

        if self._database is None:
            return []
        path = self.resolve_binexports()[side]
        if path is None:
            raise FileNotFoundError(
                "the .BinExport for this side was not found next to the result "
                "file; set it explicitly to list unmatched functions")

        matches = self._database.matches()
        matched = [m.address_primary if side == 0 else m.address_secondary
                   for m in matches]
        return unmatched_functions(read_functions(path), matched)

    def unmatched_primary(self):
        return self._unmatched(0)

    def unmatched_secondary(self):
        return self._unmatched(1)

    # -- edits --------------------------------------------------------------

    def _require_writable(self):
        if self._database is None:
            raise RuntimeError("no result file is open")
        return self._database

    def delete_matches(self, match_ids) -> int:
        return self._require_writable().delete_matches(match_ids)

    def confirm_matches(self, match_ids) -> int:
        return self._require_writable().confirm_matches(match_ids)

    def add_manual_match(self, primary_address: int, secondary_address: int):
        return self._require_writable().add_manual_match(primary_address,
                                                         secondary_address)

    def save(self) -> None:
        self._require_writable().commit()

    def revert(self) -> None:
        self._require_writable().rollback()

    # -- porting ------------------------------------------------------------

    def plan_symbol_ports(self, match_ids=None, **kwargs):
        from ida_plugin.porting import plan_symbol_ports

        database = self._require_writable()
        matches = database.matches()
        if match_ids is not None:
            wanted = set(match_ids)
            matches = [m for m in matches if m.id in wanted]
        return plan_symbol_ports(matches, **kwargs)

    def plan_comment_ports(self, match_ids=None, **kwargs):
        """Needs the secondary .BinExport: comments are not in a .BinDiff."""
        from bindiff import load_comments
        from ida_plugin.porting import plan_comment_ports

        database = self._require_writable()
        secondary = self.resolve_binexports()[1]
        if secondary is None:
            raise FileNotFoundError(
                "the secondary .BinExport was not found next to the result "
                "file; comments live there, not in the .BinDiff")
        return plan_comment_ports(database, load_comments(secondary),
                                  match_ids=match_ids, **kwargs)


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
            loaded = lambda: self.controller.loaded  # noqa: E731
            specs = (
                (ACTION_DIFF_DATABASE, "Diff database...",
                 self._diff_database, None),
                (ACTION_LOAD, "Load results...", self._load_results, None),
                (ACTION_SAVE, "Save results", self._save_results, loaded),
                (ACTION_SHOW_MATCHES, "Matched functions",
                 self._show_matches, loaded),
                (ACTION_SHOW_PRIMARY_UNMATCHED, "Primary unmatched",
                 self._show_primary_unmatched, loaded),
                (ACTION_SHOW_SECONDARY_UNMATCHED, "Secondary unmatched",
                 self._show_secondary_unmatched, loaded),
                (ACTION_SHOW_STATISTICS, "Statistics",
                 self._show_statistics, loaded),
                (ACTION_DELETE_MATCHES, "Delete match(es)",
                 self._delete_matches, loaded),
                (ACTION_CONFIRM_MATCHES, "Confirm match(es)",
                 self._confirm_matches, loaded),
                (ACTION_IMPORT_SYMBOLS_COMMENTS, "Import symbols/comments",
                 self._import_symbols_comments, loaded),
                (ACTION_IMPORT_SYMBOLS_COMMENTS_EXTERNAL,
                 "Import symbols/comments as external library",
                 self._import_symbols_comments_external, loaded),
                (ACTION_IMPORT_SYMBOLS_COMMENTS_GLOBAL,
                 "Import all symbols/comments",
                 self._import_symbols_comments_global, loaded),
                (ACTION_UNMATCHED_ADD_MATCH_PRIMARY, "Add match",
                 self._add_match_from_unmatched, loaded),
                (ACTION_UNMATCHED_ADD_MATCH_SECONDARY, "Add match",
                 self._add_match_from_unmatched, loaded),
                (ACTION_UNMATCHED_COPY_PRIMARY, "Copy address",
                 lambda: self._copy_unmatched_address("primary"), loaded),
                (ACTION_UNMATCHED_COPY_SECONDARY, "Copy address",
                 lambda: self._copy_unmatched_address("secondary"), loaded),
                (ACTION_PORT_COMMENTS, "Port comments only",
                 self._port_comments, loaded),
                (ACTION_COPY_PRIMARY_ADDRESS, "Copy primary address",
                 self._copy_primary_address, loaded),
                (ACTION_COPY_SECONDARY_ADDRESS, "Copy secondary address",
                 self._copy_secondary_address, loaded),
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

        # -- helpers --------------------------------------------------------

        def _selected_match_ids(self) -> list:
            form = self.controller._matched_form
            rows = form.selected_rows() if form is not None else []
            if not rows:
                ida_kernwin.warning("Select one or more matches first.")
            return [row.match_id for row in rows]

        def _selected_rows(self) -> list:
            form = self.controller._matched_form
            return form.selected_rows() if form is not None else []

        def _refresh_matches(self) -> None:
            form = self.controller._matched_form
            if form is not None:
                form.set_rows(self.controller.match_rows())

        def _report(self, message: str) -> None:
            ida_kernwin.msg(f"[{PLUGIN_NAME}] {message}\n")

        # -- editing --------------------------------------------------------

        def _delete_matches(self) -> None:
            ids = self._selected_match_ids()
            if not ids:
                return
            if ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_NO,
                    f"Delete {len(ids)} match(es)?") != ida_kernwin.ASKBTN_YES:
                return
            deleted = self.controller.delete_matches(ids)
            self._refresh_matches()
            self._report(f"deleted {deleted} match(es); not yet saved")

        def _confirm_matches(self) -> None:
            ids = self._selected_match_ids()
            if not ids:
                return
            changed = self.controller.confirm_matches(ids)
            self._refresh_matches()
            self._report(f"confirmed {changed} match(es); not yet saved")

        def _save_results(self) -> None:
            try:
                self.controller.save()
            except Exception as exc:
                ida_kernwin.warning(f"Could not save:\n{exc}")
                return
            self._report("saved")

        # -- porting --------------------------------------------------------

        def _import_symbols_comments(self) -> None:
            """Ports names, and comments too when the .BinExport is available.

            Names come from the result file itself. Comments do not -- they
            live in the secondary .BinExport -- so a missing export degrades to
            names only rather than failing the whole action.
            """
            ids = self._selected_match_ids()
            if not ids:
                return

            self._apply_ports(ids)

        def _import_symbols_comments_external(self) -> None:
            """Ports, then marks the primary functions as library code."""
            from ida_plugin.porting import mark_as_library

            ids = self._selected_match_ids()
            if not ids:
                return
            ports = self._apply_ports(ids)
            marked = mark_as_library([p.address for p in ports])
            self._report(f"marked {marked.applied} function(s) as library code")

        def _import_symbols_comments_global(self) -> None:
            """Every match, not the selection."""
            if not self._require_results():
                return
            count = self.controller.database.num_matches()
            if ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_NO,
                    f"Import symbols and comments for all {count} matches?"
            ) != ida_kernwin.ASKBTN_YES:
                return
            self._apply_ports(match_ids=None)

        def _apply_ports(self, match_ids):
            """Shared by the three import variants. Returns the symbol ports."""
            from ida_plugin.porting import apply_comment_ports, apply_symbol_ports

            symbols = self.controller.plan_symbol_ports(match_ids)
            symbol_result = apply_symbol_ports(symbols)
            message = (f"renamed {symbol_result.applied} function(s)"
                       + (f", {symbol_result.failed} failed"
                          if symbol_result.failed else ""))
            try:
                comments = self.controller.plan_comment_ports(match_ids)
            except FileNotFoundError as exc:
                self._report(f"{message}; comments skipped: {exc}")
                return symbols
            comment_result = apply_comment_ports(comments)
            self._report(f"{message}; wrote {comment_result.applied} comment(s)")
            return symbols

        # -- pairing from the unmatched views --------------------------------

        def _add_match_from_unmatched(self) -> None:
            """Pairs the selected primary and secondary unmatched functions.

            Needs exactly one on each side: the pairing is one-to-one, and
            guessing which of several selections was meant would be worse than
            asking.
            """
            forms = self.controller._unmatched_forms
            primary_rows = (forms["primary"].selected_rows()
                            if "primary" in forms else [])
            secondary_rows = (forms["secondary"].selected_rows()
                              if "secondary" in forms else [])

            if len(primary_rows) != 1 or len(secondary_rows) != 1:
                ida_kernwin.warning(
                    "Select exactly one function in the primary unmatched view "
                    "and one in the secondary unmatched view.")
                return

            try:
                self.controller.add_manual_match(primary_rows[0].address,
                                                 secondary_rows[0].address)
            except ValueError as exc:
                ida_kernwin.warning(str(exc))
                return

            self._refresh_matches()
            self._refresh_unmatched()
            self._report(
                f"matched 0x{primary_rows[0].address:X} to "
                f"0x{secondary_rows[0].address:X}; not yet saved")

        def _refresh_unmatched(self) -> None:
            for side, form in self.controller._unmatched_forms.items():
                try:
                    rows = (self.controller.unmatched_secondary()
                            if side == "secondary"
                            else self.controller.unmatched_primary())
                except FileNotFoundError:
                    continue
                form.set_rows(rows)

        def _copy_unmatched_address(self, side: str) -> None:
            form = self.controller._unmatched_forms.get(side)
            rows = form.selected_rows() if form is not None else []
            if not rows:
                ida_kernwin.warning("Select a function first.")
                return
            from bindiff.qt_shim import QtWidgets

            QtWidgets.QApplication.clipboard().setText(
                "\n".join(f"0x{r.address:X}" for r in rows))
            self._report(f"copied {len(rows)} address(es)")

        def _port_comments(self) -> None:
            from ida_plugin.porting import apply_comment_ports

            ids = self._selected_match_ids()
            if not ids:
                return
            try:
                ports = self.controller.plan_comment_ports(ids)
            except FileNotFoundError as exc:
                ida_kernwin.warning(str(exc))
                return
            result = apply_comment_ports(ports)
            self._report(f"wrote {result.applied} comment(s), "
                         f"{result.failed} failed")

        # -- clipboard ------------------------------------------------------

        def _copy_address(self, secondary: bool) -> None:
            rows = self._selected_rows()
            if not rows:
                ida_kernwin.warning("Select a match first.")
                return
            text = "\n".join(
                f"0x{(r.address_secondary if secondary else r.address_primary):X}"
                for r in rows)
            from bindiff.qt_shim import QtWidgets

            QtWidgets.QApplication.clipboard().setText(text)
            self._report(f"copied {len(rows)} address(es)")

        def _copy_primary_address(self) -> None:
            self._copy_address(secondary=False)

        def _copy_secondary_address(self) -> None:
            self._copy_address(secondary=True)

        # -- unmatched ------------------------------------------------------

        def _show_unmatched(self, secondary: bool) -> None:
            if not self._require_results():
                return
            from ida_plugin.panels import UnmatchedFunctionsForm

            side = "secondary" if secondary else "primary"
            try:
                rows = (self.controller.unmatched_secondary() if secondary
                        else self.controller.unmatched_primary())
            except FileNotFoundError as exc:
                ida_kernwin.warning(
                    f"Cannot list {side} unmatched functions.\n\n{exc}")
                return

            form = self.controller._unmatched_forms.get(side)
            if form is None:
                # Only the primary side can be navigated to: the secondary's
                # addresses belong to a different database.
                form = UnmatchedFunctionsForm(
                    rows, side, on_jump=None if secondary else _jump_to)
                self.controller._unmatched_forms[side] = form
            else:
                form.set_rows(rows)
            form.Show()

        def _show_primary_unmatched(self) -> None:
            self._show_unmatched(secondary=False)

        def _show_secondary_unmatched(self) -> None:
            self._show_unmatched(secondary=True)

        # -- diffing --------------------------------------------------------

        def _diff_database(self) -> None:
            """Runs a diff against another binary, out of process.

            The export is what makes this slow, and it is why the C++ plugin
            freezes the IDB: it exports the secondary from inside this process.
            Here a worker does both exports and the diff, so the UI stays live.
            """
            secondary = ida_kernwin.ask_file(
                False, "*.*", "Select the secondary binary or database")
            if not secondary:
                return
            primary = ida_nalt.get_input_file_path()
            if not primary:
                ida_kernwin.warning("No input file for the open database.")
                return
            output = ida_kernwin.ask_file(True, "*.BinDiff",
                                          "Save results as")
            if not output:
                return

            self._report("diffing in a background process; the UI stays "
                         "responsive. This can take a while.")
            self._run_diff_async(primary, secondary, output)

        def _run_diff_async(self, primary: str, secondary: str,
                            output: str) -> None:
            import threading

            from bindiff.headless import run_headless

            def work():
                result = run_headless(
                    ["pipeline", primary, secondary, output], timeout=3600)

                def finish():
                    if not result.ok:
                        ida_kernwin.warning(f"Diff failed:\n{result.message}")
                        return
                    self.controller.open_database(output)
                    self._report(f"diff complete: {result.matches} matches")
                    self._show_matches()

                # Touching IDA from a worker thread is not safe; hand the
                # result back to the UI thread.
                ida_kernwin.execute_sync(finish,
                                         ida_kernwin.MFF_WRITE)

            threading.Thread(target=work, daemon=True).start()

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
                    self.controller.match_rows(), on_jump=_jump_to,
                    context_actions=(
                        ACTION_IMPORT_SYMBOLS_COMMENTS,
                        ACTION_PORT_COMMENTS,
                        None,
                        ACTION_CONFIRM_MATCHES,
                        ACTION_DELETE_MATCHES,
                        None,
                        ACTION_COPY_PRIMARY_ADDRESS,
                        ACTION_COPY_SECONDARY_ADDRESS,
                    ))
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
