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

import contextlib
import os
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

def _describe_symbols(planned, result, replaced: int, skips) -> str:
    """The names half of an import.

    Leads with what happened rather than with a count, because a selection
    that is already fully named is the common case once you have imported
    once, and "renamed 0 function(s)" reads as a failure of the thing that
    was in fact unnecessary.
    """
    if result.applied:
        text = f"{result.applied} written"
        if replaced:
            text += f" ({replaced} replaced an existing name)"
    elif planned:
        text = "none written"
    else:
        text = "nothing to write"
    if result.failed:
        text += f", {result.failed} failed"
    if skips:
        text += " -- " + ", ".join(f"{count} {reason}"
                                   for reason, count in sorted(skips.items()))
    return text


def _describe_comments(planned, result) -> str:
    """What happened to the comments, in enough detail to act on.

    "wrote 2 comment(s)" cannot answer the only question worth asking when
    one goes missing: was it never planned, or did IDA refuse it? The two
    have different causes -- an instruction that did not match, against an
    address the database will not take a comment on -- and different fixes.
    """
    if not planned:
        return ("nothing to write -- the secondary export has no comment on "
                "the matched instructions of this selection")
    kinds = {}
    for port in planned:
        kinds[port.kind] = kinds.get(port.kind, 0) + 1
    detail = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
    message = f"{result.applied} of {len(planned)} written ({detail})"
    if result.failed:
        where = ", ".join(f"0x{a:X}" for a in result.failed_addresses[:5])
        more = ("..." if len(result.failed_addresses) > 5 else "")
        message += f"; {result.failed} refused by IDA at {where}{more}"
    return message


if IDA_AVAILABLE:
    import ida_idaapi
    import ida_kernwin
    import ida_nalt

PLUGIN_NAME = "BinDiff"
PLUGIN_VERSION = "8.1.4"
PLUGIN_HOTKEY = "Ctrl-6"
PLUGIN_COMMENT = "Structural comparison of executable objects"
PLUGIN_HELP = "Load a .BinDiff result file and browse the matches"

# Names kept identical to the C++ plugin's where the action is the same, so
# muscle memory, saved layouts and any existing scripting keep working.
ACTION_MAIN = "bindiff:main"
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
ACTION_IMPORT_TYPES = "bindiff:import_types"
ACTION_IMPORT_ALL = "bindiff:import_all"
ACTION_IMPORT_SYMBOLS_COMMENTS_EXTERNAL = "bindiff:import_symbols_comments_external"
ACTION_IMPORT_SYMBOLS_COMMENTS_GLOBAL = "bindiff:import_symbols_comments_global"
ACTION_UNMATCHED_ADD_MATCH_PRIMARY = "bindiff:primary_unmatched_add_match"
ACTION_UNMATCHED_ADD_MATCH_SECONDARY = "bindiff:secondary_unmatched_add_match"
ACTION_UNMATCHED_COPY_PRIMARY = "bindiff:primary_unmatched_copy_address"
ACTION_UNMATCHED_COPY_SECONDARY = "bindiff:secondary_unmatched_copy_address"
ACTION_PORT_COMMENTS = "bindiff:port_comments"
ACTION_COPY_PRIMARY_ADDRESS = "bindiff:copy_primary_address"
ACTION_COPY_SECONDARY_ADDRESS = "bindiff:copy_secondary_address"
ACTION_VIEW_FLOW_GRAPHS = "bindiff:view_flow_graphs"
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
        self._statistics_form = None
        self._binexports = (None, None)
        self._details = None
        self._functions = {}

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
        self._details = None
        self._functions = {}
        return self._database

    def close(self) -> None:
        if self._database is not None:
            self._database.close()
            self._database = None

    def match_rows(self):
        from ida_plugin.ui_logic import rows_from_database

        if self._database is None:
            return []
        primary, secondary = self._function_details()
        return rows_from_database(self._database, primary, secondary)

    def _function_details(self) -> tuple:
        """Per-side totals for the count columns, loaded once and kept.

        Resolving them means walking the whole instruction table of each
        .BinExport, so this is cached: doing it per refresh would make the
        table unusable on a large binary. Missing exports are not an error --
        the columns read zero and every other column still works.
        """
        from bindiff.binexport import read_function_details

        if self._details is not None:
            return self._details

        loaded = []
        for path in self.resolve_binexports():
            if path is None:
                loaded.append({})
                continue
            try:
                loaded.append(read_function_details(path))
            except Exception:
                loaded.append({})
        self._details = tuple(loaded)
        return self._details

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

    def recorded_input_name(self, side: int) -> Optional[str]:
        """What the result file calls one of its inputs.

        A .BinDiff records the filename it was given for each side, which is
        what Statistics shows. Used to name the file in a prompt rather than
        asking for "the secondary .BinExport" and leaving the user to work out
        which file that is.
        """
        if self._database is None:
            return None
        try:
            files = self._database.files()
        except Exception:
            return None
        if side < len(files):
            name = files[side].filename
            return Path(name).name if name else None
        return None

    def matches_for(self, match_ids=None):
        """The match rows behind a selection, for reporting on them."""
        if self._database is None:
            return []
        matches = self._database.matches()
        if match_ids is None:
            return matches
        wanted = set(match_ids)
        return [m for m in matches if m.id in wanted]

    def set_binexports(self, primary: Optional[str],
                       secondary: Optional[str]) -> None:
        self._binexports = (primary, secondary)
        # Both caches are keyed on the old pair and neither would notice.
        self._details = None
        self._functions = {}

    def _exported_functions(self, path: str):
        """Every function in one .BinExport, parsed once and kept.

        read_functions parses the whole protobuf, which is seconds on a large
        export. The unmatched lists are now refreshed after every edit, so
        without this a delete over a multi-selection would re-parse both
        exports and stall the UI for exactly as long as the diff's inputs are
        big.
        """
        from bindiff.binexport import read_functions

        if path not in self._functions:
            self._functions[path] = read_functions(path)
        return self._functions[path]

    def _unmatched(self, side: int):
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
        return unmatched_functions(self._exported_functions(path), matched)

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

    def record_ported_names(self, ports) -> int:
        """Writes ported names into the result file, so it agrees with IDA."""
        database = self._require_writable()
        return database.set_primary_names(
            {port.match_id: port.new_name for port in ports})

    def mark_imported(self, match_ids) -> int:
        """Records that these matches had something written into IDA.

        The .BinDiff has one flag for this, `commentsported`, and it has
        always meant more than its name: upstream sets it from PortComments(),
        which ports symbols as well. Kept to that meaning rather than given a
        column of our own -- a result file has to stay readable by the C++
        plugin and the Java UI.

        Nothing wrote it before, so the "Comments Ported" column the view has
        always had was permanently empty and its sort did nothing.
        """
        ids = sorted(set(match_ids))
        if not ids:
            return 0
        return self._require_writable().set_comments_ported(ids)

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

    def types_sidecar(self) -> Optional[str]:
        """The secondary's type sidecar, if one has been produced.

        Beside the secondary .BinExport, or beside the database it came from.
        Types cannot travel in a .BinExport -- BinExport2 has no type table --
        so this is a separate file and its absence is the normal state until
        somebody asks for types.
        """
        from bindiff.typeinfo import types_path_for

        secondary = self.resolve_binexports()[1]
        if secondary is None:
            return None
        for candidate in (types_path_for(secondary),
                          types_path_for(str(Path(secondary).with_suffix("")))):
            if Path(candidate).is_file():
                return candidate
        return None

    def plan_type_ports(self, match_ids=None, *,
                        min_similarity: float = None,
                        min_confidence: float = None):
        """Which prototypes to apply, and which types to define first.

        Returns (plan, ports) where ports is a list of (address, declaration).
        The plan covers only what this database is missing: it asks IDA what
        it already has, so a type both sides define is not redefined.
        """
        import json

        from ida_plugin.porting import (DEFAULT_PORT_MIN_CONFIDENCE,
                                        DEFAULT_PORT_MIN_SIMILARITY)
        from bindiff.typeinfo import FunctionType, from_json, plan_types
        from bindiff.typeinfo_ida import existing_type_names

        if min_similarity is None:
            min_similarity = DEFAULT_PORT_MIN_SIMILARITY
        if min_confidence is None:
            min_confidence = DEFAULT_PORT_MIN_CONFIDENCE

        database = self._require_writable()
        sidecar = self.types_sidecar()
        if sidecar is None:
            raise FileNotFoundError(
                "no type sidecar for the secondary; types are not in a "
                ".BinExport and have to be read out of its database")

        declarations, functions = from_json(
            json.loads(Path(sidecar).read_text(encoding="utf-8")))
        by_address = {f.address: f for f in functions}

        wanted = set(match_ids) if match_ids is not None else None
        needed, ports = [], []
        for match in database.matches():
            if wanted is not None and match.id not in wanted:
                continue
            if (match.similarity < min_similarity
                    or match.confidence < min_confidence):
                continue
            source = by_address.get(match.address_secondary)
            if source is None:
                continue
            needed.append(source)
            ports.append((match.address_primary, source.declaration))

        plan = plan_types(declarations, needed,
                          already_present=existing_type_names())
        return plan, ports

    def plan_comment_ports(self, match_ids=None, **kwargs):
        """Needs the secondary .BinExport: comments are not in a .BinDiff."""
        from bindiff.comments import portable_comments
        from ida_plugin.porting import plan_comment_ports

        database = self._require_writable()
        secondary = self.resolve_binexports()[1]
        if secondary is None:
            raise FileNotFoundError(
                "the secondary .BinExport was not found next to the result "
                "file; comments live there, not in the .BinDiff")
        # portable_comments, not bindiff.load_comments: the engine's
        # reader keys comments by (address, operand) and keeps one per
        # address, which for a documented function was its own name
        # rather than the documentation.
        return plan_comment_ports(database,
                                  portable_comments(secondary),
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
            """Whether the action is available right now.

            The _ALWAYS variants mean what they say: IDA records the answer
            and stops calling update(). Returning AST_DISABLE_ALWAYS for an
            action that is merely unavailable *yet* disables it for the life
            of the session -- which is what happened to every view action
            here. They were greyed before a result existed, IDA never asked
            again, and loading one changed nothing: Matched functions,
            Statistics and both unmatched lists stayed unreachable.

            AST_ENABLE and AST_DISABLE are the ones that get re-asked.
            """
            if self._enabled is None:
                # Genuinely always available, so there is nothing to re-ask.
                return ida_kernwin.AST_ENABLE_ALWAYS
            return (ida_kernwin.AST_ENABLE if self._enabled()
                    else ida_kernwin.AST_DISABLE)

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
            # Kept alive: a GraphViewer that is garbage collected takes its
            # window with it.
            self._graph_viewers: list = []

        # -- lifecycle ------------------------------------------------------

        _control_panel = None
        _cancel_event = None
        _autosave_timer = None

        def init(self):
            self._register_actions()
            return ida_idaapi.PLUGIN_KEEP

        def term(self) -> None:
            for name in self._registered:
                ida_kernwin.unregister_action(name)
            self._registered.clear()
            if self._autosave_timer is not None:
                self._autosave_timer.stop()
                self._autosave_timer = None
            self.controller.close()

        def run(self, arg) -> bool:
            self._show_control_panel()
            return True

        def _show_control_panel(self) -> None:
            """The plugin's front door.

            A panel rather than a modal chooser: the actions stay on screen
            while you work, and their enabled state is ours rather than
            IDA's -- which is what left three of the four views greyed for a
            whole session.
            """
            from ida_plugin.panels import ControlPanel

            if self._control_panel is None:
                self._control_panel = ControlPanel({
                    "on_diff": lambda path: self._diff_database(secondary=path),
                    "on_load": self._load_results,
                    "on_save": self._save_results,
                    "on_cancel": self._cancel_running_diff,
                    "on_show": self._show_view,
                    "on_autosave": self._set_autosave,
                })
            self._control_panel.Show()
            self._sync_control_panel()

        def _set_autosave(self, enabled: bool, seconds: int) -> None:
            """Starts or stops the auto-save timer.

            The timer lives here rather than on the panel so hiding the panel
            does not silently stop saving. A checkbox that stops working when
            its window is closed is worse than no checkbox.
            """
            from bindiff.qt_shim import QtCore

            if self._autosave_timer is None:
                self._autosave_timer = QtCore.QTimer()
                self._autosave_timer.timeout.connect(self._autosave_tick)
            self._autosave_timer.stop()
            if enabled:
                self._autosave_timer.setInterval(max(5, int(seconds)) * 1000)
                self._autosave_timer.start()

        def _autosave_tick(self) -> None:
            """Commits, but only when there is something to commit.

            Asking the connection rather than tracking a flag: sqlite knows
            whether a write has happened since the last commit, and a flag of
            our own would go stale the first time a new edit method forgot to
            set it. It also keeps this quiet -- a timer that reported "saved"
            every minute with nothing to save would train you to ignore it.
            """
            database = getattr(self.controller, "database", None)
            if database is None or not database.has_unsaved_changes:
                return
            try:
                self.controller.save()
            except Exception as exc:
                # Stop rather than fail on a timer forever: a broken save that
                # complains once a minute is its own problem.
                self._set_autosave(False, 0)
                ida_kernwin.warning(
                    f"{PLUGIN_NAME}: auto-save failed and has been turned "
                    f"off.\n\n{exc}")
                return
            self._report("auto-saved")

        def _show_view(self, key: str) -> None:
            {"matched": self._show_matches,
             "statistics": self._show_statistics,
             "primary_unmatched": self._show_primary_unmatched,
             "secondary_unmatched": self._show_secondary_unmatched}[key]()

        def _cancel_running_diff(self) -> None:
            if self._cancel_event is not None:
                self._cancel_event.set()

        def _sync_control_panel(self) -> None:
            """Tells the panel whether there are results. Pushed, not polled:
            the panel must not reach into the controller."""
            if self._control_panel is None:
                return
            loaded = self.controller.loaded
            path = matches = secondary = None
            if loaded:
                database = self.controller.database
                path = getattr(database, "path", None)
                try:
                    matches = database.num_matches()
                except Exception:
                    matches = None
                # What "diff again" means for a loaded result: the same
                # secondary, against a primary that has changed since. Offered
                # rather than left blank because the obvious thing to reach
                # for is the .BinDiff sitting right there in the field above,
                # which is a result and not an input.
                try:
                    secondary = self.controller.resolve_binexports()[1]
                except Exception:
                    secondary = None
            self._control_panel.set_results(loaded, path, matches, secondary)

        def _open_menu(self) -> None:
            """Offers what the plugin can do, rather than assuming.

            This used to call _load_results() directly, so choosing BinDiff
            from the menu opened a file dialog and nothing else: the diff was
            unreachable unless you already knew the action name. The C++
            plugin puts up a small menu here and that is what anyone arriving
            from it expects.
            """
            entries = [("Diff database...", self._diff_database),
                       ("Load results...", self._load_results)]
            if self.controller.loaded:
                # Only worth offering once there is something to show.
                entries.append(("Matched functions", self._show_matches))
                entries.append(("Statistics", self._show_statistics))

            chosen = self._choose_action(entries)
            if chosen:
                chosen()

        def _choose_action(self, entries):
            """The menu, in Qt where it is available and in IDA's own dialog
            where it is not.

            ask_buttons carries at most three, so the fallback offers the two
            that are always present and drops the rest; it is the path for a
            headless or Qt-less IDA, where the extra views have nothing to
            draw on anyway.
            """
            try:
                from ida_plugin.panels import ActionMenu
            except ImportError:
                ActionMenu = None

            if ActionMenu is not None:
                dialog = ActionMenu(f"{PLUGIN_NAME} {PLUGIN_VERSION}", entries)
                from bindiff.qt_shim import exec_widget

                exec_widget(dialog)
                return dialog.chosen

            answer = ida_kernwin.ask_buttons(
                entries[0][0], entries[1][0], "Close", 1,
                f"{PLUGIN_NAME} {PLUGIN_VERSION}")
            if answer == 1:
                return entries[0][1]
            if answer == 0:
                return entries[1][1]
            return None

        # -- actions --------------------------------------------------------

        def _register_actions(self) -> None:
            loaded = lambda: self.controller.loaded  # noqa: E731
            specs = (
                (ACTION_MAIN, f"{PLUGIN_NAME}...", self._open_menu, None),
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
                (ACTION_IMPORT_ALL, "Import all",
                 self._import_all, loaded),
                (ACTION_IMPORT_TYPES, "Import types",
                 self._import_types, loaded),
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
                (ACTION_VIEW_FLOW_GRAPHS, "View flow graph diff",
                 self._view_flow_graphs, loaded),
                (ACTION_CONFIGURE, "Matching algorithms...",
                 self._configure_algorithms, None),
            )
            # Shift-D is the C++ plugin's, for the same action. Someone
            # arriving from it should not have to learn a new key to open the
            # same dialog.
            shortcuts = {ACTION_MAIN: "Shift-D",
                         ACTION_LOAD: "Ctrl-Shift-6"}

            # Kept alongside registration rather than written out a second
            # time, so a context menu entry can never name an action whose
            # handler this does not have.
            self._callbacks = {name: callback for name, _, callback, _ in specs}

            for name, label, callback, enabled in specs:
                if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                        name, label, _Action(callback, enabled),
                        shortcuts.get(name))):
                    self._registered.append(name)
                    ida_kernwin.attach_action_to_menu(
                        f"Edit/Plugins/{PLUGIN_NAME}/", name,
                        ida_kernwin.SETMENU_APP)

            # Upstream's own paths and flags, read out of
            # ida/main_plugin.cc rather than guessed at. Two things about
            # them are not obvious and both bit this:
            #
            # They are internal item names, not display labels --
            # "ProduceFile", not "Produce file".
            #
            # A trailing slash means *inside* that submenu; without one the
            # entry lands beside the named item. "File/Produce file/" put
            # BinDiff at the bottom of the Produce file submenu instead of in
            # the File menu next to it.
            #
            # SETMENU_FIRST is what lifts the View submenu to the top, above
            # "Open subviews". An append puts it at the bottom by Full
            # Screen, which is where it was.
            placements = (
                ("File/ProduceFile", ACTION_MAIN, ida_kernwin.SETMENU_APP),
                ("File/LoadFile/AdditionalBinaryFile", ACTION_LOAD,
                 ida_kernwin.SETMENU_APP),
                ("File/ProduceFile/CreateCallgraphGDL", ACTION_SAVE,
                 ida_kernwin.SETMENU_APP),
                ("Edit/Comments/InsertPredefinedComment", ACTION_PORT_COMMENTS,
                 ida_kernwin.SETMENU_APP),
                # Chained: each entry is placed after the previous one, which
                # is how upstream builds the submenu in order. The submenu
                # itself is created by _create_view_menu below; attaching
                # alone leaves IDA to put it wherever it likes, which is the
                # bottom of View next to Full Screen.
                (f"View/{PLUGIN_NAME}/", ACTION_SHOW_MATCHES,
                 ida_kernwin.SETMENU_FIRST),
                (f"View/{PLUGIN_NAME}/MatchedFunctions",
                 ACTION_SHOW_STATISTICS, ida_kernwin.SETMENU_APP),
                (f"View/{PLUGIN_NAME}/Statistics",
                 ACTION_SHOW_PRIMARY_UNMATCHED, ida_kernwin.SETMENU_APP),
                (f"View/{PLUGIN_NAME}/PrimaryUnmatched",
                 ACTION_SHOW_SECONDARY_UNMATCHED, ida_kernwin.SETMENU_APP),
            )
            self._create_view_menu()
            for path, name, flags in placements:
                if name in self._registered:
                    ida_kernwin.attach_action_to_menu(path, name, flags)

        def _create_view_menu(self) -> None:
            """Creates the View/BinDiff submenu, positioned like upstream's.

            attach_action_to_menu creates a missing submenu implicitly, but
            only IDA decides where it goes -- which is the end of the menu, by
            Full Screen. SETMENU_FIRST does not move it either: it places the
            *item* at the beginning of the menu the path names, and for
            "View/BinDiff/" that menu is BinDiff itself.

            create_menu is the call that positions a submenu, and its default
            flags insert before the path given. Upstream names
            "View/Open subviews", so BinDiff lands immediately above it.

            Guarded rather than assumed present: create_menu is a thin wrapper
            in the SDK and a binding that does not export it should cost the
            submenu's position, not the whole plugin.
            """
            create_menu = getattr(ida_kernwin, "create_menu", None)
            if create_menu is None:
                return
            try:
                create_menu(f"bindiff:view_{PLUGIN_NAME.lower()}", PLUGIN_NAME,
                            "View/Open subviews")
            except Exception:
                # A failure here leaves the submenu where attaching puts it,
                # which is worse-looking and still works.
                pass

        # -- helpers --------------------------------------------------------

        def _invoke_action(self, name: str) -> None:
            """Runs a context-menu entry by action name.

            The panel used to hand the name to ida_kernwin.process_ui_action,
            which returned without running anything: the menu appeared, every
            entry was clickable, and clicking did nothing -- not even the
            "select one or more matches first" warning that an empty
            selection should produce. Silence in both directions is what made
            it look like a UI problem rather than a dispatch one.

            The handlers are in this object and the table is ours, so it calls
            them. An unknown name is reported rather than ignored, since the
            previous failure mode was precisely a click that went nowhere
            quietly.
            """
            handler = getattr(self, "_callbacks", {}).get(name)
            if handler is None:
                ida_kernwin.warning(
                    f"{PLUGIN_NAME}: no handler registered for {name!r}.")
                return
            handler()

        def _ensure_export_file(self, side: int) -> bool:
            """Makes sure the .BinExport file for one side is known, asking if not.

            A .BinDiff records matches and nothing else: the unmatched lists
            and every comment come out of the exports. The plugin can usually
            guess where they are from the result filename, but only when they
            sit beside it -- diffing two exports that live elsewhere defeats
            it, and the old behaviour was to give up with a message naming a
            file the user had never heard of.

            Asking is the honest response to not knowing. Declining leaves
            things exactly as they were.
            """
            if self.controller.resolve_binexports()[side] is not None:
                return True

            label = "primary" if side == 0 else "secondary"
            # The result file records what each input was called, so the
            # prompt can name the file it wants instead of asking for "the
            # secondary .BinExport" and leaving the user to work out which
            # that is and why anything needs it.
            wanted = self.controller.recorded_input_name(side)
            suggestion = f"{wanted}.BinExport" if wanted else "*.BinExport"
            ida_kernwin.info(
                f"{PLUGIN_NAME} needs the {label} .BinExport.\n\n"
                f"A .BinDiff records matches only. Unmatched functions and "
                f"every comment live in the exports, and this one is not "
                f"beside the result file.\n\n"
                f"Looking for: {suggestion}")
            path = ida_kernwin.ask_file(False, suggestion,
                                        f"Select {suggestion}")
            if not path:
                return False

            known = list(self.controller.resolve_binexports())
            known[side] = path
            self.controller.set_binexports(known[0], known[1])
            return True

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

        def _refresh_views(self) -> None:
            """Every view that an edit can change, refreshed together.

            Deleting a match and adding one are inverses and were not
            symmetric: adding refreshed the matched and unmatched lists,
            deleting refreshed only the matched one, so the two functions a
            delete frees never reappeared as unmatched. Statistics was
            refreshed by neither, though it derives "Matched" and "Unmatched"
            from the live match count and so moves on every edit.

            Only forms that are already open are touched -- an edit must not
            pop a window nobody asked for.
            """
            self._refresh_matches()
            self._refresh_unmatched()
            if self.controller._statistics_form is not None:
                self.controller._statistics_form.set_rows(
                    self.controller.statistic_rows())

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
            self._refresh_views()
            self._report(f"deleted {deleted} match(es); not yet saved")

        def _confirm_matches(self) -> None:
            ids = self._selected_match_ids()
            if not ids:
                return
            changed = self.controller.confirm_matches(ids)
            self._refresh_views()
            self._report(f"confirmed {changed} match(es); not yet saved")

        def _save_results(self) -> None:
            try:
                self.controller.save()
            except Exception as exc:
                ida_kernwin.warning(f"Could not save:\n{exc}")
                return
            self._report("saved")

        # -- porting --------------------------------------------------------

        def _ensure_types_sidecar(self) -> bool:
            """Makes sure the secondary's types have been read out.

            An export written by this plugin already has them: the worker
            writes the sidecar while the database is open, where reading 227
            types and 1,240 prototypes costs 0.0s against 0.9s for the open
            itself. This path is for a .BinExport produced some other way --
            BinExport's own menu, or an earlier version of this plugin -- and
            it pays for an idalib open that the export did not.
            """
            if self.controller.types_sidecar() is not None:
                return True

            from bindiff.typeinfo import types_path_for

            secondary = self.controller.resolve_binexports()[1]
            hint = Path(secondary).name if secondary else "the secondary"
            if ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_YES,
                    "HIDECANCEL\n"
                    f"{PLUGIN_NAME} has no types for {hint}.\n\n"
                    "A .BinExport cannot carry a type -- BinExport2 has no "
                    "type table -- so they have to be read out of the "
                    "database the export came from. It takes a few seconds "
                    "and is done once.\n\n"
                    "Exports written by this plugin already carry them; this "
                    "one was made some other way.\n\n"
                    "Read them now?") != ida_kernwin.ASKBTN_YES:
                return False

            # One mask or none: a list is read as a literal filename and
            # greys the dialog out. See ControlPanel._browse.
            database = ida_kernwin.ask_file(
                False, "*",
                "Select the secondary IDA database (.i64) to read types from")
            if not database:
                return False

            output = types_path_for(secondary) if secondary else \
                types_path_for(database)
            self._report(f"reading types from {Path(database).name}")
            self._run_types_worker(database, output)
            return False  # the worker reports; the caller retries

        def _run_types_worker(self, database: str, output: str) -> None:
            """Runs the type dump off the UI thread and reports when it lands."""
            import threading

            from bindiff.headless import run_headless

            def work() -> None:
                result = run_headless(["types", database, output],
                                      timeout=1800.0)

                def announce() -> int:
                    if result.ok:
                        self._report(f"types read: {result.message}. "
                                     "Import types again to apply them.")
                    else:
                        ida_kernwin.warning(
                            f"{PLUGIN_NAME}: could not read types.\n\n"
                            f"{result.message}")
                    return 1

                ida_kernwin.execute_sync(announce, ida_kernwin.MFF_FAST)

            threading.Thread(target=work, daemon=True).start()

        def _apply_types(self, match_ids) -> bool:
            """Defines the missing types, then applies the prototypes.

            Types first: a prototype naming a type the database does not have
            cannot be applied, which is the whole reason the plan is ordered.
            """
            from bindiff.typeinfo_ida import (apply_prototype,
                                              parse_declarations)

            try:
                plan, ports = self.controller.plan_type_ports(match_ids)
                if not ports:
                    from ida_plugin.porting import explain_symbol_port_skips
                    blocked = explain_symbol_port_skips(
                        self.controller.matches_for(match_ids),
                        overwrite_existing=True)
                    if self._ask_to_ignore_floors(blocked,
                                                  len(list(match_ids))):
                        plan, ports = self.controller.plan_type_ports(
                            match_ids, min_similarity=0.0, min_confidence=0.0)
            except FileNotFoundError as exc:
                self._report(f"types skipped: {exc}")
                return False

            defined = failed = 0
            if plan.statements:
                defined, failed = parse_declarations(plan.statements)

            applied = 0
            for address, declaration in ports:
                if apply_prototype(address, declaration):
                    applied += 1

            message = f"{applied} of {len(ports)} prototype(s) applied"
            if defined or failed:
                message += f"; defined {defined} type(s)"
                if failed:
                    message += f", {failed} failed to parse"
            if plan.unresolved:
                # A cycle through a by-value member. No ordering fixes it and
                # no retry count will either, so it is named rather than
                # silently dropped.
                message += (f"; {len(plan.unresolved)} type(s) could not be "
                            f"ordered: {', '.join(plan.unresolved[:3])}")
            self._report("types: " + message + "; not yet saved")
            return True

        def _import_types(self) -> None:
            """Prototypes and the types they need, and nothing else."""
            ids = self._selected_match_ids()
            if not ids:
                return
            if not self._ensure_types_sidecar():
                return
            self._apply_types(ids)
            self._refresh_matches()

        def _import_all(self) -> None:
            """Everything the other side knows about these functions.

            Names and comments first, then prototypes. The order matters for
            reading the log more than for correctness: a rename that fails is
            worth seeing before a prototype that depended on it.
            """
            ids = self._selected_match_ids()
            if not ids:
                return

            self._apply_ports(ids)
            if self.controller.types_sidecar() is None:
                # Ask once, and let the symbols and comments stand on their
                # own if the answer is no.
                if not self._ensure_types_sidecar():
                    return
            self._apply_types(ids)
            self._refresh_matches()

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

        def _ask_to_ignore_floors(self, skips: dict, total: int) -> bool:
            """Offers to import a selection the thresholds refused.

            The floors exist because porting everything at 0.0 wrote 516 wrong
            names out of 1,440 on the measured corpus. That is an argument
            about *bulk* porting: nobody read those matches. Hand-picking a
            handful of rows and choosing Import is the judgement the floor is
            standing in for, so being told "0 renamed" and left to work out
            why is the wrong answer.

            Only asked when the floor is the sole reason nothing happened.
            A selection skipped because there was no name to give has nothing
            to reconsider.
            """
            from ida_plugin.porting import DEFAULT_PORT_MIN_SIMILARITY

            blocked = skips.get("below the similarity or confidence floor", 0)
            if not blocked or blocked != total:
                return False
            return ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_NO,
                "HIDECANCEL\n"
                f"All {total} selected match(es) are below the porting "
                f"thresholds (similarity and confidence both "
                f"{DEFAULT_PORT_MIN_SIMILARITY}).\n\n"
                "Those defaults exist for importing in bulk, where nobody has "
                "read the matches. You have selected these by hand.\n\n"
                "Import them anyway?") == ida_kernwin.ASKBTN_YES

        def _apply_ports(self, match_ids):
            """Shared by the three import variants. Returns the symbol ports."""
            from ida_plugin.porting import (
                _is_generated_name, apply_comment_ports, apply_symbol_ports,
                explain_symbol_port_skips)

            # Overwrites an existing name, which is what upstream does --
            # its only guard is "already has the same name" -- and what
            # choosing this action asks for. Refusing to overwrite made the
            # action quietly do less than it said on exactly the functions
            # someone had already looked at and named.
            #
            # The similarity and confidence floors stay. They guard against a
            # different and measured problem: porting at 0.0 wrote 516 wrong
            # names out of 1440 on the corpus. That is about trusting a match,
            # not about respecting a name.
            floors = {}
            symbols = self.controller.plan_symbol_ports(
                match_ids, overwrite_existing=True)
            if not symbols:
                blocked = explain_symbol_port_skips(
                    self.controller.matches_for(match_ids),
                    overwrite_existing=True)
                if self._ask_to_ignore_floors(blocked, len(list(match_ids))):
                    floors = {"min_similarity": 0.0, "min_confidence": 0.0}
                    symbols = self.controller.plan_symbol_ports(
                        match_ids, overwrite_existing=True, **floors)
            symbol_result = apply_symbol_ports(symbols)
            # The result file records the names the differ saw. Leaving it
            # alone means the table keeps showing the old name for a function
            # that has just been renamed, and a result reopened later
            # contradicts the database it came from.
            self.controller.record_ported_names(symbols)
            replaced = sum(1 for port in symbols
                           if not _is_generated_name(port.old_name))
            # Whatever is still skipped is accounted for rather than silent.
            skips = explain_symbol_port_skips(
                self.controller.matches_for(match_ids),
                overwrite_existing=True,
                **{k: v for k, v in floors.items()})
            # One line per kind of thing. Crammed into one sentence it read
            # as "renamed 0 function(s); 30 skipped: already named the same,
            # 1 skipped: below the similarity or confidence floor; wrote 37
            # of 37 comment(s) ..." -- four clauses deep, leading with a zero,
            # and the question it was asked to answer (did the comments go?)
            # buried at the end.
            self._report("names: " + _describe_symbols(
                symbols, symbol_result, replaced, skips))
            # Comments live in the secondary export, so ask for it before
            # reporting that they were skipped for want of a file the user
            # could have supplied.
            self.controller.mark_imported(symbol_result.applied_matches)
            if not self._ensure_export_file(1):
                self._report("comments: skipped, no secondary .BinExport was "
                             "given and comments live there")
                self._refresh_matches()
                return symbols
            try:
                comments = self.controller.plan_comment_ports(
                    match_ids, **floors)
            except FileNotFoundError as exc:
                self._report(f"comments: skipped, {exc}")
                self._refresh_matches()
                return symbols
            comment_result = apply_comment_ports(comments)
            self.controller.mark_imported(symbol_result.applied_matches
                                          | comment_result.applied_matches)
            self._report("comments: "
                         + _describe_comments(comments, comment_result)
                         + "; not yet saved")
            # The names in the table came from the result file, which has just
            # changed, so redraw rather than leave it showing what used to be
            # true.
            self._refresh_matches()
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

            self._refresh_views()
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

        def _view_flow_graphs(self) -> None:
            """Shows the primary function's CFG, coloured by match state.

            Drawn with IDA's own graph widget rather than the Java UI: it docks
            like any other view and needs no second process.
            """
            from ida_plugin import panels

            rows = self._selected_rows()
            if len(rows) != 1:
                ida_kernwin.warning("Select exactly one match.")
                return
            if not getattr(panels, "GRAPH_AVAILABLE", False):
                ida_kernwin.warning(
                    "IDA's graph API is not available in this environment.")
                return
            try:
                self._graph_viewers.append(
                    panels.show_flow_graph_diff(rows[0],
                                                self.controller.database))
            except Exception as exc:
                ida_kernwin.warning(f"Could not build the graph:\n{exc}")

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
            # The same sentence import-all prints. Two wordings for one
            # action read as two different things having happened.
            self.controller.mark_imported(result.applied_matches)
            self._report("comments: " + _describe_comments(ports, result)
                         + "; not yet saved")
            self._refresh_views()

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
            # The unmatched list is derived from the export, not the result
            # file, so there is nothing to show without one.
            if not self._ensure_export_file(1 if secondary else 0):
                return
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
                # The side decides which actions apply: "add match" and
                # "copy address" mean different things on each, and the
                # registered actions are already per-side.
                if secondary:
                    actions = (ACTION_UNMATCHED_ADD_MATCH_SECONDARY,
                               ACTION_UNMATCHED_COPY_SECONDARY)
                else:
                    actions = (ACTION_UNMATCHED_ADD_MATCH_PRIMARY,
                               ACTION_UNMATCHED_COPY_PRIMARY)
                form = UnmatchedFunctionsForm(
                    rows, side, on_jump=None if secondary else _jump_to,
                    context_actions=actions, on_action=self._invoke_action)
                self.controller._unmatched_forms[side] = form
            else:
                form.set_rows(rows)
            form.Show()

        def _show_primary_unmatched(self) -> None:
            self._show_unmatched(secondary=False)

        def _show_secondary_unmatched(self) -> None:
            self._show_unmatched(secondary=True)

        # -- diffing --------------------------------------------------------

        def _binexport_plugin_dirs(self):
            """Every directory IDA loads native plugins from.

            The user directory first: it is writable without touching the
            installation, and it is where an install here belongs.
            """
            import ida_diskio

            dirs = []
            user = ida_diskio.get_user_idadir()
            if user:
                dirs.append(Path(user) / "plugins")
            try:
                dirs.append(Path(ida_diskio.idadir("plugins")))
            except Exception:
                # idadir is not worth failing a diff over; the user directory
                # is the one that matters for an install.
                pass
            return dirs

        def _ensure_binexport_plugin(self) -> bool:
            """True if the export can go ahead. Offers to fetch BinExport.

            The exporter is a native IDA plugin, not a Python package, so pip
            cannot place it and `pythonDependencies` has nowhere to name it.
            Fetching it is therefore the plugin's job -- but downloading a
            binary and putting it where IDA will load it is not something to
            do silently, so it is offered, with the URL shown, and never done
            without an answer.

            Nothing needs restarting afterwards. The export runs in a separate
            idalib worker process which starts fresh and finds the plugin on
            disk; only this GUI process would need a restart, and it is not the
            one doing the exporting.
            """
            from bindiff import binexport_installer as installer
            from bindiff import __version__

            directories = self._binexport_plugin_dirs()
            if installer.find_installed(directories):
                return True

            try:
                plan = installer.plan(directories[0], __version__)
            except installer.Unsupported as exc:
                ida_kernwin.warning(
                    f"BinExport is needed to export a binary, and {exc}.\n\n"
                    "Build it from google/binexport and put "
                    f"{installer.plugin_name_for()} in {directories[0]}.")
                return False

            answer = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                "HIDECANCEL\n"
                "Diffing two binaries needs the BinExport plugin, which is "
                "not installed.\n\n"
                f"Download it from\n{plan.archive_url}\n"
                f"and install it as\n{plan.destination}?\n\n"
                "The archive is checked against the digest published with the "
                "release before anything is written.")
            if answer != ida_kernwin.ASKBTN_YES:
                self._report("BinExport was not installed; the diff needs it "
                             "to export a binary.")
                return False

            return self._install_binexport(plan)

        def _install_binexport(self, plan) -> bool:
            """Downloads and installs, on this thread, reporting the outcome.

            Synchronous on purpose. It is roughly a megabyte, it happens once,
            and the user has just been asked and said yes -- so a brief pause
            is the honest thing rather than a progress panel for something
            that is over before it could be read. A diff, which takes minutes,
            is the case that earns the out-of-process machinery.
            """
            import json
            import urllib.request

            from bindiff import binexport_installer as installer

            def fetch(url: str) -> bytes:
                with urllib.request.urlopen(url, timeout=120) as response:
                    return response.read()

            try:
                written = installer.fetch_and_install(plan, fetch, json.loads)
            except installer.Corrupt as exc:
                ida_kernwin.warning(
                    f"The BinExport download did not verify:\n\n{exc}\n\n"
                    "Nothing was installed.")
                return False
            except Exception as exc:  # network, permissions, a 404 on the tag
                ida_kernwin.warning(
                    f"Could not install BinExport:\n\n{exc}\n\n"
                    f"Download {plan.archive_url} by hand and put "
                    f"{plan.plugin_name} in {plan.destination.parent}.")
                return False

            self._report(f"installed BinExport at {written}")
            return True

        def _diff_database(self, secondary: Optional[str] = None) -> None:
            """Runs a diff against another binary, out of process.

            The export is what makes this slow, and it is why the C++ plugin
            freezes the IDB: it exports the secondary from inside this process.
            Here a worker does both exports and the diff, so the UI stays live.
            """
            # Checked before anything is asked for: finding out that the
            # exporter is missing after picking two files and a destination
            # wastes the answers.
            if not self._ensure_binexport_plugin():
                return

            if not secondary:
                # "*" and not "*.*": the latter requires a dot in the name,
                # so a stripped ELF with no extension is not selectable.
                secondary = ida_kernwin.ask_file(
                    False, "*", "Select the secondary binary or database")
            if not secondary:
                return

            from ida_plugin.diff_runner import reject_reason

            refusal = reject_reason(secondary)
            if refusal:
                ida_kernwin.warning(
                    f"{refusal}\n\n"
                    "Diff against the other side of the comparison: its "
                    "binary, its .i64 database, or its .BinExport.\n\n"
                    "Your open database is always the primary and is "
                    "exported again for every diff, so names, comments and "
                    "types you have imported since the last one are already "
                    "included. To re-diff after importing, pick the same "
                    "secondary as before -- its .BinExport is quickest, "
                    "since it needs no export at all.")
                return

            primary = self._primary_to_export()
            if not primary:
                ida_kernwin.warning(
                    "This database has never been saved and there is no input "
                    "file to fall back on, so there is nothing to export.")
                return
            from ida_plugin.diff_runner import default_output_name

            output = ida_kernwin.ask_file(
                True, default_output_name(primary, secondary),
                "Save results as")
            if not output:
                return

            self._report("diffing in a background process; the UI stays "
                         "responsive. This can take a while.")
            self._run_diff_async(primary, secondary, output)

        def _primary_to_export(self):
            """The file the worker exports for this side of the diff.

            The saved database, not the input binary. Handing over the binary
            makes the worker re-analyse it from scratch, which discards
            everything the database holds that the bytes do not -- names,
            types, and whatever a deobfuscation pass rewrote. The export still
            succeeds and the diff still succeeds; the answer is simply about a
            program nobody was looking at, which is the worst way for this to
            be wrong.

            Offers to save first, because the snapshot can only carry what has
            been written. Declining is allowed and says what it costs.
            """
            import ida_loader

            from ida_plugin.diff_runner import primary_export_source

            if ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_YES,
                    "HIDECANCEL\nSave the database first?\n\n"
                    "The diff exports a copy of the saved database, so "
                    "anything not written yet will be missing from it."
            ) == ida_kernwin.ASKBTN_YES:
                ida_loader.save_database(
                    ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)

            return primary_export_source(
                ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
                ida_nalt.get_input_file_path())

        @staticmethod
        @contextlib.contextmanager
        def _snapshot(primary: str):
            """A copy of the database for the worker to open, or the path
            itself when it is not a database.

            IDA holds the open .i64, and a second process opening it is at
            best refused and at worst two writers on one file. Copying is
            cheap next to what follows -- it is I/O against a re-analysis --
            and it runs on the diff's own thread, so the UI never waits for it.
            """
            import shutil
            import tempfile

            source = Path(primary)
            if source.suffix.lower() not in (".idb", ".i64"):
                yield primary
                return

            # A temporary directory holding a file with the *real* name,
            # rather than a temporary file with an invented one. BinExport
            # records the filename it was given, so mkstemp's name ended up
            # in the .BinExport, in the .BinDiff's file table and on screen
            # in Statistics as "bindiff-primary-oa1ywul8.primary". It also
            # defeated finding the exports again later, since that works from
            # the names.
            holder = tempfile.mkdtemp(prefix="bindiff-snapshot-")
            target = str(Path(holder) / source.name)
            try:
                shutil.copyfile(source, target)
                yield target
            finally:
                # A leftover copy of someone's database is not a small
                # mess, so it goes even if the diff raised.
                shutil.rmtree(holder, ignore_errors=True)

        def _run_diff_async(self, primary: str, secondary: str,
                            output: str) -> None:
            """Wires the real collaborators into DiffRun and starts it.

            The sequence itself lives in ida_plugin.diff_runner, which has no
            Qt and no IDA in it, so the harness can drive it. What is left here
            is only the wiring: the panel, the marshal to the UI thread, and
            the thread.
            """
            import functools
            import threading

            from bindiff.headless import run_headless
            from ida_plugin.diff_runner import (DEFAULT_TIMEOUT_SECONDS,
                                                DiffRun, panel_title,
                                                worker_arguments)
            from ida_plugin.panels import DiffProgressForm

            cancel = threading.Event()
            # Kept so the control panel's Cancel can reach this diff.
            self._cancel_event = cancel

            # Report into the control panel when it is open, so a diff started
            # from it does not open a second window to watch. The standalone
            # progress form is still the answer for a diff started from a
            # menu, which is the case the control panel is not part of.
            panel = self._control_panel
            if panel is not None and panel.parent is not None:
                panel.start(panel_title(primary))
                form = panel
            else:
                form = DiffProgressForm(panel_title(primary),
                                        on_cancel=cancel.set)
                form.Show()

            def post(action, flags) -> None:
                # Touching Qt or IDA from the worker thread is not safe.
                # execute_sync hands the call to the UI thread and blocks until
                # it has run. It wants an int back, which the actions do not
                # return.
                def wrapped() -> int:
                    action()
                    return 1

                ida_kernwin.execute_sync(wrapped, flags)

            def load(path: str, exports: Sequence[str] = ()) -> None:
                self.controller.open_database(path)
                # Recorded rather than guessed. open_database clears them, so
                # this has to come after it.
                if len(exports) == 2:
                    self.controller.set_binexports(exports[0], exports[1])
                self._show_matches()
                self._sync_control_panel()

            def runner(args, **kwargs):
                # Both sides are copied, and here rather than in
                # _diff_database so the copying happens on this thread instead
                # of the UI's. The secondary needs it as much as the primary:
                # an .i64 open in another IDA is locked, idalib's
                # open_database returns non-zero for it, and that surfaced as
                # a bare "could not open <path>" with nothing to do about it.
                with self._snapshot(args[1]) as primary_source, \
                        self._snapshot(args[2]) as secondary_source:
                    return run_headless(
                        [args[0], primary_source, secondary_source,
                         *args[3:]],
                        timeout=DEFAULT_TIMEOUT_SECONDS, **kwargs)

            run = DiffRun(
                runner=runner,
                panel=form,
                # Progress repaints must not queue behind a database lock the
                # user's own analysis is holding; the single final call loads a
                # file and opens windows, so it takes the stronger flag.
                post_progress=functools.partial(
                    post, flags=ida_kernwin.MFF_FAST),
                post_result=functools.partial(
                    post, flags=ida_kernwin.MFF_WRITE),
                report=self._report,
                warn=ida_kernwin.warning, load=load)

            threading.Thread(
                target=run.execute,
                args=(worker_arguments(primary, secondary, output), output,
                      cancel),
                daemon=True).start()

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
            self._sync_control_panel()

        def _show_matches(self) -> None:
            if not self._require_results():
                return
            from ida_plugin.panels import MatchedFunctionsForm

            if self.controller._matched_form is None:
                self.controller._matched_form = MatchedFunctionsForm(
                    self.controller.match_rows(), on_jump=_jump_to,
                    context_actions=(
                        ACTION_VIEW_FLOW_GRAPHS,
                        None,
                        ACTION_IMPORT_ALL,
                        ACTION_IMPORT_SYMBOLS_COMMENTS,
                        ACTION_IMPORT_TYPES,
                        ACTION_PORT_COMMENTS,
                        None,
                        ACTION_CONFIRM_MATCHES,
                        ACTION_DELETE_MATCHES,
                        None,
                        ACTION_COPY_PRIMARY_ADDRESS,
                        ACTION_COPY_SECONDARY_ADDRESS,
                    ),
                    on_action=self._invoke_action)
                self.controller._matched_form.Show()
            else:
                self.controller._matched_form.set_rows(
                    self.controller.match_rows())
                self.controller._matched_form.Show()

        def _show_statistics(self) -> None:
            if not self._require_results():
                return
            from ida_plugin.panels import StatisticsForm

            rows = self.controller.statistic_rows()
            if self.controller._statistics_form is None:
                self.controller._statistics_form = StatisticsForm(rows)
            else:
                self.controller._statistics_form.set_rows(rows)
            self.controller._statistics_form.Show()

        def _configure_algorithms(self) -> None:
            import bindiff

            from ida_plugin.panels import AlgorithmConfigDialog

            def apply(changes: dict) -> None:
                bindiff.set_config(changes)
                ida_kernwin.msg(
                    f"[{PLUGIN_NAME}] matching configuration updated; "
                    f"it applies to the next diff\n")

            from bindiff.qt_shim import exec_widget

            exec_widget(
                AlgorithmConfigDialog(bindiff.get_config(), apply))

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
