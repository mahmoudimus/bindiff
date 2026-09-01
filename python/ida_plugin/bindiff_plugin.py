"""BinDiff plugin for IDA Pro.

Six PluginForms and four ida_kernwin.Choose lists collapsed into one dock tab
and its companion inspector. The choosers could not filter, could not sort on
anything but the column IDA happened to give them, and could not show two
values side by side without string padding; the six forms each carried their
own copy of what was open and each learned about a change separately.

Structure:

    ui_logic.py, trust.py, query.py, lenses.py, inspection.py, theme.py
                  pure view logic, no Qt and no IDA -- tested headless
    controller.py the data layer over the .BinDiff and the exports
    session.py    DiffSession: the one owner of every fact the UI shows
    panels.py     the two tables, the flow graph, the algorithm editor
    workbench.py  the dock tab that is the plugin; inspector.py its companion
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
from typing import Optional, Sequence

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

from ida_plugin.controller import BinDiffController, _describe_comments  # noqa: E402,F401


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


if IDA_AVAILABLE:
    from ida_plugin import session as actions
    from ida_plugin.porting import (DEFAULT_PORT_MIN_CONFIDENCE,
                                    DEFAULT_PORT_MIN_SIMILARITY, PortLedger)
    from ida_plugin.session import DiffSession, State
    from ida_plugin.ui_logic import (STATE_IMPORTED, STATE_PORTED,
                                     STATE_REPLACED)

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

        def __init__(self, callback) -> None:
            super().__init__()
            self._callback = callback

        def activate(self, ctx) -> int:
            self._callback()
            return 1

        def update(self, ctx) -> int:
            """Always available, as far as IDA is concerned.

            Availability is the session's answer and it changes constantly:
            what is selected, whether a result is open, whether a comparison
            is running. IDA's own action state cannot express that. The
            _ALWAYS variants mean what they say -- IDA records the answer and
            stops asking -- so an action reported unavailable *yet* stayed
            unavailable for the life of the session, which is what left four
            views permanently greyed.

            So every action is enabled here and every handler asks the
            session first, reporting one line when the answer is no.
            """
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
            # One session over that one controller. Every view reads it and
            # every handler writes through it; nothing here keeps a second
            # copy of what is open.
            self.session = DiffSession(self.controller)
            self.workbench = None
            self.inspector = None
            self._registered: list = []
            # Kept alive: a GraphViewer that is garbage collected takes its
            # window with it.
            self._graph_viewers: list = []
            self._cancel_event = None
            self._autosave_timer = None
            # The worker's StageResult, so `load` can tell a partial result
            # from a complete one. Set on the diff thread, read on the UI
            # thread after the worker has returned.
            self._last_result = None

        # -- lifecycle ------------------------------------------------------

        def init(self):
            from ida_plugin.workbench import AUTOSAVE_SECONDS

            self._register_actions()
            # The strip's toggle starts checked and only *reports* changes, so
            # unless the timer is started here the default is a tick nobody
            # made and a checkbox that lies.
            self._set_autosave(True, AUTOSAVE_SECONDS)
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
            self._open_workbench()
            return True

        # -- the two forms ---------------------------------------------------

        def handlers(self) -> dict:
            """The contract between this object and the two forms.

            One dict, handed to both: a form calls a key, this object decides
            whether the session permits it and does it. Nothing in a form
            reaches into the controller, and nothing here reaches into a
            widget except through the two entry points below.
            """
            return {
                "compare": self._compare,
                "cancel": self._cancel,
                "browse": self._browse,
                "configure": self._configure,
                "save": self._save,
                "close": self._close,
                "unmatch": self._unmatch,
                "verify": self._verify,
                "port": self._port,
                "restore_name": self._restore_name,
                "pair": self._pair,
                "graphs": self._graphs,
                "inspect": self._inspect,
                "copy_here": lambda: self._copy(0),
                "copy_there": lambda: self._copy(1),
                "locate_export": self._locate_export,
                "jump": _jump_to,
                "autosave": self._set_autosave,
                "threshold": (lambda t: self.inspector.set_threshold(t)
                              if self.inspector is not None else None),
            }

        def _the_workbench(self):
            """The dock tab, created on first use and kept.

            Kept rather than rebuilt: it is the subscriber list on the
            session, and a second one would draw the same result twice.
            """
            from ida_plugin.workbench import Workbench

            if self.workbench is None:
                self.workbench = Workbench(self.session, self.handlers())
            return self.workbench

        def _open_workbench(self) -> None:
            self._the_workbench().show_scope("matches")

        def _show_scope(self, key: str) -> None:
            self._the_workbench().show_scope(key)

        def _inspect(self) -> None:
            if not self._allowed(actions.INSPECT):
                return
            from ida_plugin.inspector import InspectorForm

            if self.inspector is None:
                self.inspector = InspectorForm(self.session, self.handlers())
            self.inspector.Show()

        # -- actions --------------------------------------------------------

        def _register_actions(self) -> None:
            specs = (
                (ACTION_MAIN, PLUGIN_NAME, self._open_workbench),
                (ACTION_DIFF_DATABASE, "Compare with…", self._compare_from_menu),
                (ACTION_LOAD, "Open result…", self._load_results),
                (ACTION_SAVE, "Save result", self._save),
                (ACTION_SHOW_MATCHES, "Matched functions",
                 lambda: self._show_scope("matches")),
                (ACTION_SHOW_PRIMARY_UNMATCHED, "Only here (primary unmatched)",
                 lambda: self._show_scope("only_here")),
                (ACTION_SHOW_SECONDARY_UNMATCHED,
                 "Only there (secondary unmatched)",
                 lambda: self._show_scope("only_there")),
                (ACTION_SHOW_STATISTICS, "Overview (statistics)",
                 lambda: self._show_scope("overview")),
                (ACTION_DELETE_MATCHES, "Unmatch", self._unmatch),
                (ACTION_CONFIRM_MATCHES, "Verify", self._verify),
                (ACTION_IMPORT_ALL, "Port name, comments and types",
                 self._import_all),
                (ACTION_IMPORT_TYPES, "Port types", self._import_types),
                (ACTION_IMPORT_SYMBOLS_COMMENTS, "Port name + comments",
                 self._port_selected),
                (ACTION_IMPORT_SYMBOLS_COMMENTS_EXTERNAL,
                 "Port name + comments as library code", self._port_external),
                (ACTION_IMPORT_SYMBOLS_COMMENTS_GLOBAL, "Port every match…",
                 self._port_global),
                (ACTION_UNMATCHED_ADD_MATCH_PRIMARY, "Pair", self._pair),
                (ACTION_UNMATCHED_ADD_MATCH_SECONDARY, "Pair", self._pair),
                (ACTION_UNMATCHED_COPY_PRIMARY, "Copy address",
                 lambda: self._copy_unmatched(0)),
                (ACTION_UNMATCHED_COPY_SECONDARY, "Copy address",
                 lambda: self._copy_unmatched(1)),
                (ACTION_PORT_COMMENTS, "Port comments only", self._port_comments),
                (ACTION_COPY_PRIMARY_ADDRESS, "Copy address here",
                 lambda: self._copy(0)),
                (ACTION_COPY_SECONDARY_ADDRESS, "Copy address there",
                 lambda: self._copy(1)),
                (ACTION_VIEW_FLOW_GRAPHS, "Flow graphs", self._graphs),
                (ACTION_CONFIGURE, "Matching algorithms…", self._configure),
            )
            # Shift-D is the C++ plugin's, for the same action. Someone
            # arriving from it should not have to learn a new key to open the
            # same thing.
            shortcuts = {ACTION_MAIN: "Shift-D",
                         ACTION_LOAD: "Ctrl-Shift-6"}

            for name, label, callback in specs:
                if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                        name, label, _Action(callback), shortcuts.get(name))):
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

        def _report(self, message: str) -> None:
            ida_kernwin.msg(f"[{PLUGIN_NAME}] {message}\n")

        def _allowed(self, action: str) -> bool:
            """Whether the session permits this now, with a line when it does not.

            One line in the output window rather than a modal: an action that
            is not available yet is not an error, and a dialog for it is a
            click whose only content is "oh".
            """
            if self.session.can(action):
                return True
            self._report(self._why_not(action))
            return False

        def _why_not(self, action: str) -> str:
            """The one thing that is missing, named."""
            session = self.session
            if action == actions.CANCEL:
                return "no comparison is running"
            if session.state is State.COMPARING:
                return "a comparison is running"
            if action == actions.SAVE and session.is_open:
                return "there is nothing unsaved"
            if not session.is_open:
                return "no result is open"
            if action in (actions.GRAPHS, actions.INSPECT):
                return "select exactly one match first"
            if action == actions.PAIR:
                return ("choose one function under Only here and one under "
                        "Only there first")
            if action == actions.RESTORE_NAME:
                return "nothing was written to that match this session"
            return "select one or more matches first"

        def _ordered_selection(self) -> list:
            """The selected match ids, in the order they are on screen.

            The session owns *what* is selected; only the table knows the
            order it is drawn in, and a copied block of addresses that does
            not match the rows it was copied from is worse than useless.
            """
            if self.workbench is not None and self.workbench.parent is not None:
                shown = self.workbench.selected_ids()
                if shown:
                    return list(shown)
            return list(self.session.selected_ids)

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

        def _locate_export(self, side: int) -> None:
            """The Locate button on an unmatched scope with no export."""
            if not self._allowed(actions.LOCATE_EXPORT):
                return
            if not self._ensure_export_file(side):
                return
            # Rebuilds the counts without reopening: reopening would clear
            # the edits and the ledger, and the result is the same one.
            self.session.exports_located()
            self._report(f"found the {'primary' if side == 0 else 'secondary'}"
                         " export; the counts are up to date")

        # -- editing --------------------------------------------------------

        def _unmatch(self) -> None:
            if not self._allowed(actions.UNMATCH):
                return
            ids = list(self.session.selected_ids)
            count = self.session.unmatch(ids)
            self._report(f"unmatched {count} match(es); not yet saved")

        def _verify(self) -> None:
            if not self._allowed(actions.VERIFY):
                return
            ids = list(self.session.selected_ids)
            count = self.session.verify(ids)
            self._report(f"verified {count} match(es); not yet saved")

        def _pair(self) -> None:
            if not self._allowed(actions.PAIR):
                return
            here = self.session.chosen_unmatched[0]
            there = self.session.chosen_unmatched[1]
            try:
                self.session.pair(here, there)
            except ValueError as exc:
                ida_kernwin.warning(str(exc))
                return
            self._report(f"matched 0x{here:X} to 0x{there:X}; not yet saved")

        def _save(self) -> None:
            if not self._allowed(actions.SAVE):
                return
            try:
                self.session.save()
            except Exception as exc:
                ida_kernwin.warning(f"Could not save:\n{exc}")
                return
            self._report("saved")

        def _close(self) -> None:
            """Closes the result, asking only when that would lose something.

            The one confirmation in the interface. Everything else here is
            either reversible or reported; unsaved edits are neither, so the
            question names how many there are rather than asking whether the
            user is sure.
            """
            if not self._allowed(actions.CLOSE):
                return
            if self.session.state is State.OPEN_EDITED:
                if ida_kernwin.ask_yn(
                        ida_kernwin.ASKBTN_NO,
                        f"Close with {self.session.edits} unsaved edit(s)?"
                        "\n\nSave first to keep them."
                ) != ida_kernwin.ASKBTN_YES:
                    return
            self.session.close_result()
            self._report("closed")

        # -- porting --------------------------------------------------------

        def _port(self, threshold: float, ids, *,
                  floors_for_comments=None) -> Optional[PortLedger]:
            """Names and comments for these matches, at this threshold.

            The preview decides; the ledger records; the session tells the
            views. Types are separate (they have their own sidecar).

            Not guarded on can(PORT): the footer ports what is *on screen*
            when nothing is picked, which is the flagship path and has no
            selection by definition. What has to be true is that there is a
            result and something to write to.
            """
            from ida_plugin.porting import (apply_comment_ports, apply_symbol_ports,
                                            build_ledger, preview_symbol_ports)

            ids = list(ids)
            if not self.session.is_open or not ids:
                self._report("nothing to port: " + ("no result is open"
                                                    if not self.session.is_open
                                                    else "nothing is selected"))
                return None

            # A threshold of 0.0 is the inspector's "I have read this pair and
            # I want it": the block-coverage floor is the same judgement made
            # in bulk, so it goes too. Both the preview and the comments read
            # the one number, or they disagree about the same pair.
            confidence = (floors_for_comments if floors_for_comments is not None
                          else (0.0 if threshold == 0.0
                                else DEFAULT_PORT_MIN_CONFIDENCE))
            controller = self.session.controller
            matches = controller.matches_for(ids)
            preview = preview_symbol_ports(matches, min_similarity=threshold,
                                           min_confidence=confidence)
            symbols = apply_symbol_ports(preview.ports)
            controller.record_ported_names(preview.ports)
            comments = None
            planned = ()
            if self._ensure_export_file(1):
                try:
                    planned = controller.plan_comment_ports(
                        ids, min_similarity=threshold,
                        min_confidence=confidence)
                except FileNotFoundError as exc:
                    self._report(f"comments skipped: {exc}")
                else:
                    comments = apply_comment_ports(planned)
            ledger = build_ledger(preview, symbols, comments)
            self.session.note_ports(ledger)
            message = "names: " + ledger.summary()
            if comments is not None:
                message += "; comments: " + _describe_comments(planned, comments)
            if preview.below_threshold:
                message += (f"; {len(preview.below_threshold)} below the "
                            f"{threshold:.2f} threshold -- drag the footer slider or "
                            f"port one from the inspector")
            self._report(message + "; not yet saved")
            # Both write into IDA rather than into the .BinDiff, so they are
            # outside the ledger: there is no port outcome to record and
            # nothing for the table to show. Each reports its own line and
            # neither is allowed to fail the import.
            self._apply_pseudocode_comments(ids)
            self._apply_stack_names(ids)
            return ledger

        def _port_selected(self) -> None:
            if not self._allowed(actions.PORT):
                return
            self._port(DEFAULT_PORT_MIN_SIMILARITY, self.session.selected_ids)

        def _port_external(self) -> None:
            """Ports, then marks the primary functions as library code."""
            from ida_plugin.porting import mark_as_library

            if not self._allowed(actions.PORT):
                return
            ledger = self._port(DEFAULT_PORT_MIN_SIMILARITY,
                                self.session.selected_ids)
            if ledger is None:
                return
            # Only what was really written: marking a function whose rename
            # IDA refused says something about this database that is not true.
            addresses = [entry.address for entry in ledger
                         if entry.outcome in (STATE_PORTED, STATE_REPLACED)]
            marked = mark_as_library(addresses)
            self._report(f"marked {marked.applied} function(s) as library code")

        def _port_global(self) -> None:
            """Every match, not the selection."""
            if not self.session.is_open:
                self._report("no result is open")
                return
            ids = [row.match_id for row in self.session.rows()]
            if ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_NO,
                    f"Port names and comments for all {len(ids)} matches?\n\n"
                    f"Only matches at or above the {DEFAULT_PORT_MIN_SIMILARITY:.2f} "
                    "similarity floor are written."
            ) != ida_kernwin.ASKBTN_YES:
                return
            self._port(DEFAULT_PORT_MIN_SIMILARITY, ids)

        def _port_comments(self) -> None:
            """Comments and nothing else, for the selection."""
            from ida_plugin.porting import LedgerEntry, apply_comment_ports

            if not self._allowed(actions.PORT):
                return
            ids = list(self.session.selected_ids)
            if not self._ensure_export_file(1):
                self._report("comments skipped: no secondary .BinExport was "
                             "given, and comments live there")
                return
            try:
                planned = self.session.controller.plan_comment_ports(ids)
            except FileNotFoundError as exc:
                ida_kernwin.warning(str(exc))
                return
            result = apply_comment_ports(planned)
            # Recorded as "imported" rather than as a port outcome: no name
            # was written, so there is nothing to restore, but something did
            # land in this database and the row has to say so.
            delta = PortLedger()
            for match_id in sorted(result.applied_matches):
                delta.record(LedgerEntry(match_id, STATE_IMPORTED, 0, "", "",
                                         comments_written=1))
            self.session.note_ports(delta)
            self._report("comments: " + _describe_comments(planned, result)
                         + "; not yet saved")
            self._apply_pseudocode_comments(ids)
            self._apply_stack_names(ids)

        def _restore_name(self) -> None:
            """Puts back the name this session replaced, one row at a time."""
            from ida_plugin.porting import apply_symbol_ports

            if not self._allowed(actions.RESTORE_NAME):
                return
            match_id = self.session.current_id
            reverse = self.session.ledger.reversal(match_id)
            if reverse is None:
                return
            apply_symbol_ports([reverse])
            self.session.controller.record_ported_names([reverse])
            self.session.forget_port(match_id)
            self._report(f"restored {reverse.new_name}")

        # -- types ----------------------------------------------------------

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
            # greys the dialog out. See RunStrip._browse.
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

        def _apply_stack_names(self, match_ids) -> None:
            """Stack variable names -- upstream issue #13.

            Never fails an import. The names are an extra: an export made
            before this existed, or a frame API this build spells
            differently, must not cost the names and comments that did go
            across.
            """
            from bindiff.stack_names_ida import Unavailable, apply_stack_names

            try:
                ports = self.controller.plan_stack_name_ports(match_ids)
            except FileNotFoundError:
                return
            except Exception as exc:
                self._report(f"stack variables: skipped, {exc}")
                return
            if not ports:
                return
            try:
                result = apply_stack_names(ports)
            except (Unavailable, RuntimeError) as exc:
                self._report(f"stack variables: skipped, {exc}")
                return

            message = f"stack variables: {result.applied} renamed"
            if result.replaced:
                message += f" ({result.replaced} replaced an existing name)"
            if result.refused:
                # rename_udm really does refuse, unlike set_name, and it is
                # nearly always a name already taken in the same frame --
                # which is information, not a mishap.
                message += (f", {result.refused} refused: the name is "
                            f"already used in that frame")
            if result.unresolved:
                message += (f", {result.unresolved} operand(s) are not stack "
                            f"variables in this database")
            self._report(message)

        def _apply_pseudocode_comments(self, match_ids) -> None:
            """The comments Hex-Rays keeps, not the ones IDA keeps.

            Reported only when there is something to report. On a real
            database these are rare -- 4 across 10,435 functions on the pair
            this was built for -- and a line saying so after every import
            would be noise on the one number that is almost always zero.

            Never fails an import: the decompiler is licensed separately, the
            sidecar may predate this, and neither is a reason to lose the
            comments and names that did go across.
            """
            from bindiff.pseudocode_ida import apply_pseudocode_comments

            try:
                ports = self.controller.plan_pseudocode_ports(match_ids)
            except FileNotFoundError:
                return
            except Exception as exc:
                self._report(f"pseudocode comments: skipped, {exc}")
                return
            if not ports:
                return
            written, refused = apply_pseudocode_comments(ports)
            message = f"pseudocode comments: {written} of {len(ports)} written"
            if refused:
                # Hex-Rays takes any treeloc and drops the ones that do not
                # land on a ctree item, so this is counted after decompiling
                # rather than from what the write returned.
                message += (f", {refused} did not attach to a line in this "
                            f"database")
            self._report(message)

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

        def _ask_to_ignore_floors(self, skips: dict, total: int) -> bool:
            """Offers to import a selection the thresholds refused.

            The floors exist because porting everything at 0.0 wrote 516 wrong
            names out of 1,440 on the measured corpus. That is an argument
            about *bulk* porting: nobody read those matches. Hand-picking a
            handful of rows and choosing Port is the judgement the floor is
            standing in for, so being told "0 renamed" and left to work out
            why is the wrong answer.

            Only asked when the floor is the sole reason nothing happened.
            A selection skipped because there was no name to give has nothing
            to reconsider.
            """
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

        def _import_types(self) -> None:
            """Prototypes and the types they need, and nothing else."""
            if not self._allowed(actions.PORT):
                return
            ids = list(self.session.selected_ids)
            if not self._ensure_types_sidecar():
                return
            self._apply_types(ids)

        def _import_all(self) -> None:
            """Everything the other side knows about these functions.

            Names and comments first, then prototypes. The order matters for
            reading the log more than for correctness: a rename that fails is
            worth seeing before a prototype that depended on it.
            """
            if not self._allowed(actions.PORT):
                return
            ids = list(self.session.selected_ids)
            self._port(DEFAULT_PORT_MIN_SIMILARITY, ids)
            if self.controller.types_sidecar() is None:
                # Ask once, and let the names and comments stand on their own
                # if the answer is no.
                if not self._ensure_types_sidecar():
                    return
            self._apply_types(ids)

        # -- clipboard ------------------------------------------------------

        def _copy(self, side: int) -> None:
            """The picked addresses on one side, to the clipboard."""
            if not self.session.can(actions.COPY):
                # The unmatched scopes route their Copy here too, where there
                # is no match selection and the row under the cursor is what
                # was asked for.
                self._copy_unmatched(side)
                return
            addresses = []
            for match_id in self._ordered_selection():
                row = self.session.row(match_id)
                if row is not None:
                    addresses.append(row.address_secondary if side
                                     else row.address_primary)
            self._to_clipboard(addresses)

        def _copy_unmatched(self, side: int) -> None:
            chosen = self.session.chosen_unmatched.get(side)
            if chosen is None:
                self._report("select a function first")
                return
            self._to_clipboard([chosen])

        def _to_clipboard(self, addresses: Sequence[int]) -> None:
            if not addresses:
                self._report("nothing to copy")
                return
            from bindiff.qt_shim import QtWidgets

            QtWidgets.QApplication.clipboard().setText(
                "\n".join(f"0x{address:X}" for address in addresses))
            self._report(f"copied {len(addresses)} address(es)")

        # -- graphs ---------------------------------------------------------

        def _graphs(self) -> None:
            """Shows the primary function's CFG, coloured by match state.

            Drawn with IDA's own graph widget rather than the Java UI: it docks
            like any other view and needs no second process.
            """
            from ida_plugin import panels

            if not self._allowed(actions.GRAPHS):
                return
            row = self.session.row(self.session.current_id)
            if row is None:
                self._report("that match is no longer in the result")
                return
            if not getattr(panels, "GRAPH_AVAILABLE", False):
                ida_kernwin.warning(
                    "IDA's graph API is not available in this environment.")
                return
            try:
                self._graph_viewers.append(
                    panels.show_flow_graph_diff(row, self.controller.database))
            except Exception as exc:
                ida_kernwin.warning(f"Could not build the graph:\n{exc}")

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
                "Comparing two binaries needs the BinExport plugin, which is "
                "not installed.\n\n"
                f"Download it from\n{plan.archive_url}\n"
                f"and install it as\n{plan.destination}?\n\n"
                "The archive is checked against the digest published with the "
                "release before anything is written.")
            if answer != ida_kernwin.ASKBTN_YES:
                self._report("BinExport was not installed; the comparison "
                             "needs it to export a binary.")
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

        def _browse(self):
            """What this object has to offer for the other side: nothing.

            The run strip asks here first and falls back to IDA's own file
            dialog when the answer is None, which is what the harness drives.
            It is also where a picker that knows about recent results would
            go.
            """
            return None

        def _compare_from_menu(self) -> None:
            """The menu's way in, which is the strip's way in with a prompt.

            The field is asked first: someone who typed a path into the strip
            and then reached for the menu means that path, and a file dialog
            over the top of it would be the plugin ignoring what it was told.
            """
            if not self._allowed(actions.COMPARE):
                return
            workbench = self._the_workbench()
            workbench.show_scope("matches")
            path = (workbench.run_strip.secondary_path()
                    if workbench.run_strip is not None else "")
            if not path:
                # "*" and not "*.*": the latter requires a dot in the name,
                # so a stripped ELF with no extension is not selectable.
                path = ida_kernwin.ask_file(
                    False, "*",
                    "Select the binary, database or export to compare with")
            if not path:
                return
            self._compare(path)

        def _compare(self, secondary: str) -> None:
            """Compares this database with another binary, out of process.

            The export is what makes this slow, and it is why the C++ plugin
            freezes the IDB: it exports the secondary from inside this process.
            Here a worker does both exports and the diff, so the UI stays live.
            """
            from ida_plugin.diff_runner import (default_output_name,
                                                panel_title, reject_reason)

            if not self._allowed(actions.COMPARE):
                return
            # Checked before anything is asked for: finding out that the
            # exporter is missing after picking a file and a destination
            # wastes the answers.
            if not self._ensure_binexport_plugin():
                return

            refusal = reject_reason(secondary)
            if refusal:
                ida_kernwin.warning(
                    f"{refusal}\n\n"
                    "Compare against the other side: its binary, its .i64 "
                    "database, or its .BinExport.\n\n"
                    "Your open database is always this side and is exported "
                    "again for every comparison, so names, comments and types "
                    "you have ported since the last one are already included. "
                    "To compare again after porting, pick the same other side "
                    "as before -- its .BinExport is quickest, since it needs "
                    "no export at all.")
                return

            primary = self._primary_to_export()
            if not primary:
                ida_kernwin.warning(
                    "This database has never been saved and there is no input "
                    "file to fall back on, so there is nothing to export.")
                return

            output = ida_kernwin.ask_file(
                True, default_output_name(primary, secondary),
                "Save result as")
            if not output:
                return

            title = panel_title(primary)
            workbench = self._the_workbench()
            workbench.show_scope("matches")
            self.session.begin_compare(title)
            if workbench.run_strip is not None:
                workbench.run_strip.start(title)
            self._report("comparing in a background process; the UI stays "
                         "responsive. This can take a while.")
            self._run_diff_async(primary, secondary, output)

        def _cancel(self) -> None:
            if not self._allowed(actions.CANCEL):
                return
            if self._cancel_event is not None:
                self._cancel_event.set()
                self._report("asked the worker to stop and keep what it has "
                             "matched so far")

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
                    "The comparison exports a copy of the saved database, so "
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
            # in the overview as "bindiff-primary-oa1ywul8.primary". It also
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
            is only the wiring: the panel adapter, the marshal to the UI
            thread, and the thread.
            """
            import functools
            import threading

            from bindiff.headless import run_headless
            from ida_plugin.diff_runner import (DEFAULT_TIMEOUT_SECONDS,
                                                DiffRun, worker_arguments)

            cancel = threading.Event()
            # Kept so the strip's Cancel can reach this comparison.
            self._cancel_event = cancel
            plugin = self

            class _PanelAdapter:
                """DiffRun's panel protocol, routed through the session.

                Progress goes to the session and nowhere else: the workbench
                subscribes to session.progress and updates the strip itself,
                so calling the strip from here as well would draw every record
                twice. The end of the run is the other way round -- the strip
                owns its own clock and its own stacked page -- so finish
                reaches it directly, and then the session is told the
                comparison is over.
                """

                def update_progress(self, progress) -> None:
                    plugin.session.report_progress(progress)

                def finish(self, message: str) -> None:
                    strip = (plugin.workbench.run_strip
                             if plugin.workbench is not None else None)
                    # The tab can have been closed mid-comparison, which takes
                    # the strip with it; the session still has to hear.
                    if strip is not None:
                        strip.finish(message)
                    plugin.session.finish_compare(None)

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
                # A cancelled comparison still produced matches worth having,
                # and the result carries that so nobody reads a partial answer
                # as the whole picture.
                result = self._last_result
                partial = bool(result.details.get("cancelled")) if result else False
                self.session.open_result(path, exports, partial=partial)
                workbench = self._the_workbench()
                # A fresh result is something to read before it is something
                # to port from, so it opens on the audit lens.
                workbench.set_lens("needs_a_look")
                workbench.show_scope("matches")

            def runner(args, **kwargs):
                # Both sides are copied, and here rather than in _compare so
                # the copying happens on this thread instead of the UI's. The
                # secondary needs it as much as the primary: an .i64 open in
                # another IDA is locked, idalib's open_database returns
                # non-zero for it, and that surfaced as a bare "could not open
                # <path>" with nothing to do about it.
                with self._snapshot(args[1]) as primary_source, \
                        self._snapshot(args[2]) as secondary_source:
                    result = run_headless(
                        [args[0], primary_source, secondary_source,
                         *args[3:]],
                        timeout=DEFAULT_TIMEOUT_SECONDS, **kwargs)
                # Stashed rather than threaded through DiffRun: `load` is
                # handed the path and the exports only, and whether the run
                # was cancelled is the one other thing the session needs.
                self._last_result = result
                return result

            run = DiffRun(
                runner=runner,
                panel=_PanelAdapter(),
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

        # -- results --------------------------------------------------------

        def _load_results(self) -> None:
            path = _ask_for_database()
            if path is None:
                return
            try:
                meta = self.session.open_result(path)
            except Exception as exc:
                ida_kernwin.warning(f"Could not open {path}:\n{exc}")
                return
            self._report(f"opened {path} ({meta.matched} matches)")
            self._the_workbench().show_scope("matches")

        def _configure(self) -> None:
            import bindiff

            from ida_plugin.panels import AlgorithmConfigDialog

            if not self._allowed(actions.CONFIGURE):
                return

            def apply(changes: dict) -> None:
                bindiff.set_config(changes)
                self._report("matching configuration updated; it applies to "
                             "the next comparison")

            from bindiff.qt_shim import exec_widget

            exec_widget(
                AlgorithmConfigDialog(bindiff.get_config(), apply))

        # -- auto-save ------------------------------------------------------

        def _set_autosave(self, enabled: bool, seconds: int) -> None:
            """Starts or stops the auto-save timer.

            The timer lives here rather than on the strip so hiding the tab
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
                self.session.save()
            except Exception as exc:
                # Stop rather than fail on a timer forever: a broken save that
                # complains once a minute is its own problem.
                self._set_autosave(False, 0)
                ida_kernwin.warning(
                    f"{PLUGIN_NAME}: auto-save failed and has been turned "
                    f"off.\n\n{exc}")
                return
            self._report("auto-saved")

    def PLUGIN_ENTRY():
        return BinDiffPlugin()

else:  # pragma: no cover - exercised only outside IDA

    def PLUGIN_ENTRY():
        raise RuntimeError("BinDiff plugin requires IDA Pro")
