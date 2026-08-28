# -*- coding: utf-8 -*-
# IDA Pro Python Plugin for PyBinDiff (Qt5 Edition)

import collections
import importlib
import importlib.util
import inspect
import logging
import os
import re
import sys
import time
import types
import weakref
from dataclasses import dataclass, field

# IDA imports
import ida_idaapi

# we still need ida_kernwin for action registration, warnings, etc.
import ida_kernwin
import ida_nalt

# PyQt5 imports
from PyQt5 import QtCore, QtWidgets

# Python-BinDiff
try:
    import bindiff

    bindiff.BinDiff.assert_installation_ok()
    PYTHON_BINDIFF_AVAILABLE = True
except ImportError:
    ida_kernwin.warning(
        "python-bindiff library not found. Please install it (`pip install python-bindiff`)."
    )
    PYTHON_BINDIFF_AVAILABLE = False
except bindiff.types.BindiffNotFound:
    ida_kernwin.warning(
        "BinDiff 'differ' executable not found in PATH. Please install BinDiff."
    )
    PYTHON_BINDIFF_AVAILABLE = False
except Exception as e:
    ida_kernwin.warning(f"Error importing python-bindiff: {e}")
    PYTHON_BINDIFF_AVAILABLE = False

# constants
_PLUGIN_NAME = "PyBinDiff"
PLUGIN_VERSION = "0.1.1"
PLUGIN_AUTHORS = "mahmoudimus"
PLUGIN_DATE = "2025"
PLUGIN_HOTKEY = "Ctrl-6"
PLUGIN_COMMENT = "Structural comparison of executable objects (Python + Qt5)"
PLUGIN_HELP = "Python + Qt5 port of the BinDiff IDA Plugin"

# action names
# action names (prefix updated to pybindiff)
ACTION_SHOW_MATCHED = "pybindiff:show_matched"
ACTION_SHOW_UNMATCHED_PRIMARY = "pybindiff:show_primary_unmatched"
ACTION_SHOW_UNMATCHED_SECONDARY = "pybindiff:show_secondary_unmatched"
ACTION_SHOW_STATISTICS = "pybindiff:show_statistics"
ACTION_DIFF_DATABASE = "pybindiff:diff_database"
ACTION_LOAD_RESULTS = "pybindiff:load_results"


def configure_logging(
    log,
    level=logging.INFO,
    handler_filters=None,
    fmt_str="[%(levelname)s][%(asctime)s][%(name)s]: %(message)s",
):
    log.propagate = False
    log.setLevel(level)
    formatter = logging.Formatter(fmt_str)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.setLevel(level)

    # Add the custom filter if every_n is specified.
    if handler_filters is not None:
        for _filter in handler_filters:
            handler.addFilter(_filter)

    for handler in log.handlers[:]:
        log.removeHandler(handler)
        handler.close()

    if not log.handlers:
        log.addHandler(handler)


log = logging.getLogger(_PLUGIN_NAME)
configure_logging(log)


#
# ─── QT DIALOGS & TABLES ─────────────────────────────────────────────────────────
#


class ProgressDialog:
    def __init__(self, message="Please wait...", hide_cancel=False):
        self._default_msg: str
        self.hide_cancel: bool
        self.__user_canceled = False
        self.configure(message, hide_cancel)

    def _message(self, message=None, hide_cancel=None):
        display_msg = self._default_msg if message is None else message
        hide_cancel = self.hide_cancel if hide_cancel is None else hide_cancel
        prefix = "HIDECANCEL\n" if hide_cancel else ""
        return prefix + display_msg

    def configure(self, message="Please wait...", hide_cancel=False):
        self._default_msg = message
        self.hide_cancel = hide_cancel
        return self

    __call__ = configure

    def __enter__(self):
        ida_kernwin.show_wait_box(self._message())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        ida_kernwin.hide_wait_box()
        if self.__user_canceled:
            ida_kernwin.warning("Canceled")

    def replace_message(self, new_message, hide_cancel=False):
        msg = self._message(message=new_message, hide_cancel=hide_cancel)
        ida_kernwin.replace_wait_box(msg)

    def user_canceled(self):
        self.__user_canceled = ida_kernwin.user_cancelled()
        return self.__user_canceled

    user_cancelled = user_canceled


class ida_tguidm:

    def __init__(self, iterable, total=None, initial=0):
        self.iterable = iterable

        if total is None and iterable is not None:
            if isinstance(iterable, types.GeneratorType) or inspect.isgeneratorfunction(
                iterable
            ):
                self.iterable = list(iterable)
                iterable = self.iterable
            try:
                total = len(iterable)
            except (TypeError, AttributeError):
                total = None

        if total == float("inf"):
            # Infinite iterations, behave same as unknown
            total = None
        self.total = total
        self.start_time = None  # Track start time
        self.n = initial

    def __iter__(self):
        # Inlining instance variables as locals (speed optimization)
        iterable = self.iterable
        total = self.total
        self.start_time = time.time()  # Start tracking time
        with ProgressDialog("Executing") as pd:
            for idx, item in enumerate(iterable, start=1):
                if pd.user_canceled():
                    break

                elapsed_time = time.time() - self.start_time
                avg_time_per_item = elapsed_time / idx if idx > 0 else 0
                remaining_time = (total - idx) * avg_time_per_item if total else None

                if remaining_time is not None:
                    eta_str = f" | ETA: {int(remaining_time)}s"
                else:
                    eta_str = ""

                pd.replace_message(f"Processing ({idx}/{total}){eta_str}")

                try:
                    yield item
                except Exception as e:
                    ida_kernwin.warning(f"Unexpected error {e}")
                    break


class WaitBox:
    buffertime = 0.0
    shown = False
    msg = ""

    @staticmethod
    def _show(msg):
        WaitBox.msg = msg
        if WaitBox.shown:
            ida_kernwin.replace_wait_box(msg)
        else:
            ida_kernwin.show_wait_box(msg)
            WaitBox.shown = True

    @staticmethod
    def show(msg, buffertime=0.1):
        if msg == WaitBox.msg:
            return

        if buffertime > 0.0:
            if time.time() - WaitBox.buffertime < buffertime:
                return
            WaitBox.buffertime = time.time()
        WaitBox._show(msg)

    @staticmethod
    def hide():
        if WaitBox.shown:
            ida_kernwin.hide_wait_box()
            WaitBox.shown = False


def set_clipboard_text(data):
    cb = QtWidgets.QApplication.clipboard()
    cb.clear(mode=cb.Clipboard)
    cb.setText(data, mode=cb.Clipboard)


def ensure_qt_app():
    """Make sure there's a running QApplication inside IDA."""
    app = QtWidgets.QApplication.instance()
    if app is None:
        return QtWidgets.QApplication(sys.argv)
    return app


class ActionSelectionDialog(QtWidgets.QDialog):
    """
    Top-level dialog that replaces the old IDA Form in run_plugin_logic().
    Presents buttons for Diff / Load and, if results are loaded, also
    Matched / Unmatched / Statistics.
    """

    def __init__(self, core):
        super().__init__(flags=QtCore.Qt.Window)
        self.core = core
        self.setWindowTitle(f"{_PLUGIN_NAME} v{PLUGIN_VERSION}")
        layout = QtWidgets.QVBoxLayout(self)

        # description
        lbl = QtWidgets.QLabel(f"<b>{_PLUGIN_NAME} {PLUGIN_VERSION}</b>", self)
        layout.addWidget(lbl)

        # always-available buttons
        btn_layout = QtWidgets.QHBoxLayout()
        for text, callback in [
            ("Diff Database…", core.diff_database),
            ("Load Results…", core.load_bindiff_results_file),
        ]:
            btn = QtWidgets.QPushButton(text, self)
            btn.clicked.connect(lambda _, cb=callback: (cb(), self.accept()))
            btn_layout.addWidget(btn)
        layout.addLayout(btn_layout)

        # if we already have results, present the views
        if core.bindiff_results:
            view_layout = QtWidgets.QHBoxLayout()
            for text, cb in [
                ("Matched Functions", MatchedFunctionsDialog.show_dialog),
                ("Unmatched Primary", UnmatchedPrimaryDialog.show_dialog),
                ("Unmatched Secondary", UnmatchedSecondaryDialog.show_dialog),
                ("Statistics", StatisticsDialog.show_dialog),
            ]:
                btn = QtWidgets.QPushButton(text, self)
                btn.clicked.connect(lambda _, fn=cb: (fn(core), self.accept()))
                view_layout.addWidget(btn)
            layout.addLayout(view_layout)

        # Close button
        close = QtWidgets.QPushButton("Close", self)
        close.clicked.connect(self.reject)
        layout.addWidget(close)


class BaseTableDialog(QtWidgets.QDialog):
    """
    Generic table dialog: you supply headers, a function to fetch rows,
    and an optional on_double_click(row_data) callback.
    """

    def __init__(self, title, columns, fetch_rows_fn, on_double_click=None):
        super().__init__(flags=QtCore.Qt.Window)
        self.setWindowTitle(title)
        self.resize(800, 400)
        layout = QtWidgets.QVBoxLayout(self)

        self.table = QtWidgets.QTableWidget(self)
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels([h[0] for h in columns])
        for idx, (_, fmt) in enumerate(columns):
            if fmt == "hex":
                self.table.setColumnWidth(idx, 100)
            elif fmt == "dec":
                self.table.setColumnWidth(idx, 80)
        layout.addWidget(self.table)

        btn_layout = QtWidgets.QHBoxLayout()
        refresh_btn = QtWidgets.QPushButton("Refresh", self)
        refresh_btn.clicked.connect(self._populate)
        btn_layout.addWidget(refresh_btn)
        close_btn = QtWidgets.QPushButton("Close", self)
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        self.fetch_rows = fetch_rows_fn
        self.on_double_click = on_double_click
        if on_double_click:
            self.table.itemDoubleClicked.connect(self._on_item_double)

        self._populate()

    def _populate(self):
        rows = self.fetch_rows()
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                item = QtWidgets.QTableWidgetItem(str(val))
                self.table.setItem(r, c, item)

    def _on_item_double(self, item):
        row = item.row()
        data = self.fetch_rows()[row]
        self.on_double_click(data)
        # do not close automatically; let the user view more


class MatchedFunctionsDialog:
    @staticmethod
    def show_dialog(core):
        """
        Displays matched functions in a table. Double-click jumps to primary.
        """

        def fetch():
            out = []
            if not core.bindiff_results:
                return out
            for m_data in core.bindiff_results.primary_functions_match.values():
                f1_addr = int(m_data.address1)
                f2_addr = int(m_data.address2)
                try:
                    f1 = core.bindiff_results.primary.get(f1_addr)
                    f2 = core.bindiff_results.secondary.get(f2_addr)
                    if f1 is None or f2 is None:
                        log.warning(
                            f"Could not find function for match: {f1_addr:#x} <-> {f2_addr:#x}. Skipping."
                        )
                        continue

                    out.append(
                        [
                            f"{m_data.similarity:.4f}",
                            f"{m_data.confidence:.4f}",
                            f"{f1.addr:#x}",
                            getattr(f1, "name", "N/A"),
                            f"{f2.addr:#x}",
                            getattr(f2, "name", "N/A"),
                            str(m_data.algorithm),
                            len(
                                getattr(m_data, "bb_count", [])
                            ),  # Or however bb_matches are stored in m_data
                            len(
                                getattr(m_data, "edge_count", [])
                            ),  # Or however edge_matches are stored
                            len(
                                getattr(m_data, "inst_count", [])
                            ),  # Or however instruction_matches are stored
                        ]
                    )
                except KeyError as e:
                    log.error(
                        f"KeyError processing match for addrs {f1_addr:#x} / {f2_addr:#x}: {e}. Skipping this match."
                    )
                except Exception as e:
                    log.error(
                        f"Unexpected error processing match for addrs {f1_addr:#x} / {f2_addr:#x}: {e}. Skipping this match."
                    )
            return out

        def on_double(row):
            # jump to primary address
            addr = int(row[2], 16)
            ida_kernwin.jumpto(addr)

        columns = [
            ("Similarity", "dec"),
            ("Confidence", "dec"),
            ("Primary Addr", "hex"),
            ("Primary Name", "plain"),
            ("Secondary Addr", "hex"),
            ("Secondary Name", "plain"),
            ("Algorithm", "plain"),
            ("BB Count", "dec"),
            ("Edge Count", "dec"),
            ("Inst Count", "dec"),
        ]
        dlg = BaseTableDialog(
            f"Matched Functions ({_PLUGIN_NAME})", columns, fetch, on_double
        )
        dlg.exec_()


class UnmatchedPrimaryDialog:
    @staticmethod
    def show_dialog(core):
        def fetch():
            out = []
            for f in core.bindiff_results.primary_unmatched_function():
                bb = len(getattr(f, "basic_blocks", []))
                inst = getattr(f, "instruction_count", 0)
                edge = getattr(f, "edge_count", 0)
                out.append([f"{f.addr:#x}", getattr(f, "name", "N/A"), bb, inst, edge])
            return out

        def on_double(row):
            addr = int(row[0], 16)
            ida_kernwin.jumpto(addr)

        cols = [
            ("Addr", "hex"),
            ("Name", "plain"),
            ("BB Count", "dec"),
            ("Inst Count", "dec"),
            ("Edge Count", "dec"),
        ]
        dlg = BaseTableDialog(
            f"Unmatched Primary ({_PLUGIN_NAME})", cols, fetch, on_double
        )
        dlg.exec_()


class UnmatchedSecondaryDialog:
    @staticmethod
    def show_dialog(core):
        def fetch():
            out = []
            for f in core.bindiff_results.secondary_unmatched_function():
                bb = len(getattr(f, "basic_blocks", []))
                inst = getattr(f, "instruction_count", 0)
                edge = getattr(f, "edge_count", 0)
                out.append([f"{f.addr:#x}", getattr(f, "name", "N/A"), bb, inst, edge])
            return out

        def on_double(row):
            addr = int(row[0], 16)
            set_clipboard_text(f"{addr:#x}")

        cols = [
            ("Addr", "hex"),
            ("Name", "plain"),
            ("BB Count", "dec"),
            ("Inst Count", "dec"),
            ("Edge Count", "dec"),
        ]
        dlg = BaseTableDialog(
            f"Unmatched Secondary ({_PLUGIN_NAME})", cols, fetch, on_double
        )
        dlg.exec_()


class StatisticsDialog:
    @staticmethod
    def show_dialog(core):
        def fetch():
            bd = core.bindiff_results
            stats = []
            stats.append(["Similarity", f"{bd.similarity:.4f}"])
            stats.append(["Confidence", f"{bd.confidence:.4f}"])
            stats.append(["—" * 20, "—" * 10])
            for name, attr in [
                ("Primary Functions", "functions"),
                ("Primary BB", "nb_basic_blocks"),
                ("Primary Inst", "nb_instructions"),
                ("Primary Edges", "nb_edges"),
            ]:
                stats.append([name, str(getattr(bd.primary, attr, "?"))])
            stats.append(["—" * 20, "—" * 10])
            for name, attr in [
                ("Secondary Functions", "functions"),
                ("Secondary BB", "nb_basic_blocks"),
                ("Secondary Inst", "nb_instructions"),
                ("Secondary Edges", "nb_edges"),
            ]:
                stats.append([name, str(getattr(bd.secondary, attr, "?"))])
            stats.append(["—" * 20, "—" * 10])
            for name, val in [
                ("Matched Functions", len(getattr(bd, "matches", []))),
                ("Unmatched Primary", len(getattr(bd, "primary_unmatched", []))),
                ("Unmatched Secondary", len(getattr(bd, "secondary_unmatched", []))),
            ]:
                stats.append([name, str(val)])
            return stats

        cols = [("Name", "plain"), ("Value", "plain")]
        dlg = BaseTableDialog(
            f"Statistics ({_PLUGIN_NAME})", cols, fetch, on_double_click=None
        )
        dlg.exec_()


# Python Callback / Signals (Part of reloader snippet)
def register_callback(callback_list, callback):
    try:
        callback_ref = weakref.ref(callback.__func__), weakref.ref(callback.__self__)
    except AttributeError:
        callback_ref = weakref.ref(callback), None
    callback_list.append(callback_ref)


def notify_callback(callback_list, *args):
    cleanup = []
    for callback_ref in callback_list:
        callback, obj_ref = callback_ref[0](), callback_ref[1]
        if obj_ref:
            obj = obj_ref()
            if obj is None:
                cleanup.append(callback_ref)
                continue
            try:
                callback(obj, *args)
            except RuntimeError as e:
                cleanup.append(callback_ref)
                continue
        else:
            if callback is None:
                cleanup.append(callback_ref)
                continue
            callback(*args)
    for callback_ref in cleanup:
        callback_list.remove(callback_ref)


# Module Reloading (Part of reloader snippet)
def reload_package(target_module):
    target_name = target_module.__name__
    visited_modules = {target_name: target_module}
    _recursive_reload(target_module, target_name, visited_modules)


def _recursive_reload(module, target_name, visited):
    ignore = [
        "__builtins__",
        "__cached__",
        "__doc__",
        "__file__",
        "__loader__",
        "__name__",
        "__package__",
        "__spec__",
        "__path__",
    ]
    visited[module.__name__] = module
    for attribute_name in dir(module):
        if attribute_name in ignore:
            continue
        if attribute_name.startswith("ida_") or attribute_name == "idc":
            continue
        attribute_value = getattr(module, attribute_name)
        if type(attribute_value) == types.ModuleType:
            attribute_module_name = attribute_value.__name__
            attribute_module = attribute_value
        elif callable(attribute_value):
            attribute_module_name = attribute_value.__module__
            attribute_module = sys.modules[attribute_module_name]
        elif isinstance(
            attribute_value, (dict, list, int, bytes, bytearray, set, logging.Logger)
        ):
            continue
        else:
            # Temporarily quiet this print for cleaner integration
            # print(f"Ignoring attribute {attribute_name} of type {type(attribute_value)} from module {module.__name__}. Target module: {target_name}.")
            pass  # Was: print(err)

        if target_name not in attribute_module_name:
            continue
        if "__plugins__" in attribute_module_name:
            continue
        if attribute_module_name in visited:
            continue
        _recursive_reload(attribute_module, target_name, visited)
    importlib.reload(module)


def reload_module(module, to_reload: set):
    if module not in to_reload:
        return
    to_reload.remove(module)
    for _, dep in inspect.getmembers(module, lambda k: inspect.ismodule(k)):
        reload_module(dep, to_reload)
    # print(f"Reloading {module.__name__} ..") # Temporarily quiet this
    try:
        importlib.reload(module)
    except ModuleNotFoundError as e:
        if "spec not found for the module" in str(e):
            force_reload()
        else:
            raise e


def reload_plugin():
    to_reload = set()
    # Assuming the plugin's main file or package root starts with "pybindiff"
    # This needs to match the actual module name(s) used by the plugin.
    # If the plugin is a single file named 'pybindiff.py', then __name__ will be 'pybindiff'.
    # If it's a package, adjust accordingly.
    plugin_module_prefix = _PLUGIN_NAME.lower()  # Or more specific if needed
    if __name__ != "__main__":  # if imported as a module
        plugin_module_prefix = __name__.split(".")[0]

    for k, mod in sys.modules.items():
        # Check if the module name itself starts with the prefix, or if it's part of a package with that prefix
        if k.startswith(plugin_module_prefix):
            to_reload.add(mod)

    # Add the main plugin module itself if it was missed (e.g. if __name__ was __main__ initially)
    if __name__ in sys.modules:
        to_reload.add(sys.modules[__name__])

    # print(f"Modules to reload: {[m.__name__ for m in to_reload]}") # For debugging
    for mod in list(to_reload):
        reload_module(mod, to_reload)


def force_reload(plugin_name: str = f"__plugins__{_PLUGIN_NAME.lower()}"):
    name = plugin_name
    path = sys.modules[name].__file__

    # 1) remove the old module
    sys.modules.pop(name, None)

    # 2) create a spec from its file
    spec = importlib.util.spec_from_file_location(name, path)

    # 3) make a fresh module from that spec
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module

    # 4) execute the module
    spec.loader.exec_module(module)


# --- End Reloader Utility ---


# --- Base Action Class ---
class action_t:
    """
    A base class for reloadable IDA actions.
    """

    def __init__(self, core, ida_action_name_str: str):
        self.core = core
        self.ida_action_name = ida_action_name_str  # IDA internal name for registration

    def term(self):
        """
        Terminate the action & clean up.
        Called when the plugin core is unloading.
        Default implementation does nothing.
        """
        pass


# --- Action Implementations ---
class ShowMatchedAction(ida_kernwin.action_handler_t, action_t):
    def __init__(self, core, name):
        ida_kernwin.action_handler_t.__init__(self)
        action_t.__init__(self, core, name)

    def activate(self, ctx):
        if self.core.bindiff_results:
            MatchedFunctionsDialog.show_dialog(self.core)
        else:
            ida_kernwin.warning("No results loaded.")
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if self.core.bindiff_results
            else ida_kernwin.AST_DISABLE
        )


class ShowUnmatchedPrimaryAction(ida_kernwin.action_handler_t, action_t):
    def __init__(self, core, name):
        ida_kernwin.action_handler_t.__init__(self)
        action_t.__init__(self, core, name)

    def activate(self, ctx):
        if self.core.bindiff_results:
            UnmatchedPrimaryDialog.show_dialog(self.core)
        else:
            ida_kernwin.warning("No results loaded.")
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if self.core.bindiff_results
            else ida_kernwin.AST_DISABLE
        )


class ShowUnmatchedSecondaryAction(ida_kernwin.action_handler_t, action_t):
    def __init__(self, core, name):
        ida_kernwin.action_handler_t.__init__(self)
        action_t.__init__(self, core, name)

    def activate(self, ctx):
        if self.core.bindiff_results:
            UnmatchedSecondaryDialog.show_dialog(self.core)
        else:
            ida_kernwin.warning("No results loaded.")
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if self.core.bindiff_results
            else ida_kernwin.AST_DISABLE
        )


class ShowStatisticsAction(ida_kernwin.action_handler_t, action_t):
    def __init__(self, core, name):
        ida_kernwin.action_handler_t.__init__(self)
        action_t.__init__(self, core, name)

    def activate(self, ctx):
        if self.core.bindiff_results:
            StatisticsDialog.show_dialog(self.core)
        else:
            ida_kernwin.warning("No results loaded.")
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if self.core.bindiff_results
            else ida_kernwin.AST_DISABLE
        )


class DiffDatabaseAction(ida_kernwin.action_handler_t, action_t):
    def __init__(self, core, name):
        ida_kernwin.action_handler_t.__init__(self)
        action_t.__init__(self, core, name)

    def activate(self, ctx):
        self.core.diff_database()
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if ida_nalt.get_input_file_path()
            else ida_kernwin.AST_DISABLE_FOR_IDB
        )


class LoadResultsAction(ida_kernwin.action_handler_t, action_t):
    def __init__(self, core, name):
        ida_kernwin.action_handler_t.__init__(self)
        action_t.__init__(self, core, name)

    def activate(self, ctx):
        self.core.load_bindiff_results_file()
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE
            if ida_nalt.get_input_file_path()
            else ida_kernwin.AST_DISABLE_FOR_IDB
        )


# --- New Plugin Core Class (from user) ---
# Using collections.deque from user's snippet, ensure it's imported.
deque = collections.deque


@dataclass
class PluginCore:
    PLUGIN_NAME: str = _PLUGIN_NAME
    PLUGIN_VERSION: str = PLUGIN_VERSION
    PLUGIN_AUTHORS: str = PLUGIN_AUTHORS
    PLUGIN_DATE: str = PLUGIN_DATE

    defer_load: bool = field(default=False)
    loaded: bool = field(default=False, init=False)
    _startup_hooks: object | None = field(default=None, init=False, repr=False)

    bindiff_results: any = field(default=None, init=False, repr=False)
    bindiff_icon_id: int = field(default=-1, init=False)
    _active_actions: deque = field(default_factory=deque, init=False, repr=False)

    @classmethod
    def deferred_load(cls):
        return cls(defer_load=True)

    def __post_init__(self):
        global g_bindiff_plugin_core
        g_bindiff_plugin_core = self
        if self.defer_load:
            self._startup_hooks = _UIHooks(self)
            self._startup_hooks.hook()

    def load(self):
        if self.loaded:
            return True
        if self._startup_hooks:
            self._startup_hooks.unhook()
            self._startup_hooks = None

        if not PYTHON_BINDIFF_AVAILABLE:
            log.error("Dependencies not met.")
            return False

        # register actions (unchanged)
        for name, label, cls, shortcut, tip in [
            (ACTION_SHOW_MATCHED, "~M~atched functions", ShowMatchedAction, None, ""),
            (
                ACTION_SHOW_UNMATCHED_PRIMARY,
                "~P~rimary unmatched",
                ShowUnmatchedPrimaryAction,
                None,
                "",
            ),
            (
                ACTION_SHOW_UNMATCHED_SECONDARY,
                "~S~econdary unmatched",
                ShowUnmatchedSecondaryAction,
                None,
                "",
            ),
            (ACTION_SHOW_STATISTICS, "S~t~atistics", ShowStatisticsAction, None, ""),
            (ACTION_DIFF_DATABASE, "Bin~D~iff…", DiffDatabaseAction, "Shift-D", ""),
            (
                ACTION_LOAD_RESULTS,
                "~L~oad Results…",
                LoadResultsAction,
                "Ctrl-Shift-6",
                "",
            ),
        ]:
            inst = cls(self, name)
            self._active_actions.append(inst)
            desc = ida_kernwin.action_desc_t(
                name, label, inst, shortcut, tip, self.bindiff_icon_id
            )
            if not ida_kernwin.register_action(desc):
                log.error(f"Failed to register {name}")

        # create menu
        ida_kernwin.create_menu(
            "pybindiff:view_pybindiff", "PyBinDiff", "View/Open subviews/"
        )
        for name in [
            ACTION_SHOW_MATCHED,
            ACTION_SHOW_UNMATCHED_PRIMARY,
            ACTION_SHOW_UNMATCHED_SECONDARY,
            ACTION_SHOW_STATISTICS,
        ]:
            ida_kernwin.attach_action_to_menu(
                "View/PyBinDiff/", name, ida_kernwin.SETMENU_APP
            )

        self.loaded = True
        return True

    def unload(self, from_ida=False):
        if not self.loaded:
            return
        for name in [
            ACTION_SHOW_MATCHED,
            ACTION_SHOW_UNMATCHED_PRIMARY,
            ACTION_SHOW_UNMATCHED_SECONDARY,
            ACTION_SHOW_STATISTICS,
        ]:
            ida_kernwin.detach_action_from_menu("View/PyBinDiff/", name)
        ida_kernwin.delete_menu("pybindiff:view_pybindiff")
        count = 0
        for act in reversed(self._active_actions):
            act.term()
            if ida_kernwin.unregister_action(act.ida_action_name):
                count += 1
        self._active_actions.clear()
        self.bindiff_results = None
        self.loaded = False
        log.info(f"{self.PLUGIN_NAME} unloaded ({count} actions).")

    def run_plugin_logic(self, arg):
        try:
            return self._run_plugin_logic_impl(arg)
        except Exception as e:
            log.error(f"Error during {self.PLUGIN_NAME} run: {e}", exc_info=True)
            ida_kernwin.warning(f"Error during {self.PLUGIN_NAME} run: {e}")
            return False

    def _run_plugin_logic_impl(self, arg):
        # ensure Qt app
        ensure_qt_app()
        # reload results vs prompt to save left out for brevity...
        # show our new Qt dialog
        dlg = ActionSelectionDialog(self)
        dlg.exec_()
        return True

    def prompt_save_if_modified(self):
        is_modified = False
        if self.bindiff_results and is_modified:
            res = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                "HIDECANCEL\\nBinDiff results have been modified. Save them first?",
            )
            if res == ida_kernwin.ASKBTN_YES:
                log.warning("Save functionality not implemented yet.")
                return True
            elif res == ida_kernwin.ASKBTN_CANCEL:
                return False
        return True

    def load_bindiff_results_file(self):
        if not self.prompt_save_if_modified():
            return False
        bindiff_file_path = ida_kernwin.ask_file(
            False, "*.BinDiff", "Select BinDiff Results File"
        )
        if not bindiff_file_path or not os.path.exists(bindiff_file_path):
            log.info("Load results cancelled or file invalid.")
            return False

        log.info(f"Attempting to load BinDiff results from: {bindiff_file_path}")
        # ida_kernwin.show_wait_box("Loading BinDiff Results...") # Replaced by ProgressDialog

        primary_binexport_path, secondary_binexport_path = (
            self._find_binexports_for_diff(bindiff_file_path)
        )
        if not primary_binexport_path or not secondary_binexport_path:
            # ida_kernwin.hide_wait_box() # Replaced by ProgressDialog context management
            ida_kernwin.warning(
                "Could not find corresponding .BinExport files. Please select them manually."
            )
            primary_binexport_path = ida_kernwin.ask_file(
                False, "*.BinExport", "Select Primary BinExport File for Diff"
            )
            if not primary_binexport_path:
                # ida_kernwin.hide_wait_box() # Not needed, no active ProgressDialog here
                return False
            secondary_binexport_path = ida_kernwin.ask_file(
                False, "*.BinExport", "Select Secondary BinExport File for Diff"
            )
            if not secondary_binexport_path:
                # ida_kernwin.hide_wait_box() # Not needed, no active ProgressDialog here
                return False
            # ida_kernwin.show_wait_box("Loading BinDiff Results...") # Replaced by ProgressDialog context

        try:
            with ProgressDialog("Loading BinDiff data...") as pd:
                new_results = bindiff.BinDiff(
                    primary_binexport_path, secondary_binexport_path, bindiff_file_path
                )
                current_hash = (
                    ida_nalt.retrieve_input_file_sha256()
                    or ida_nalt.retrieve_input_file_md5()
                )
                primary_hash_in_results = new_results.primary_file.hash
                primary_filename_in_results = new_results.primary_file.filename
                log.info(
                    f"Loaded results. Primary: {primary_filename_in_results}, Hash: {primary_hash_in_results}"
                )

            # ProgressDialog is hidden here after the 'with' block

            if (
                current_hash
                and primary_hash_in_results
                and current_hash.hex().lower() != primary_hash_in_results.lower()
            ):
                # ida_kernwin.hide_wait_box() # ProgressDialog already hidden
                btn = ida_kernwin.ask_buttons(
                    "Continue",
                    "Cancel",
                    "",
                    ida_kernwin.ASKBTN_BTN1,
                    f"Warning: Hash Mismatch!\n\nCurrent IDB hash ({current_hash.hex()}) does not match "
                    f"BinDiff primary hash ({primary_hash_in_results} - {os.path.basename(primary_filename_in_results)}).\n\n"
                    f"Results may be inaccurate.",
                )
                if btn != ida_kernwin.ASKBTN_BTN1:
                    log.warning("Load cancelled by user due to hash mismatch.")
                    return False
                # ida_kernwin.show_wait_box("Loading BinDiff Results...") # Replaced by ProgressDialog context below

            # Finalizing results under a new ProgressDialog context if needed,
            # or if previous section showed it and this is a continuation.
            # The original logic showed a wait box here if hash mismatch was confirmed.
            with ProgressDialog("Finalizing BinDiff results...") as pd_final:
                self.bindiff_results = new_results
                log.info(
                    f"Successfully loaded BinDiff. Similarity: {self.bindiff_results.similarity}, Confidence: {self.bindiff_results.confidence}"
                )
            return True
        except (bindiff.types.BindiffNotFound, FileNotFoundError) as e:
            log.error(f"Error loading BinDiff (differ or BinExport not found): {e}")
            ida_kernwin.warning(
                f"Error loading BinDiff results. Check installation/files.\\n{e}"
            )
            self.bindiff_results = None
            return False
        except Exception as e:
            log.error(f"Failed to load BinDiff results: {e}", exc_info=True)
            ida_kernwin.warning(f"Error loading BinDiff results:\\n{e}")
            self.bindiff_results = None
            return False

    def _find_binexports_for_diff(self, bindiff_file_path: str) -> tuple[str, str]:
        diff_dir = os.path.dirname(bindiff_file_path)
        diff_basename = os.path.basename(bindiff_file_path)
        match = re.match(
            r"(.+)_vs_(.+)\\.BinDiff", diff_basename, re.IGNORECASE
        )  # Escaped dot
        if match:
            primary_name, secondary_name = match.groups()
            p_binexport = os.path.join(diff_dir, primary_name + ".BinExport")
            s_binexport = os.path.join(diff_dir, secondary_name + ".BinExport")
            if os.path.exists(p_binexport) and os.path.exists(s_binexport):
                log.info(f"Auto-detected BinExport files: {p_binexport}, {s_binexport}")
                return p_binexport, s_binexport
            log.warning("Could not auto-detect BinExport files based on .BinDiff name.")
        else:
            log.warning(
                "Could not parse primary/secondary names from .BinDiff filename."
            )
        return None, None

    def diff_database(self):
        if not PYTHON_BINDIFF_AVAILABLE:
            ida_kernwin.warning(f"{self.PLUGIN_NAME} dependencies not available.")
            return False
        try:
            import binexport  # Check for binexport locally to this method
        except ImportError:
            ida_kernwin.warning("python-binexport not found (required for diffing).")
            return False

        primary_path = ida_nalt.get_input_file_path()
        if not primary_path:
            ida_kernwin.warning("No IDB open.")
            return False
        if not self.prompt_save_if_modified():
            return False

        secondary_path = ida_kernwin.ask_file(
            False, "*.*", "Select Secondary Binary/IDB"
        )
        if not secondary_path or not os.path.exists(secondary_path):
            log.info("Diff cancelled or secondary file invalid.")
            return False

        default_diff_name = f"{os.path.splitext(os.path.basename(primary_path))[0]}_vs_{os.path.splitext(os.path.basename(secondary_path))[0]}.BinDiff"
        diff_output_path = ida_kernwin.ask_file(
            True, "*.BinDiff", f"Save BinDiff Results As ({default_diff_name})"
        )
        if not diff_output_path:
            log.info("Diff cancelled, no output path.")
            return False

        log.info(
            f"Starting diff: {primary_path} vs {secondary_path} -> {diff_output_path}"
        )
        # ida_kernwin.show_wait_box( # Replaced by ProgressDialog
        #     f"Running BinDiff...\\nPrimary: {os.path.basename(primary_path)}\\nSecondary: {os.path.basename(secondary_path)}"
        # )
        progress_message = f"Running BinDiff...\\nPrimary: {os.path.basename(primary_path)}\\nSecondary: {os.path.basename(secondary_path)}"
        try:
            with ProgressDialog(progress_message) as pd:
                new_results = bindiff.BinDiff.from_binary_files(
                    primary_path, secondary_path, diff_output_path, override=True
                )
                if new_results:
                    self.bindiff_results = new_results
                    log.info("Diff completed successfully.")
                    # return True # Must be outside 'with' block if pd interaction is needed before returning
                else:
                    log.error("BinDiff.from_binary_files returned None. Diff failed.")
                    ida_kernwin.warning("Diffing process failed. Check logs.")
                    self.bindiff_results = None
                    # return False

            # Return after ProgressDialog has exited
            if new_results:
                return True
            else:
                return False

        except bindiff.types.BindiffNotFound as e:
            log.error(f"BinDiff differ executable not found: {e}")
            ida_kernwin.warning(
                f"BinDiff differ not found. Check installation and PATH/BINDIFF_PATH.\\n{e}"
            )
            return False
        except Exception as e:
            log.error(f"Diffing failed: {e}", exc_info=True)
            ida_kernwin.warning(f"Error during diffing process:\\n{e}")
            self.bindiff_results = None
            return False
        finally:
            # if ida_pro.is_idaq(): # ProgressDialog handles its own hide_wait_box unconditionally
            #     ida_kernwin.hide_wait_box()
            pass  # ProgressDialog's __exit__ handles hiding

    def test(self):
        log.info(f"{self.PLUGIN_NAME} Core test method called.")
        ida_kernwin.info(
            f"{self.PLUGIN_NAME} Core test method executed. Check logs for details."
        )
        if self.bindiff_results:
            log.info(
                f"  Test: Results are loaded. Similarity: {self.bindiff_results.similarity}"
            )
        else:
            log.info("  Test: No results currently loaded.")
        # User's snippet returned False, keeping that behavior for test.
        return False


class _UIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, core):
        super().__init__()
        self._core = weakref.ref(core)

    def ready_to_run(self):
        c = self._core()
        if c:
            c.load()
            self.unhook()


class BinDiffPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_FIX
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = _PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    instance = None

    def __init__(self):
        super().__init__()
        self.core = None
        log.debug("Plugin __init__")

    def init(self):
        log.info("Initializing plugin")
        BinDiffPlugin.instance = self
        self.core = PluginCore(defer_load=False)
        if not self.core.load():
            return ida_idaapi.PLUGIN_SKIP
        self.add_plugin_to_console()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        log.info("Terminating plugin")
        if self.core:
            self.core.unload()
            self.core = None
        global g_bindiff_plugin_core
        g_bindiff_plugin_core = None
        BinDiffPlugin.instance = None

    def run(self, arg):
        log.debug("Plugin run()")
        if not self.core or not self.core.loaded:
            if not self.core.load():
                ida_kernwin.warning("Core not loaded.")
                return False
        return self.core.run_plugin_logic(arg)

    def add_plugin_to_console(self):
        name = self.core.PLUGIN_NAME
        setattr(sys.modules["__main__"], name, self)
        setattr(sys.modules["__main__"], f"{name}_core", self.core)

    def reload(self):
        log.info("Reloading plugin")
        if self.core:
            self.core.unload()
        reload_plugin()
        self.core = PluginCore(defer_load=False)
        if self.core.load():
            self.add_plugin_to_console()
            ida_kernwin.info("Reloaded successfully.")


def PLUGIN_ENTRY():
    return BinDiffPlugin()
