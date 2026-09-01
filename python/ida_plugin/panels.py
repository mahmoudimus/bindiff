"""Qt views for the BinDiff plugin.

These render the view objects from ui_logic and forward user actions back; they
hold no presentation logic of their own, so what is worth testing is testable
headless. Widgets are only defined when IDA is importable, which keeps this
module importable in the test harness -- the same guard d810 and Gepetto use.

Qt5 and Qt6 both work: everything goes through bindiff.qt_shim, which picks
PySide6 (IDA 9.2+) or PyQt5 (IDA 9.1) and papers over the differences.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from ida_plugin.ui_logic import (
    COLUMNS,
    ColumnVisibility,
    DiffProgress,
    FlowGraphDiff,
    build_flow_graph_diff,
    UNMATCHED_COLUMNS,
    UnmatchedRow,
    filter_unmatched,
    format_elapsed,
    sort_unmatched,
    text_query_narrows,
    unmatched_cell_values,
    MatchFilter,
    MatchRow,
    StatisticRow,
    describe_change_flags,
    cell_values,
    change_legend,
    IncrementalFilter,
    filter_rows,
    format_address,
    similarity_color,
    sort_rows,
)

from bindiff.ida_env import ida_kernwin_if_loaded, qt_widgets_usable

# Widgets need a running GUI, which is a stronger condition than "ida_kernwin
# can be imported": in an idalib process it imports fine and there is still no
# QApplication and no display. Probing for it is also unsafe -- see
# bindiff.ida_env -- so this asks whether IDA already loaded it.
IDA_AVAILABLE = qt_widgets_usable()
ida_kernwin = ida_kernwin_if_loaded()

if IDA_AVAILABLE:
    import ida_bytes
    import ida_funcs


if IDA_AVAILABLE:
    from bindiff.qt_shim import (Qt, QtCore, QtGui, QtWidgets,
                             exec_widget)

    def _set_interactive(header) -> None:
        """Columns the user can drag, spelled for either Qt binding."""
        try:
            header.setSectionResizeMode(
                QtWidgets.QHeaderView.ResizeMode.Interactive)
        except AttributeError:
            header.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)

    class _SizesColumnsOnce:
        """Sizes columns to their contents the first time rows arrive.

        Once only: doing it on every set_rows would undo a width the user had
        dragged, every time the filter box changed the visible set. The point
        of Interactive columns is that the widths are theirs after that.
        """

        def _size_columns_once(self) -> None:
            if getattr(self, "_columns_sized", False):
                return
            if not self._model.rows:
                return
            self._columns_sized = True
            self.resizeColumnsToContents()

    def show_action_menu(view, actions, on_action, position) -> None:
        """Pops up a menu of IDA action names and runs the chosen one.

        Shared by both list views. They had a copy each, and a copy each is
        how the matched menu got its dispatch fixed while the unmatched one
        had no menu at all.

        The chosen action is called directly rather than handed to
        ida_kernwin.process_ui_action, which does not dispatch from inside a
        Qt menu on our own widget and fails silently when it does not.
        """
        if not actions:
            return
        menu = QtWidgets.QMenu(view)
        for name in actions:
            if name is None:
                menu.addSeparator()
                continue
            entry = menu.addAction(name.split(":", 1)[-1].replace("_", " "))
            entry.setData(name)
        chosen = exec_widget(menu, view.viewport().mapToGlobal(position))
        if chosen is None:
            return
        if on_action is not None:
            on_action(chosen.data())
        else:
            ida_kernwin.process_ui_action(chosen.data())

    def debounced(parent, callback, interval: int = 150):
        """A single-shot timer that restarts on every call.

        Typing arrives faster than a filtered result can be read, so both
        search boxes wait for a pause rather than filtering per keystroke.
        Returns the timer; the caller connects a textChanged to its start.
        """
        timer = QtCore.QTimer(parent)
        timer.setSingleShot(True)
        timer.setInterval(interval)
        timer.timeout.connect(callback)
        return timer

    def _no_edit_triggers():
        """QAbstractItemView.NoEditTriggers, spelled for either binding."""
        view = QtWidgets.QAbstractItemView
        try:
            return view.EditTrigger.NoEditTriggers
        except AttributeError:
            return view.NoEditTriggers

    def _select_rows():
        view = QtWidgets.QAbstractItemView
        try:
            return view.SelectionBehavior.SelectRows
        except AttributeError:
            return view.SelectRows

    def _extended_selection():
        view = QtWidgets.QAbstractItemView
        try:
            return view.SelectionMode.ExtendedSelection
        except AttributeError:
            return view.ExtendedSelection

    class ActionMenu(QtWidgets.QDialog):
        """The plugin's front door: the actions it can start, as buttons.

        The C++ plugin opens exactly this when BinDiff is chosen from the
        menu, and it is what anyone coming from it expects. This one used to
        call _load_results() straight from run(), so the whole plugin
        presented as a file-open dialog and the diff was unreachable without
        knowing the action name.

        Only actions that exist get a button. The C++ menu also offers "Diff
        Database Filtered..."; there is no filtered diff here, and a button
        that does nothing is worse than an absent one.
        """

        def __init__(self, title, entries, parent=None):
            super().__init__(parent)
            self.setWindowTitle(title)
            layout = QtWidgets.QVBoxLayout(self)
            layout.setSpacing(8)
            for label, callback in entries:
                button = QtWidgets.QPushButton(label, self)
                button.setMinimumHeight(32)
                # Closed before the action runs: several of these open modal
                # dialogs of their own, and stacking one on top of this would
                # leave the menu hanging behind them for the whole diff.
                button.clicked.connect(
                    lambda _checked=False, fn=callback: self._chose(fn))
                layout.addWidget(button)
            layout.addSpacing(6)
            close = QtWidgets.QPushButton("Close", self)
            close.clicked.connect(self.reject)
            layout.addWidget(close)
            self.chosen = None

        def _chose(self, callback):
            self.chosen = callback
            self.accept()

    class MatchTableModel(QtCore.QAbstractTableModel):
        """Serves MatchRow objects to a view on demand.

        The table was a QTableWidget, which materialises a QTableWidgetItem
        per cell: 5956 rows by 18 columns is 107,208 widgets built on every
        repopulate, and the filter box repopulated on every keystroke. A model
        builds nothing. The view asks for the cells it is about to paint --
        thirty-odd rows -- and asks again when you scroll.

        Formatting lives in ui_logic.cell_values so it stays testable without
        a GUI; this class is the adapter and nothing more.
        """

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self._rows: List[MatchRow] = []
            # data() is called once per visible cell, so the same row is
            # formatted eighteen times in a row. One slot of memory removes
            # seventeen of those.
            self._cached_index = -1
            self._cached_values: tuple = ()

        # -- Qt model interface ---------------------------------------------

        def rowCount(self, parent=None) -> int:
            if parent is not None and parent.isValid():
                return 0
            return len(self._rows)

        def columnCount(self, parent=None) -> int:
            if parent is not None and parent.isValid():
                return 0
            return len(COLUMNS)

        def _values(self, index: int) -> tuple:
            if index != self._cached_index:
                self._cached_index = index
                self._cached_values = cell_values(self._rows[index])
            return self._cached_values

        def data(self, index, role=None):
            if not index.isValid():
                return None
            if role is None:
                role = Qt.DisplayRole
            position = index.row()
            if position >= len(self._rows):
                return None
            row = self._rows[position]

            if role == Qt.DisplayRole:
                return self._values(position)[index.column()]
            if role == Qt.BackgroundRole and index.column() == 0:
                return QtGui.QBrush(
                    QtGui.QColor(*similarity_color(row.similarity)))
            if role == Qt.ToolTipRole and index.column() == 2:
                changed = describe_change_flags(row.change_flags)
                return ", ".join(changed) if changed else "No changes"
            if role == Qt.FontRole and row.manual:
                font = QtGui.QFont()
                font.setBold(True)
                return font
            return None

        def headerData(self, section, orientation, role=None):
            if role is None:
                role = Qt.DisplayRole
            if orientation != Qt.Horizontal or not 0 <= section < len(COLUMNS):
                return None
            if role == Qt.DisplayRole:
                return COLUMNS[section][1]
            # The Change column reads "GI--EL-" and nothing on screen says
            # what the seven positions are.
            if role == Qt.ToolTipRole and COLUMNS[section][0] == "change":
                return change_legend()
            return None

        # -- our interface ---------------------------------------------------

        def set_rows(self, rows: Sequence[MatchRow]) -> None:
            self.beginResetModel()
            self._rows = list(rows)
            self._cached_index = -1
            self.endResetModel()

        @property
        def rows(self) -> List[MatchRow]:
            return self._rows

    class MatchTable(_SizesColumnsOnce, QtWidgets.QTableView):
        """The matched-functions table.

        Sorting is done in ui_logic rather than by Qt so the order is the same
        whether it came from a click or from a test.
        """

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self._model = MatchTableModel(self)
            self.setModel(self._model)
            self.setEditTriggers(_no_edit_triggers())
            self.setSelectionBehavior(_select_rows())
            self.setSelectionMode(_extended_selection())
            self.setAlternatingRowColors(True)
            self.verticalHeader().setVisible(False)

            header = self.horizontalHeader()
            # Interactive, not ResizeToContents. ResizeToContents locks the
            # header: the columns are sized for the widest cell and cannot be
            # dragged, so one long mangled name makes its column
            # unmanageable and there is nothing to be done about it.
            # Interactive plus a one-off sizing gives sensible defaults that
            # can then be changed.
            _set_interactive(header)
            header.setStretchLastSection(True)
            header.setSectionsClickable(True)
            header.sectionClicked.connect(self._on_header_clicked)

            self._sort_column = "similarity"
            self._sort_descending = True
            self.on_activated: Optional[Callable[[MatchRow], None]] = None
            self.doubleClicked.connect(self._on_double_clicked)

            # Context menu entries name IDA actions, so they stay in one
            # place: registered once, reachable from the plugin menu and from
            # here, and enabled by the same predicate.
            self.context_actions: Sequence[str] = ()
            # How a chosen entry is run. Set by the plugin to call the handler
            # directly; process_ui_action is the fallback and does not work
            # from inside this menu -- see _show_context_menu.
            self.on_action: Optional[Callable[[str], None]] = None

            # Density. The default row height leaves a table that shows a
            # dozen rows where it could show thirty, and a diff is a list you
            # scan rather than read. Sized from the font rather than a
            # constant so it follows IDA's own scaling.
            metrics = self.fontMetrics()
            self.verticalHeader().setDefaultSectionSize(metrics.height() + 4)
            self.setWordWrap(False)
            self._visibility = ColumnVisibility()
            self.on_visibility_changed: Optional[Callable[[], None]] = None
            self._apply_visibility()

            # The header carries its own menu: which columns to show is a
            # property of the table, not an IDA-wide action.
            header_menu_policy = self.horizontalHeader()
            try:
                header_menu_policy.setContextMenuPolicy(
                    Qt.ContextMenuPolicy.CustomContextMenu)
            except AttributeError:
                header_menu_policy.setContextMenuPolicy(Qt.CustomContextMenu)
            header_menu_policy.customContextMenuRequested.connect(
                self._show_column_menu)
            try:
                self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            except AttributeError:
                self.setContextMenuPolicy(Qt.CustomContextMenu)
            self.customContextMenuRequested.connect(self._show_context_menu)

        @property
        def visibility(self) -> ColumnVisibility:
            return self._visibility

        def set_visibility(self, visibility: ColumnVisibility) -> None:
            self._visibility = visibility
            self._apply_visibility()

        def _apply_visibility(self) -> None:
            for index, (name, _label) in enumerate(COLUMNS):
                self.setColumnHidden(index, not self._visibility.is_visible(name))

        def _show_column_menu(self, position) -> None:
            menu = QtWidgets.QMenu(self)
            for name, label in COLUMNS:
                action = menu.addAction(label)
                action.setCheckable(True)
                action.setChecked(self._visibility.is_visible(name))
                action.setData(name)
            menu.addSeparator()
            show_all = menu.addAction("Show all")
            reset = menu.addAction("Reset to defaults")

            chosen = exec_widget(
                menu,
                self.horizontalHeader().mapToGlobal(position))
            if chosen is None:
                return
            if chosen is show_all:
                self._visibility.show_all()
            elif chosen is reset:
                self._visibility.reset()
            elif not self._visibility.set_visible(chosen.data(),
                                                  chosen.isChecked()):
                # Refused: this was the last visible column.
                QtWidgets.QMessageBox.information(
                    self, "BinDiff", "At least one column must stay visible.")
                return
            self._apply_visibility()
            if self.on_visibility_changed is not None:
                self.on_visibility_changed()

        def _show_context_menu(self, position) -> None:
            show_action_menu(self, self.context_actions, self.on_action,
                             position)
        def set_rows(self, rows: Sequence[MatchRow]) -> None:
            self._model.set_rows(
                sort_rows(rows, self._sort_column, self._sort_descending))
            self._size_columns_once()

        @property
        def _rows(self) -> List[MatchRow]:
            return self._model.rows

        def selected_rows(self) -> List[MatchRow]:
            rows = self._model.rows
            indexes = {index.row() for index in self.selectedIndexes()}
            return [rows[i] for i in sorted(indexes) if i < len(rows)]

        def _on_header_clicked(self, section: int) -> None:
            column = COLUMNS[section][0]
            if column == self._sort_column:
                self._sort_descending = not self._sort_descending
            else:
                self._sort_column = column
                # Scores read best highest-first; names and addresses ascending.
                self._sort_descending = column in ("similarity", "confidence")
            self.set_rows(self._model.rows)

        def _on_double_clicked(self, index) -> None:
            rows = self._model.rows
            if self.on_activated and index.isValid() and index.row() < len(rows):
                self.on_activated(rows[index.row()])



    # -- flow graph diff ---------------------------------------------------

    # IDA's own graph widget rather than the Java UI: it docks like every other
    # view, needs no second process, and colours nodes directly.
    try:
        import ida_graph
        import ida_gdl
        import ida_lines

        GRAPH_AVAILABLE = True
    except Exception:
        GRAPH_AVAILABLE = False

    # Node colours are BGR, which is what IDA expects -- not RGB.
    _COLOUR_MATCHED = 0x90EE90      # light green
    _COLOUR_UNMATCHED = 0x9090EE    # light red
    _COLOUR_IDENTICAL = 0xD0D0D0    # grey, for a block that matched exactly

    def primary_flow_graph(address: int):
        """Reads the open database's control flow for one function.

        Taken from IDA rather than the .BinExport: it is live, so it reflects
        any analysis or patching done since the export, and it is what the
        analyst is actually looking at.
        """
        function = ida_funcs.get_func(address)
        if function is None:
            raise ValueError(f"no function at 0x{address:X}")

        blocks = []
        edges = []
        for block in ida_gdl.FlowChart(function, flags=ida_gdl.FC_PREDS):
            lines = []
            current = block.start_ea
            while current < block.end_ea and len(lines) < 64:
                lines.append(ida_lines.tag_remove(
                    ida_lines.generate_disasm_line(current) or ""))
                nxt = ida_bytes.get_item_end(current)
                if nxt <= current:
                    break
                current = nxt
            blocks.append((block.start_ea, lines))
            for successor in block.succs():
                edges.append((block.start_ea, successor.start_ea))
        return blocks, edges

    if GRAPH_AVAILABLE:

        class FlowGraphDiffViewer(ida_graph.GraphViewer):
            """The primary function's CFG, coloured by what the differ paired.

            Only the primary side is drawn. A single GraphViewer cannot show
            two graphs side by side, and the useful part is knowing which of
            *these* blocks changed -- each matched node names its counterpart,
            so the secondary address is one glance away.
            """

            def __init__(self, title: str, diff: FlowGraphDiff) -> None:
                super().__init__(title, True)
                self._diff = diff

            def OnRefresh(self) -> bool:
                self.Clear()
                for node in self._diff.nodes:
                    self.AddNode(node)
                for source, target in self._diff.edges:
                    self.AddEdge(source, target)
                return True

            def OnGetText(self, node_id):
                node = self[node_id]
                body = "\n".join(node.lines) if node.lines else "(no code)"
                colour = _COLOUR_MATCHED if node.matched else _COLOUR_UNMATCHED
                return (f"{node.title}\n{body}", colour)

            def OnDblClick(self, node_id) -> bool:
                ida_kernwin.jumpto(self[node_id].address)
                return True

        def show_flow_graph_diff(match_row, database) -> None:
            """Builds and shows the diff view for one match."""
            blocks, edges = primary_flow_graph(match_row.address_primary)
            diff = build_flow_graph_diff(
                blocks, edges,
                database.basic_block_matches(match_row.match_id))

            name = match_row.name_primary or f"0x{match_row.address_primary:X}"
            viewer = FlowGraphDiffViewer(f"BinDiff - {name}", diff)
            viewer.Show()
            ida_kernwin.msg(f"[BinDiff] {diff.summary}\n")
            return viewer

    class UnmatchedTableModel(QtCore.QAbstractTableModel):
        """Serves UnmatchedRow objects to a view on demand.

        Same reasoning as MatchTableModel: on a real binary the unmatched
        list is not a short one -- a diff that matches 5956 functions can
        leave thousands unaccounted for on either side -- and a widget per
        cell makes the panel slow to open and slow to filter.
        """

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self._rows: List[UnmatchedRow] = []
            self._cached_index = -1
            self._cached_values: tuple = ()

        def rowCount(self, parent=None) -> int:
            if parent is not None and parent.isValid():
                return 0
            return len(self._rows)

        def columnCount(self, parent=None) -> int:
            if parent is not None and parent.isValid():
                return 0
            return len(UNMATCHED_COLUMNS)

        def data(self, index, role=None):
            if not index.isValid():
                return None
            if role is None:
                role = Qt.DisplayRole
            if role != Qt.DisplayRole or index.row() >= len(self._rows):
                return None
            if index.row() != self._cached_index:
                self._cached_index = index.row()
                self._cached_values = unmatched_cell_values(
                    self._rows[index.row()])
            return self._cached_values[index.column()]

        def headerData(self, section, orientation, role=None):
            if role is None:
                role = Qt.DisplayRole
            if role != Qt.DisplayRole or orientation != Qt.Horizontal:
                return None
            if 0 <= section < len(UNMATCHED_COLUMNS):
                return UNMATCHED_COLUMNS[section][1]
            return None

        def set_rows(self, rows: Sequence[UnmatchedRow]) -> None:
            self.beginResetModel()
            self._rows = list(rows)
            self._cached_index = -1
            self.endResetModel()

        @property
        def rows(self) -> List[UnmatchedRow]:
            return self._rows

    class UnmatchedTable(_SizesColumnsOnce, QtWidgets.QTableView):
        """Functions on one side that no match refers to."""

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self._model = UnmatchedTableModel(self)
            self.setModel(self._model)
            self.setEditTriggers(_no_edit_triggers())
            self.setSelectionBehavior(_select_rows())
            self.setSelectionMode(_extended_selection())
            self.setAlternatingRowColors(True)
            self.verticalHeader().setVisible(False)

            metrics = self.fontMetrics()
            self.verticalHeader().setDefaultSectionSize(metrics.height() + 4)
            self.setWordWrap(False)

            header = self.horizontalHeader()
            # Interactive, not ResizeToContents. ResizeToContents locks the
            # header: the columns are sized for the widest cell and cannot be
            # dragged, so one long mangled name makes its column
            # unmanageable and there is nothing to be done about it.
            # Interactive plus a one-off sizing gives sensible defaults that
            # can then be changed.
            _set_interactive(header)
            header.setStretchLastSection(True)
            header.setSectionsClickable(True)
            header.sectionClicked.connect(self._on_header_clicked)

            self._sort_column = "address"
            self._sort_descending = False
            self.on_activated: Optional[Callable[[UnmatchedRow], None]] = None
            self.doubleClicked.connect(self._on_double_clicked)

            # This panel had no context menu at all, so the actions the plugin
            # registers for it -- add a match, copy an address -- were
            # registered and unreachable.
            self.context_actions: Sequence[str] = ()
            self.on_action: Optional[Callable[[str], None]] = None
            self.setContextMenuPolicy(Qt.CustomContextMenu)
            self.customContextMenuRequested.connect(self._show_context_menu)

        def _show_context_menu(self, position) -> None:
            show_action_menu(self, self.context_actions, self.on_action,
                             position)

        def set_rows(self, rows: Sequence[UnmatchedRow]) -> None:
            self._model.set_rows(
                sort_unmatched(rows, self._sort_column, self._sort_descending))
            self._size_columns_once()

        @property
        def _rows(self) -> List[UnmatchedRow]:
            return self._model.rows

        def selected_rows(self) -> List[UnmatchedRow]:
            rows = self._model.rows
            indexes = {index.row() for index in self.selectedIndexes()}
            return [rows[i] for i in sorted(indexes) if i < len(rows)]

        def _on_header_clicked(self, section: int) -> None:
            column = UNMATCHED_COLUMNS[section][0]
            if column == self._sort_column:
                self._sort_descending = not self._sort_descending
            else:
                self._sort_column, self._sort_descending = column, False
            self.set_rows(self._model.rows)

        def _on_double_clicked(self, index) -> None:
            rows = self._model.rows
            if self.on_activated and index.isValid() and index.row() < len(rows):
                self.on_activated(rows[index.row()])

    class ControlPanel(ida_kernwin.PluginForm):
        """One place to drive the plugin from.

        Everything here was reachable only through menus, and three of the
        four view entries spent the morning disabled because IDA had been
        told once that they were permanently unavailable. Buttons whose
        enabled state is ours sidestep that entirely.

        The primary side is always the open database -- this is an assistant
        to the IDB in front of you, not a standalone workbench -- so there is
        one file picker and it is the secondary.

        It implements the panel protocol DiffRun expects (update_progress and
        finish), so a diff started from here reports into it rather than
        opening a second window. The separate DiffProgressForm remains for a
        diff started from the menus.
        """

        VIEWS = (("matched", "Matched functions"),
                 ("statistics", "Statistics"),
                 ("primary_unmatched", "Primary unmatched"),
                 ("secondary_unmatched", "Secondary unmatched"))

        def __init__(self, callbacks: dict) -> None:
            super().__init__()
            self._callbacks = callbacks
            self.parent = None
            self._view_buttons: dict = {}
            self._results_open = False
            self._started = 0.0
            self._done = True

        # -- construction ----------------------------------------------------

        def OnCreate(self, form) -> None:
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(8)

            layout.addWidget(self._diff_group())
            layout.addWidget(self._results_group())
            self._progress_box = self._progress_group()
            layout.addWidget(self._progress_box)
            layout.addWidget(self._views_group())
            layout.addStretch(1)

            self._progress_box.setVisible(False)
            self._refresh_enabled()
            # The checkbox starts on, so say so rather than waiting for the
            # first toggle to start the timer.
            self._emit_autosave()

        def _diff_group(self):
            box = QtWidgets.QGroupBox("Diff against")
            row = QtWidgets.QHBoxLayout(box)
            self._secondary = QtWidgets.QLineEdit()
            self._secondary.setPlaceholderText(
                "Binary, .i64 database or .BinExport -- the primary is the "
                "database you have open")
            browse = QtWidgets.QPushButton("Browse...")
            browse.clicked.connect(self._browse)
            self._diff_button = QtWidgets.QPushButton("Diff")
            self._diff_button.setToolTip(
                "Exports your open database and diffs it against the file "
                "above.\nA .BinExport is used as it is, so only your side is "
                "exported.")
            self._diff_button.clicked.connect(self._start_diff)
            row.addWidget(self._secondary, 1)
            row.addWidget(browse)
            row.addWidget(self._diff_button)
            return box

        def _results_group(self):
            box = QtWidgets.QGroupBox("Results")
            row = QtWidgets.QHBoxLayout(box)
            load = QtWidgets.QPushButton("Load...")
            load.setToolTip("Open a .BinDiff produced earlier.")
            load.clicked.connect(lambda: self._call("on_load"))
            self._save_button = QtWidgets.QPushButton("Save")
            self._save_button.setToolTip(
                "Write confirmations, deletions and manual matches back to "
                "the .BinDiff.")
            self._save_button.clicked.connect(lambda: self._call("on_save"))
            # A dot and a filename, with the full path on hover. "results
            # loaded" answers a question nobody was asking; which results is
            # the thing you need when two diffs are open in two IDAs.
            self._results_dot = QtWidgets.QLabel()
            self._results_label = QtWidgets.QLabel()

            self._autosave = QtWidgets.QCheckBox("Auto-save every")
            self._autosave.setToolTip(
                "Commit edits to the .BinDiff on a timer.\n\n"
                "Confirmations, deletions, manual matches and ported names "
                "are held in an open transaction until saved. With this on "
                "they are written periodically instead.\n\n"
                "Note that Revert undoes what has not been saved, so a "
                "shorter interval leaves less to revert.")
            self._autosave.setChecked(True)
            self._autosave_seconds = QtWidgets.QSpinBox()
            self._autosave_seconds.setRange(5, 3600)
            self._autosave_seconds.setValue(60)
            self._autosave_seconds.setSuffix(" s")
            self._autosave_seconds.setToolTip(
                "How often to save, in seconds.")
            self._autosave.toggled.connect(self._emit_autosave)
            self._autosave_seconds.valueChanged.connect(self._emit_autosave)

            row.addWidget(load)
            row.addWidget(self._save_button)
            row.addSpacing(12)
            row.addWidget(self._autosave)
            row.addWidget(self._autosave_seconds)
            row.addStretch(1)
            row.addWidget(self._results_dot)
            row.addWidget(self._results_label)
            self._set_results_text(False, None, None)
            return box

        def _set_results_text(self, open_, path, matches) -> None:
            colour = "#2e9e2e" if open_ else "#9a9a9a"
            self._results_dot.setText("\u25cf")
            self._results_dot.setStyleSheet(f"color: {colour};")
            if not open_:
                self._results_label.setText("nothing loaded")
                self._results_label.setToolTip("")
                self._results_dot.setToolTip("")
                return
            name = Path(path).name if path else "results"
            counted = f"  --  {matches:,} matches" if matches is not None else ""
            self._results_label.setText(f"{name}{counted}")
            tip = str(path) if path else ""
            self._results_label.setToolTip(tip)
            self._results_dot.setToolTip(tip)

        def _progress_group(self):
            box = QtWidgets.QGroupBox("Progress")
            column = QtWidgets.QVBoxLayout(box)
            self._bar = QtWidgets.QProgressBar()
            self._bar.setRange(0, 0)
            self._detail = QtWidgets.QLabel()
            row = QtWidgets.QHBoxLayout()
            self._elapsed = QtWidgets.QLabel()
            self._cancel = QtWidgets.QPushButton("Cancel")
            self._cancel.clicked.connect(lambda: self._call("on_cancel"))
            self._hide = QtWidgets.QPushButton("Hide")
            self._hide.setToolTip("Put the progress away. Results stay open.")
            self._hide.clicked.connect(
                lambda: self._progress_box.setVisible(False))
            self._hide.setVisible(False)
            row.addWidget(self._elapsed)
            row.addStretch(1)
            row.addWidget(self._cancel)
            row.addWidget(self._hide)
            column.addWidget(self._bar)
            column.addWidget(self._detail)
            column.addLayout(row)

            self._timer = QtCore.QTimer(self.parent)
            self._timer.timeout.connect(self._tick)
            return box

        def _views_group(self):
            box = QtWidgets.QGroupBox("Views")
            grid = QtWidgets.QGridLayout(box)
            for index, (key, label) in enumerate(self.VIEWS):
                button = QtWidgets.QPushButton(label)
                button.clicked.connect(
                    lambda _checked=False, k=key: self._call("on_show", k))
                grid.addWidget(button, index // 2, index % 2)
                self._view_buttons[key] = button
            return box

        # -- state -----------------------------------------------------------

        def _emit_autosave(self, *_args) -> None:
            self._autosave_seconds.setEnabled(self._autosave.isChecked())
            self._call("on_autosave", self._autosave.isChecked(),
                       self._autosave_seconds.value())

        def autosave_settings(self) -> tuple:
            """(enabled, seconds), for a caller starting the timer."""
            return (self._autosave.isChecked(), self._autosave_seconds.value())

        def _call(self, name, *args):
            callback = self._callbacks.get(name)
            if callback is not None:
                callback(*args)

        def _browse(self) -> None:
            path = ida_kernwin.ask_file(
                False, "*.BinExport;*.i64;*.idb;*.*",
                "Select the secondary binary, database or export")
            if path:
                self._secondary.setText(path)

        def _start_diff(self) -> None:
            path = self._secondary.text().strip()
            if not path:
                ida_kernwin.warning("Choose a file to diff against first.")
                return
            self._call("on_diff", path)

        def set_results(self, open_: bool, path=None, matches=None) -> None:
            """What is loaded, and therefore what is available.

            Pushed by the plugin rather than inferred here: the panel does not
            reach into the controller, and IDA's own action state is not to be
            trusted for this -- being told once that the views were
            unavailable is what left them greyed for a whole session.
            """
            self._results_open = open_
            if self.parent is None:
                return
            self._set_results_text(open_, path, matches)
            self._refresh_enabled()

        def _refresh_enabled(self) -> None:
            if self.parent is None:
                return
            self._save_button.setEnabled(self._results_open)
            for button in self._view_buttons.values():
                button.setEnabled(self._results_open)

        # -- the panel protocol DiffRun expects -------------------------------

        def start(self, title: str) -> None:
            if self.parent is None:
                return
            self._done = False
            self._started = time.monotonic()
            self._progress_box.setVisible(True)
            self._progress_box.setTitle(title)
            self._bar.setRange(0, 0)
            self._detail.setText("starting...")
            self._elapsed.setText("")
            self._cancel.setEnabled(True)
            self._hide.setVisible(False)
            self._diff_button.setEnabled(False)
            self._timer.start(1000)

        def _tick(self) -> None:
            if self.parent is None or self._done:
                return
            self._elapsed.setText(
                format_elapsed(time.monotonic() - self._started))

        def update_progress(self, progress: DiffProgress) -> None:
            if self.parent is None:
                return
            if progress.fraction is None:
                self._bar.setRange(0, 0)
            else:
                self._bar.setRange(0, 100)
                self._bar.setValue(int(progress.fraction * 100))
            self._detail.setText(progress.message)

        def finish(self, message: str) -> None:
            self._done = True
            if self.parent is None:
                return
            self._timer.stop()
            self._bar.setRange(0, 100)
            self._bar.setValue(100)
            self._cancel.setEnabled(False)
            self._hide.setVisible(True)
            self._diff_button.setEnabled(True)
            self._detail.setText(message)
            self._elapsed.setText(
                f"Took {format_elapsed(time.monotonic() - self._started)}")

        def OnClose(self, form) -> None:
            self.parent = None

        def Show(self):
            return ida_kernwin.PluginForm.Show(
                self, "BinDiff",
                options=(ida_kernwin.PluginForm.WOPN_PERSIST
                         | ida_kernwin.PluginForm.WCLS_SAVE
                         | ida_kernwin.PluginForm.WOPN_RESTORE
                         | ida_kernwin.PluginForm.WOPN_TAB),
            )

    class DiffProgressForm(ida_kernwin.PluginForm):
        """Live status for a diff running in a worker process.

        A dockable panel rather than IDA's wait box, which is modal: the point
        of running the diff out of process is that the database stays usable
        while it runs, and a modal box would give that back.

        Nothing here pumps the event loop. A script that does its work on the
        UI thread has to call processEvents() to stay responsive -- eidolon's
        pattern -- but the work is in another process entirely, so the UI
        thread is already free and re-entering the event loop by hand would
        only invite reentrancy bugs.

        Every method must be called on the UI thread; see the plugin's
        _run_diff_async, which posts them there.
        """

        def __init__(self, title: str,
                     on_cancel: Optional[Callable[[], None]] = None) -> None:
            super().__init__()
            self._title = title
            self._on_cancel = on_cancel
            self._started = time.monotonic()
            self._last: Optional[DiffProgress] = None
            self._done = False
            self.parent = None

        def OnCreate(self, form) -> None:
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)

            self._status = QtWidgets.QLabel(self._title)
            self._status.setWordWrap(True)
            self._detail = QtWidgets.QLabel("starting...")
            self._elapsed = QtWidgets.QLabel("Elapsed: 0s")

            self._bar = QtWidgets.QProgressBar()
            # 0/0 is Qt's indeterminate bar: the right thing to show while an
            # export runs, because there is genuinely no fraction to report.
            self._bar.setRange(0, 0)

            self._cancel = QtWidgets.QPushButton("Cancel")
            self._cancel.setEnabled(self._on_cancel is not None)
            self._cancel.clicked.connect(self._request_cancel)

            # Appears only once there is nothing left to watch. While a diff
            # runs the panel is the only thing reporting it, so there is
            # nothing to offer to hide.
            self._hide = QtWidgets.QPushButton("Hide")
            self._hide.setToolTip(
                "Close this panel. The results stay open.")
            self._hide.clicked.connect(lambda: self.Close(0))
            self._hide.setVisible(False)

            buttons = QtWidgets.QHBoxLayout()
            buttons.addWidget(self._elapsed)
            buttons.addStretch(1)
            buttons.addWidget(self._hide)
            buttons.addWidget(self._cancel)

            layout.addWidget(self._status)
            layout.addWidget(self._bar)
            layout.addWidget(self._detail)
            layout.addLayout(buttons)
            layout.addStretch(1)

            # The elapsed clock ticks on its own rather than only when a
            # progress record arrives: a matching step can run for minutes
            # without one, and a status panel that stops moving reads as a
            # hang. Same reason eidolon runs a 1s QTimer beside its worker.
            self._timer = QtCore.QTimer(self.parent)
            self._timer.timeout.connect(self._tick)
            self._timer.start(1000)
            if self._last is not None:
                self.update_progress(self._last)

        def OnClose(self, form) -> None:
            timer = getattr(self, "_timer", None)
            if timer is not None:
                timer.stop()
            self.parent = None

        def _tick(self) -> None:
            if self.parent is None or self._done:
                return
            self._elapsed.setText(
                f"Elapsed: {format_elapsed(time.monotonic() - self._started)}")

        def _request_cancel(self) -> None:
            if self._on_cancel is None:
                return
            self._cancel.setEnabled(False)
            self._detail.setText("cancelling...")
            self._on_cancel()

        def update_progress(self, progress: DiffProgress) -> None:
            """Shows one progress record. Cheap enough to call per record."""
            self._last = progress
            if self.parent is None:
                return  # Created later; OnCreate replays the last record.
            percentage = progress.percentage
            if percentage is None:
                self._bar.setRange(0, 0)
            else:
                self._bar.setRange(0, 100)
                self._bar.setValue(percentage)
            self._detail.setText(progress.describe())

        def finish(self, message: str) -> None:
            """Stops the clock and leaves the outcome on screen.

            The panel is not closed: when a diff fails, the last thing it said
            it was doing is the most useful thing on the screen.
            """
            self._done = True
            if self.parent is None:
                return
            self._timer.stop()
            self._bar.setRange(0, 100)
            self._bar.setValue(100)
            self._cancel.setEnabled(False)
            self._hide.setVisible(True)
            self._detail.setText(message)
            self._elapsed.setText(
                f"Took {format_elapsed(time.monotonic() - self._started)}")

        def Show(self):
            return ida_kernwin.PluginForm.Show(
                self, self._title,
                options=(ida_kernwin.PluginForm.WOPN_PERSIST
                         | ida_kernwin.PluginForm.WOPN_TAB),
            )

    class UnmatchedFunctionsForm(ida_kernwin.PluginForm):
        """Dockable list of unmatched functions for one side."""

        def __init__(self, rows: Sequence[UnmatchedRow], side: str,
                     on_jump: Optional[Callable[[int], None]] = None,
                     context_actions: Sequence = (),
                     on_action: Optional[Callable[[str], None]] = None) -> None:
            super().__init__()
            self._all_rows = list(rows)
            self._context_actions = tuple(context_actions)
            self._on_action = on_action
            self._filtered = IncrementalFilter(text_query_narrows,
                                               filter_unmatched)
            self._side = side
            self._on_jump = on_jump
            self._table: Optional[UnmatchedTable] = None
            self._status: Optional[QtWidgets.QLabel] = None
            self.parent = None

        def OnCreate(self, form) -> None:
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)

            self._search = QtWidgets.QLineEdit()
            self._search.setPlaceholderText("Filter by name or address...")
            self._search.setClearButtonEnabled(True)
            self._debounce = debounced(self.parent, self._apply)
            self._search.textChanged.connect(lambda _t: self._debounce.start())

            self._table = UnmatchedTable()
            self._table.context_actions = self._context_actions
            self._table.on_action = self._on_action
            if self._on_jump is not None:
                self._table.on_activated = lambda row: self._on_jump(row.address)
            self._status = QtWidgets.QLabel()

            layout.addWidget(self._search)
            layout.addWidget(self._table, 1)
            layout.addWidget(self._status)
            self._apply()

        def OnClose(self, form) -> None:
            self._table = None
            self.parent = None

        def set_rows(self, rows: Sequence[UnmatchedRow]) -> None:
            self._all_rows = list(rows)
            # New data invalidates the base narrowing would have built on.
            self._filtered.invalidate()
            if self._table is not None:
                self._apply()

        def _apply(self) -> None:
            if self._table is None:
                return
            visible = self._filtered(self._all_rows, self._search.text())
            self._table.set_rows(visible)
            if self._status is not None:
                self._status.setText(
                    f"{len(visible)} of {len(self._all_rows)} unmatched "
                    f"({self._side}); library code hidden")

        def Show(self):
            return ida_kernwin.PluginForm.Show(
                self, f"BinDiff - Unmatched ({self._side})",
                options=(ida_kernwin.PluginForm.WOPN_PERSIST
                         | ida_kernwin.PluginForm.WCLS_SAVE
                         | ida_kernwin.PluginForm.WOPN_RESTORE
                         | ida_kernwin.PluginForm.WOPN_TAB),
            )

    class FilterBar(QtWidgets.QWidget):
        """Filter controls above the match table.

        Emits nothing; it calls back with a MatchFilter so the panel does not
        have to know which control changed.
        """

        def __init__(self, on_changed: Callable[[MatchFilter], None],
                     parent=None) -> None:
            super().__init__(parent)
            self._on_changed = on_changed

            self._text = QtWidgets.QLineEdit()
            self._text.setPlaceholderText("Filter by name or address...")
            self._text.setClearButtonEnabled(True)

            self._min_similarity = QtWidgets.QDoubleSpinBox()
            self._min_similarity.setRange(0.0, 1.0)
            self._min_similarity.setSingleStep(0.05)
            self._min_similarity.setDecimals(2)

            self._min_confidence = QtWidgets.QDoubleSpinBox()
            self._min_confidence.setRange(0.0, 1.0)
            self._min_confidence.setSingleStep(0.05)
            self._min_confidence.setDecimals(2)

            # Both of these were opaque: the labels name a property of a
            # match without saying which, and neither is guessable.
            self._manual_only = QtWidgets.QCheckBox("Manual only")
            self._manual_only.setToolTip(
                "Show only matches you made or confirmed by hand.\n"
                "The engine's own matches are hidden. A confirmed match "
                "reads as manual, which is why the Algorithm column changes "
                "to \"function: manual\" after confirming.")
            # The porting worklist, as one tick. Named on the other side and
            # not on this one is exactly "somebody did this work in the old
            # database and it has not reached the new one".
            self._needs_a_name = QtWidgets.QCheckBox("Needs a name")
            self._needs_a_name.setToolTip(
                "Show only matches that are named on the other side and not "
                "on this one.\n\n"
                "A row where Name Primary is still sub_… and Name Secondary "
                "is not: work done in the old database that has not been "
                "brought across. Select them and import symbols to bring the "
                "names, comments and prototypes over.")

            self._changed_only = QtWidgets.QCheckBox("Changed only")
            self._changed_only.setToolTip(
                "Show only matches whose two functions differ FROM EACH "
                "OTHER.\n\n"
                "Not changed since a previous diff, and not changed by you: "
                "changed between the primary and the secondary. A match "
                "showing \"-------\" in the Change column is a function that "
                "came through the version bump identical, and this hides "
                "those -- what is left is what actually moved.\n\n"
                + change_legend())

            layout = QtWidgets.QHBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self._text, 1)
            layout.addWidget(QtWidgets.QLabel("Min similarity"))
            layout.addWidget(self._min_similarity)
            self._min_similarity.setToolTip(
                "Hide matches below this similarity.\n"
                "Similarity is how alike the two functions are; the column "
                "is coloured by it.")
            self._min_confidence.setToolTip(
                "Hide matches below this confidence.\n"
                "Confidence is how much the engine trusts the pairing, and "
                "is mostly decided by how well the basic blocks matched "
                "rather than by which algorithm found it.")
            layout.addWidget(QtWidgets.QLabel("Min confidence"))
            layout.addWidget(self._min_confidence)
            layout.addWidget(self._needs_a_name)
            layout.addWidget(self._manual_only)
            layout.addWidget(self._changed_only)

            # Typing is debounced; the rest is not. A spinbox or a checkbox
            # is one deliberate act and answers immediately.
            self._debounce = debounced(self, self._emit)
            self._text.textChanged.connect(lambda _t: self._debounce.start())
            self._min_similarity.valueChanged.connect(self._emit)
            self._min_confidence.valueChanged.connect(self._emit)
            self._needs_a_name.toggled.connect(self._emit)
            self._manual_only.toggled.connect(self._emit)
            self._changed_only.toggled.connect(self._emit)

        def current_filter(self) -> MatchFilter:
            return MatchFilter(
                text=self._text.text(),
                min_similarity=self._min_similarity.value(),
                min_confidence=self._min_confidence.value(),
                needs_a_name=self._needs_a_name.isChecked(),
                manual_only=self._manual_only.isChecked(),
                changed_only=self._changed_only.isChecked(),
            )

        def _emit(self, *_args) -> None:
            self._on_changed(self.current_filter())

    class MatchedFunctionsForm(ida_kernwin.PluginForm):
        """Dockable panel listing matched functions."""

        def __init__(self, rows: Sequence[MatchRow],
                     on_jump: Optional[Callable[[int], None]] = None,
                     context_actions: Sequence = (),
                     on_action: Optional[Callable[[str], None]] = None) -> None:
            super().__init__()
            self._all_rows = list(rows)
            self._on_jump = on_jump
            self._context_actions = tuple(context_actions)
            self._on_action = on_action
            self._table: Optional[MatchTable] = None
            self._status: Optional[QtWidgets.QLabel] = None
            self.parent = None

        def OnCreate(self, form) -> None:
            # PluginForm is not a QObject and the widget IDA returns cannot be
            # subclassed, so the panel owns its children rather than deriving.
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)

            self._filtered = IncrementalFilter(
                lambda previous, current: current.narrows(previous),
                filter_rows)
            self._filter_bar = FilterBar(self._apply_filter)
            self._table = MatchTable()
            self._table.on_activated = self._activate
            self._table.context_actions = self._context_actions
            self._table.on_action = self._on_action
            self._status = QtWidgets.QLabel()

            layout.addWidget(self._filter_bar)
            layout.addWidget(self._table, 1)
            layout.addWidget(self._status)

            self._apply_filter(self._filter_bar.current_filter())

        def OnClose(self, form) -> None:
            self._table = None
            self.parent = None

        def set_rows(self, rows: Sequence[MatchRow]) -> None:
            self._all_rows = list(rows)
            # New data, so the cached result narrowing would build on no
            # longer describes anything.
            self._filtered.invalidate()
            if self._table is not None:
                self._apply_filter(self._filter_bar.current_filter())

        def _apply_filter(self, match_filter: MatchFilter) -> None:
            if self._table is None:
                return
            visible = self._filtered(self._all_rows, match_filter)
            self._table.set_rows(visible)
            if self._status is not None:
                self._status.setText(
                    f"{len(visible)} of {len(self._all_rows)} matches")

        def selected_rows(self) -> List[MatchRow]:
            return self._table.selected_rows() if self._table else []

        def _activate(self, row: MatchRow) -> None:
            if self._on_jump is not None:
                self._on_jump(row.address_primary)

        def Show(self, caption: str = "BinDiff - Matched Functions"):
            return ida_kernwin.PluginForm.Show(
                self, caption,
                options=(ida_kernwin.PluginForm.WOPN_PERSIST
                         | ida_kernwin.PluginForm.WCLS_SAVE
                         | ida_kernwin.PluginForm.WOPN_RESTORE
                         | ida_kernwin.PluginForm.WOPN_TAB),
            )

    class StatisticsForm(ida_kernwin.PluginForm):
        """Read-only summary of the two inputs, as a dockable tab.

        It was a modal dialog, which meant it could not sit beside the matches
        it describes and had to be dismissed before anything else could be
        done. Every other view here docks; this is not different in kind.
        """

        def __init__(self, rows: Sequence[StatisticRow]) -> None:
            super().__init__()
            self._rows = list(rows)
            self._table = None
            self.parent = None

        def OnCreate(self, form) -> None:
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(0, 0, 0, 0)
            self._table = QtWidgets.QTableWidget(0, 3, self.parent)
            self._table.setHorizontalHeaderLabels(["", "Primary", "Secondary"])
            self._table.setEditTriggers(_no_edit_triggers())
            self._table.verticalHeader().setVisible(False)
            self._table.setAlternatingRowColors(True)
            self._table.setWordWrap(False)
            metrics = self._table.fontMetrics()
            self._table.verticalHeader().setDefaultSectionSize(
                metrics.height() + 4)
            header = self._table.horizontalHeader()
            _set_interactive(header)
            header.setStretchLastSection(True)
            layout.addWidget(self._table)
            self.set_rows(self._rows)

        def set_rows(self, rows: Sequence[StatisticRow]) -> None:
            self._rows = list(rows)
            if self._table is None:
                return
            self._table.setRowCount(len(self._rows))
            for index, row in enumerate(self._rows):
                for column, value in enumerate((row.label, row.primary,
                                                row.secondary)):
                    self._table.setItem(
                        index, column, QtWidgets.QTableWidgetItem(str(value)))
            self._table.resizeColumnsToContents()

        def OnClose(self, form) -> None:
            self._table = None
            self.parent = None

        def Show(self):
            return ida_kernwin.PluginForm.Show(
                self, "BinDiff - Statistics",
                options=(ida_kernwin.PluginForm.WOPN_PERSIST
                         | ida_kernwin.PluginForm.WCLS_SAVE
                         | ida_kernwin.PluginForm.WOPN_RESTORE
                         | ida_kernwin.PluginForm.WOPN_TAB),
            )

    class AlgorithmConfigDialog(QtWidgets.QDialog):
        """Enable, disable, reorder and re-weight the matching algorithms.

        Writes straight through to the engine config, so everything here takes
        effect on the next diff -- confidence included. The engine used to read
        confidence once per process, which made it look editable and silently
        ignore the edit; it now reads a snapshot that this rebuilds.
        """

        def __init__(self, config: dict, on_apply: Callable[[dict], None],
                     parent=None) -> None:
            super().__init__(parent)
            self.setWindowTitle("BinDiff - Matching Algorithms")
            self.resize(640, 560)
            self._config = config
            self._on_apply = on_apply

            self._tabs = QtWidgets.QTabWidget(self)
            self._function_list = self._build_list("function_matching")
            self._basic_block_list = self._build_list("basic_block_matching")
            self._tabs.addTab(self._function_list, "Functions")
            self._tabs.addTab(self._basic_block_list, "Basic blocks")

            note = QtWidgets.QLabel(
                "Unchecked algorithms are not run. Order is priority order; "
                "drag to reorder. Confidence weights how much a match from an "
                "algorithm is trusted -- double-click to edit. All of it "
                "applies to the next diff.")
            note.setWordWrap(True)

            buttons = QtWidgets.QDialogButtonBox()
            try:
                standard = QtWidgets.QDialogButtonBox.StandardButton
                buttons.setStandardButtons(standard.Ok | standard.Cancel
                                           | standard.RestoreDefaults)
            except AttributeError:
                buttons.setStandardButtons(
                    QtWidgets.QDialogButtonBox.Ok
                    | QtWidgets.QDialogButtonBox.Cancel
                    | QtWidgets.QDialogButtonBox.RestoreDefaults)
            buttons.accepted.connect(self._apply)
            buttons.rejected.connect(self.reject)

            layout = QtWidgets.QVBoxLayout(self)
            layout.addWidget(note)
            layout.addWidget(self._tabs, 1)
            layout.addWidget(buttons)

        def _build_list(self, key: str) -> QtWidgets.QTableWidget:
            """One row per algorithm: enabled, name, editable confidence."""
            steps = self._config.get(key, [])
            table = QtWidgets.QTableWidget(len(steps), 2)
            table.setHorizontalHeaderLabels(["Algorithm", "Confidence"])
            table.verticalHeader().setVisible(False)
            table.setSelectionBehavior(_select_rows())
            try:
                table.setDragDropMode(
                    QtWidgets.QAbstractItemView.DragDropMode.InternalMove)
            except AttributeError:
                table.setDragDropMode(QtWidgets.QAbstractItemView.InternalMove)

            for row, step in enumerate(steps):
                name_item = QtWidgets.QTableWidgetItem(step["name"])
                name_item.setData(Qt.UserRole, step["name"])
                try:
                    name_item.setFlags(
                        (name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                        | Qt.ItemFlag.ItemIsUserCheckable)
                    name_item.setCheckState(Qt.CheckState.Checked)
                except AttributeError:
                    name_item.setFlags((name_item.flags() & ~Qt.ItemIsEditable)
                                       | Qt.ItemIsUserCheckable)
                    name_item.setCheckState(Qt.Checked)
                table.setItem(row, 0, name_item)

                confidence = QtWidgets.QTableWidgetItem(
                    f"{float(step.get('confidence', 0.0)):.2f}")
                table.setItem(row, 1, confidence)

            try:
                table.horizontalHeader().setSectionResizeMode(
                    0, QtWidgets.QHeaderView.ResizeMode.Stretch)
            except AttributeError:
                table.horizontalHeader().setSectionResizeMode(
                    0, QtWidgets.QHeaderView.Stretch)
            return table

        @staticmethod
        def _selected_steps(table: QtWidgets.QTableWidget) -> List[dict]:
            """The enabled rows, in display order, with edited confidences.

            A confidence that will not parse, or falls outside 0..1, is skipped
            rather than clamped: silently substituting a value the user did not
            type would be worse than leaving the row as it was.
            """
            steps = []
            for row in range(table.rowCount()):
                name_item = table.item(row, 0)
                if name_item is None:
                    continue
                try:
                    checked = name_item.checkState() == Qt.CheckState.Checked
                except AttributeError:
                    checked = name_item.checkState() == Qt.Checked
                if not checked:
                    continue

                confidence_item = table.item(row, 1)
                try:
                    confidence = float(confidence_item.text())
                except (AttributeError, TypeError, ValueError):
                    continue
                if not 0.0 <= confidence <= 1.0:
                    continue
                steps.append({"name": name_item.data(Qt.UserRole),
                              "confidence": confidence})
            return steps

        def _apply(self) -> None:
            functions = self._selected_steps(self._function_list)
            basic_blocks = self._selected_steps(self._basic_block_list)
            # The engine aborts on an empty list, so refuse before it can.
            if not functions or not basic_blocks:
                QtWidgets.QMessageBox.warning(
                    self, "BinDiff",
                    "At least one algorithm must stay enabled on each tab.")
                return
            self._on_apply({"function_matching": functions,
                            "basic_block_matching": basic_blocks})
            self.accept()
