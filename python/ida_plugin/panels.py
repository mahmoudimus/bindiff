"""Qt views for the BinDiff plugin.

What is left here are the tables and the flow-graph view: they render the view
objects from ui_logic and forward user actions back, holding no presentation
logic of their own, so what is worth testing is testable headless. The dock
forms that used to live here are workbench.py and inspector.py now. Widgets are
only defined when IDA is importable, which keeps this module importable in the
test harness -- the same guard d810 and Gepetto use.

Qt5 and Qt6 both work: everything goes through bindiff.qt_shim, which picks
PySide6 (IDA 9.2+) or PyQt5 (IDA 9.1) and papers over the differences.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence

from ida_plugin.porting import OUTCOME_REPLACES_YOURS
from ida_plugin.theme import semantic_tints
from ida_plugin.ui_logic import (
    COLUMNS,
    ColumnVisibility,
    FlowGraphDiff,
    MatchRow,
    STATE_BY_HAND,
    STATE_VERIFIED,
    UNMATCHED_COLUMNS,
    UnmatchedRow,
    build_flow_graph_diff,
    cell_values,
    column_index,
    describe_change_flags,
    is_generated_name,
    sort_unmatched,
    unmatched_cell_values,
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

    def palette_rgb(colour) -> tuple:
        return (colour.red(), colour.green(), colour.blue())

    def _palette_role(palette, name: str):
        """One QPalette colour, spelled for either Qt binding."""
        try:
            role = getattr(QtGui.QPalette.ColorRole, name)
        except AttributeError:
            role = getattr(QtGui.QPalette, name)
        return palette.color(role)

    def tints_for(widget) -> dict:
        """The verdict tints for this widget's palette, as QColors.

        Read at call time, never stored at import: IDA can switch theme
        while the plugin is loaded, and a colour computed once is a colour
        that is wrong after that.
        """
        palette = widget.palette()
        text = palette_rgb(_palette_role(palette, "Text"))
        base = palette_rgb(_palette_role(palette, "Base"))
        return {name: QtGui.QColor(*rgb)
                for name, rgb in semantic_tints(text, base).items()}

    def _align_left():
        """Qt.AlignVCenter | Qt.AlignLeft, spelled for either binding."""
        try:
            flag = Qt.AlignmentFlag
        except AttributeError:
            flag = Qt
        return flag.AlignVCenter | flag.AlignLeft

    class MatchTableModel(QtCore.QAbstractTableModel):
        """Serves MatchRow objects to a view on demand.

        A model rather than a QTableWidget: 10,000 rows by 26 columns is a
        quarter of a million items built per repopulate. The view asks for
        the thirty it paints. Formatting is ui_logic.cell_values; this is
        the adapter, plus the roles that carry the verdict tints.
        """

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self._rows: List[MatchRow] = []
            # data() is called once per visible cell, so the same row is
            # formatted once per column. One slot of memory removes the rest.
            self._cached_index = -1
            self._cached_values: tuple = ()
            self._tints: dict = {}
            self._annotations: dict = {}   # column name -> {match_id: text}

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
            if not index.isValid() or index.row() >= len(self._rows):
                return None
            if role is None:
                role = Qt.DisplayRole
            row = self._rows[index.row()]
            column = COLUMNS[index.column()][0]

            if role == Qt.DisplayRole:
                annotated = self._annotations.get(column)
                if annotated is not None:
                    return annotated.get(row.match_id, "")
                return self._values(index.row())[index.column()]
            if role == Qt.UserRole:
                return row.match_id
            if role == Qt.ForegroundRole and self._tints:
                if column == "trust" or (column == "similarity"
                                         and row.trust != "strong"):
                    tint = self._tints.get(row.trust)
                    return QtGui.QBrush(tint) if tint is not None else None
                return None
            if role == Qt.BackgroundRole and self._tints:
                outcome = self._annotations.get("outcome", {}).get(row.match_id)
                if outcome == OUTCOME_REPLACES_YOURS:
                    return QtGui.QBrush(self._tints["replaces"])
                return None
            if role == Qt.ToolTipRole and column == "changed":
                changed = describe_change_flags(row.change_flags)
                return ", ".join(changed) if changed else "Nothing differs"
            if role == Qt.FontRole and row.state in (STATE_VERIFIED,
                                                     STATE_BY_HAND):
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
            return None

        # -- our interface ---------------------------------------------------

        def set_rows(self, rows: Sequence[MatchRow]) -> None:
            self.beginResetModel()
            self._rows = list(rows)
            self._cached_index = -1
            self.endResetModel()

        def set_tints(self, tints: dict) -> None:
            self._tints = dict(tints)
            self._repaint_everything()

        def set_annotations(self, column: str, values: dict) -> None:
            self._annotations[column] = dict(values)
            self._repaint_everything()

        def _repaint_everything(self) -> None:
            """A colour or an annotation changes every cell at once.

            dataChanged over the whole rectangle rather than a reset: a reset
            drops the selection, and both of these arrive while the analyst is
            looking at rows they picked.
            """
            if self._rows:
                self.dataChanged.emit(self.index(0, 0),
                                      self.index(len(self._rows) - 1,
                                                 len(COLUMNS) - 1))

        @property
        def rows(self) -> List[MatchRow]:
            return self._rows

    class SideCellDelegate(QtWidgets.QStyledItemDelegate):
        """Paints "ADDR  name": address dim and monospaced, name in the
        item's own colour. The named side is the source of a port, so it
        is the side that reads brighter; a generated name on this side is
        dimmed to make the direction legible without an arrow per row."""

        def __init__(self, table, generated_side: str, parent=None) -> None:
            super().__init__(parent)
            self._table = table
            self._generated_side = generated_side  # "primary" | "secondary"

        def paint(self, painter, option, index) -> None:
            text = index.data(Qt.DisplayRole) or ""
            address, _, name = text.partition("  ")
            tints = self._table.current_tints()
            self.initStyleOption(option, index)
            option.text = ""
            style = (option.widget.style() if option.widget
                     else QtWidgets.QApplication.style())
            try:
                item_view_item = QtWidgets.QStyle.ControlElement.CE_ItemViewItem
            except AttributeError:
                item_view_item = QtWidgets.QStyle.CE_ItemViewItem
            style.drawControl(item_view_item, option, painter, option.widget)

            painter.save()
            rect = option.rect.adjusted(4, 0, -4, 0)
            dim = tints.get("dim") or option.palette.text().color()
            mono = QtGui.QFont(option.font)
            mono.setFamily("Menlo")
            try:
                monospace = QtGui.QFont.StyleHint.Monospace
            except AttributeError:
                monospace = QtGui.QFont.Monospace
            mono.setStyleHint(monospace)
            painter.setFont(mono)
            painter.setPen(dim)
            metrics = QtGui.QFontMetrics(mono)
            painter.drawText(rect, _align_left(), address)

            painter.setFont(option.font)
            row = self._table.row_at(index)
            dim_name = (row is not None and is_generated_name(
                row.name_primary if self._generated_side == "primary"
                else row.name_secondary))
            painter.setPen(dim if dim_name else option.palette.text().color())
            offset = metrics.horizontalAdvance(address + "  ")
            painter.drawText(rect.adjusted(offset, 0, 0, 0),
                             _align_left(), name)
            painter.restore()

    class MatchTable(_SizesColumnsOnce, QtWidgets.QTableView):
        """The judgement surface: selection, bulk action, jumping IDA.

        Sorting and filtering happen in the workbench through ui_logic, so
        the order is the same whether it came from a click or a test. The
        context menu is built by the workbench too -- the table only says
        where the click was.
        """

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self._model = MatchTableModel(self)
            self.setModel(self._model)
            self.setEditTriggers(_no_edit_triggers())
            self.setSelectionBehavior(_select_rows())
            self.setSelectionMode(_extended_selection())
            self.setAlternatingRowColors(False)
            self.verticalHeader().setVisible(False)
            self.setShowGrid(False)

            header = self.horizontalHeader()
            # Interactive, not ResizeToContents. ResizeToContents locks the
            # header: the columns are sized for the widest cell and cannot be
            # dragged, so one long mangled name makes its column unmanageable
            # and there is nothing to be done about it. Interactive plus a
            # one-off sizing gives sensible defaults that can then be changed.
            _set_interactive(header)
            header.setStretchLastSection(True)
            header.setSectionsClickable(True)
            header.sectionClicked.connect(self._on_header_clicked)
            try:
                custom_menu = Qt.ContextMenuPolicy.CustomContextMenu
            except AttributeError:
                custom_menu = Qt.CustomContextMenu
            # The header carries its own menu: which columns to show is a
            # property of the table, not an IDA-wide action.
            header.setContextMenuPolicy(custom_menu)
            self.setContextMenuPolicy(custom_menu)
            header.customContextMenuRequested.connect(self.show_column_menu)
            self.customContextMenuRequested.connect(
                lambda position: self.on_context_menu(position)
                if self.on_context_menu else None)

            self._sort_column = "similarity"
            self._sort_descending = True
            self.on_activated: Optional[Callable[[MatchRow], None]] = None
            self.on_selection_changed: Optional[Callable[[list], None]] = None
            self.on_context_menu: Optional[Callable] = None
            self.on_sort_changed: Optional[Callable[[str, bool], None]] = None
            self.on_visibility_changed: Optional[Callable[[], None]] = None
            self.doubleClicked.connect(self._on_double_clicked)
            self.selectionModel().selectionChanged.connect(
                lambda *_: self.on_selection_changed(self.selected_ids())
                if self.on_selection_changed else None)

            # Density. The default row height leaves a table that shows a
            # dozen rows where it could show thirty, and a diff is a list you
            # scan rather than read. Sized from the font rather than a
            # constant so it follows IDA's own scaling.
            metrics = self.fontMetrics()
            self.verticalHeader().setDefaultSectionSize(metrics.height() + 6)
            self.setWordWrap(False)
            self._visibility = ColumnVisibility()
            self._tints: dict = {}
            self.setItemDelegateForColumn(
                column_index("this_database"),
                SideCellDelegate(self, "primary", self))
            self.setItemDelegateForColumn(
                column_index("other_binary"),
                SideCellDelegate(self, "secondary", self))
            self._apply_visibility()

        # -- palette --------------------------------------------------------

        def current_tints(self) -> dict:
            return self._tints

        def refresh_tints(self) -> None:
            self._tints = tints_for(self)
            self._model.set_tints(self._tints)

        def showEvent(self, event) -> None:
            super().showEvent(event)
            self.refresh_tints()

        def changeEvent(self, event) -> None:
            super().changeEvent(event)
            try:
                palette_change = QtCore.QEvent.Type.PaletteChange
            except AttributeError:
                palette_change = QtCore.QEvent.PaletteChange
            if event.type() == palette_change:
                self.refresh_tints()

        # -- columns --------------------------------------------------------

        @property
        def visibility(self) -> ColumnVisibility:
            return self._visibility

        def set_columns(self, names: Sequence[str]) -> None:
            self._visibility = ColumnVisibility(names)
            self._apply_visibility()

        def _apply_visibility(self) -> None:
            for index, (name, _label) in enumerate(COLUMNS):
                self.setColumnHidden(index, not self._visibility.is_visible(name))

        def show_column_menu(self, position) -> None:
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

        # -- rows -----------------------------------------------------------

        def set_rows(self, rows: Sequence[MatchRow]) -> None:
            selected = set(self.selected_ids())
            self._model.set_rows(rows)
            self._size_columns_once()
            if selected:
                self.select_ids(selected)

        def set_annotations(self, column: str, values: dict) -> None:
            self._model.set_annotations(column, values)

        @property
        def rows(self) -> List[MatchRow]:
            return self._model.rows

        def row_at(self, index) -> Optional[MatchRow]:
            rows = self._model.rows
            if not index.isValid() or index.row() >= len(rows):
                return None
            return rows[index.row()]

        def selected_rows(self) -> List[MatchRow]:
            rows = self._model.rows
            indexes = {index.row() for index in self.selectedIndexes()}
            return [rows[i] for i in sorted(indexes) if i < len(rows)]

        def selected_ids(self) -> list:
            return [row.match_id for row in self.selected_rows()]

        def select_ids(self, ids) -> None:
            wanted = set(ids)
            selection = self.selectionModel()
            selection.clearSelection()
            try:
                flag = QtCore.QItemSelectionModel.SelectionFlag
            except AttributeError:
                flag = QtCore.QItemSelectionModel
            flags = flag.Select | flag.Rows
            for position, row in enumerate(self._model.rows):
                if row.match_id in wanted:
                    selection.select(self._model.index(position, 0), flags)

        def _on_header_clicked(self, section: int) -> None:
            column = COLUMNS[section][0]
            if column == self._sort_column:
                self._sort_descending = not self._sort_descending
            else:
                self._sort_column = column
                # Scores read best highest-first; names and addresses ascending.
                self._sort_descending = column in ("similarity", "confidence",
                                                   "trust")
            if self.on_sort_changed:
                self.on_sort_changed(self._sort_column, self._sort_descending)

        def _on_double_clicked(self, index) -> None:
            row = self.row_at(index)
            if self.on_activated and row is not None:
                self.on_activated(row)

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
