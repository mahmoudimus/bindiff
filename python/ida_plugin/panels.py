"""Qt views for the BinDiff plugin.

These render the view objects from ui_logic and forward user actions back; they
hold no presentation logic of their own, so what is worth testing is testable
headless. Widgets are only defined when IDA is importable, which keeps this
module importable in the test harness -- the same guard d810 and Gepetto use.

Qt5 and Qt6 both work: everything goes through bindiff.qt_shim, which picks
PySide6 (IDA 9.2+) or PyQt5 (IDA 9.1) and papers over the differences.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence

from ida_plugin.ui_logic import (
    COLUMNS,
    FlowGraphDiff,
    build_flow_graph_diff,
    UNMATCHED_COLUMNS,
    UnmatchedRow,
    filter_unmatched,
    sort_unmatched,
    MatchFilter,
    MatchRow,
    StatisticRow,
    describe_change_flags,
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
    from bindiff.qt_shim import Qt, QtCore, QtGui, QtWidgets

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

    class MatchTable(QtWidgets.QTableWidget):
        """The matched-functions table.

        Sorting is done in ui_logic rather than by Qt so the order is the same
        whether it came from a click or from a test.
        """

        def __init__(self, parent=None) -> None:
            super().__init__(0, len(COLUMNS), parent)
            self.setHorizontalHeaderLabels([label for _, label in COLUMNS])
            self.setEditTriggers(_no_edit_triggers())
            self.setSelectionBehavior(_select_rows())
            self.setSelectionMode(_extended_selection())
            self.setAlternatingRowColors(True)
            self.verticalHeader().setVisible(False)

            header = self.horizontalHeader()
            try:
                header.setSectionResizeMode(
                    QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
            except AttributeError:
                header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
            header.setSectionsClickable(True)
            header.sectionClicked.connect(self._on_header_clicked)

            self._rows: List[MatchRow] = []
            self._sort_column = "similarity"
            self._sort_descending = True
            self.on_activated: Optional[Callable[[MatchRow], None]] = None
            self.cellDoubleClicked.connect(self._on_double_clicked)

            # Context menu entries are IDA actions, not Qt ones, so they stay
            # in one place: registered once, reachable from both the plugin
            # menu and here, and enabled/disabled by the same predicate.
            self.context_actions: Sequence[str] = ()
            try:
                self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            except AttributeError:
                self.setContextMenuPolicy(Qt.CustomContextMenu)
            self.customContextMenuRequested.connect(self._show_context_menu)

        def _show_context_menu(self, position) -> None:
            if not self.context_actions:
                return
            menu = QtWidgets.QMenu(self)
            for name in self.context_actions:
                if name is None:
                    menu.addSeparator()
                    continue
                action = menu.addAction(name.split(":", 1)[-1].replace("_", " "))
                action.setData(name)
            chosen = menu.exec_(self.viewport().mapToGlobal(position))
            if chosen is not None:
                ida_kernwin.process_ui_action(chosen.data())

        def set_rows(self, rows: Sequence[MatchRow]) -> None:
            self._rows = sort_rows(rows, self._sort_column, self._sort_descending)
            self._repopulate()

        def selected_rows(self) -> List[MatchRow]:
            indexes = {index.row() for index in self.selectedIndexes()}
            return [self._rows[i] for i in sorted(indexes) if i < len(self._rows)]

        def _on_header_clicked(self, section: int) -> None:
            column = COLUMNS[section][0]
            if column == self._sort_column:
                self._sort_descending = not self._sort_descending
            else:
                self._sort_column = column
                # Scores read best highest-first; names and addresses ascending.
                self._sort_descending = column in ("similarity", "confidence")
            self.set_rows(self._rows)

        def _on_double_clicked(self, row: int, _column: int) -> None:
            if self.on_activated and 0 <= row < len(self._rows):
                self.on_activated(self._rows[row])

        def _repopulate(self) -> None:
            self.setRowCount(len(self._rows))
            for index, row in enumerate(self._rows):
                values = (
                    f"{row.similarity:.2f}",
                    f"{row.confidence:.2f}",
                    row.change_text,
                    format_address(row.address_primary),
                    row.name_primary,
                    format_address(row.address_secondary),
                    row.name_secondary,
                    row.algorithm,
                    "yes" if row.comments_ported else "",
                    str(row.basic_blocks),
                    str(row.basic_blocks_primary),
                    str(row.basic_blocks_secondary),
                    str(row.instructions),
                    str(row.instructions_primary),
                    str(row.instructions_secondary),
                    str(row.edges),
                    str(row.edges_primary),
                    str(row.edges_secondary),
                )
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    if column == 0:
                        item.setBackground(QtGui.QBrush(QtGui.QColor(
                            *similarity_color(row.similarity))))
                    if column == 2:
                        changed = describe_change_flags(row.change_flags)
                        item.setToolTip(
                            ", ".join(changed) if changed else "No changes")
                    if row.manual:
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)
                    self.setItem(index, column, item)



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

    class UnmatchedTable(QtWidgets.QTableWidget):
        """Functions on one side that no match refers to."""

        def __init__(self, parent=None) -> None:
            super().__init__(0, len(UNMATCHED_COLUMNS), parent)
            self.setHorizontalHeaderLabels(
                [label for _, label in UNMATCHED_COLUMNS])
            self.setEditTriggers(_no_edit_triggers())
            self.setSelectionBehavior(_select_rows())
            self.setSelectionMode(_extended_selection())
            self.setAlternatingRowColors(True)
            self.verticalHeader().setVisible(False)

            header = self.horizontalHeader()
            try:
                header.setSectionResizeMode(
                    QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
            except AttributeError:
                header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
            header.setSectionsClickable(True)
            header.sectionClicked.connect(self._on_header_clicked)

            self._rows: List[UnmatchedRow] = []
            self._sort_column = "address"
            self._sort_descending = False
            self.on_activated: Optional[Callable[[UnmatchedRow], None]] = None
            self.cellDoubleClicked.connect(self._on_double_clicked)

        def set_rows(self, rows: Sequence[UnmatchedRow]) -> None:
            self._rows = sort_unmatched(rows, self._sort_column,
                                        self._sort_descending)
            self.setRowCount(len(self._rows))
            for index, row in enumerate(self._rows):
                kind = "library" if row.is_library else (
                    "named" if row.has_real_name else "unnamed")
                for column, value in enumerate((row.address_text, row.name, kind)):
                    self.setItem(index, column,
                                 QtWidgets.QTableWidgetItem(value))

        def selected_rows(self) -> List[UnmatchedRow]:
            indexes = {index.row() for index in self.selectedIndexes()}
            return [self._rows[i] for i in sorted(indexes) if i < len(self._rows)]

        def _on_header_clicked(self, section: int) -> None:
            column = UNMATCHED_COLUMNS[section][0]
            if column == self._sort_column:
                self._sort_descending = not self._sort_descending
            else:
                self._sort_column, self._sort_descending = column, False
            self.set_rows(self._rows)

        def _on_double_clicked(self, row: int, _column: int) -> None:
            if self.on_activated and 0 <= row < len(self._rows):
                self.on_activated(self._rows[row])

    class UnmatchedFunctionsForm(ida_kernwin.PluginForm):
        """Dockable list of unmatched functions for one side."""

        def __init__(self, rows: Sequence[UnmatchedRow], side: str,
                     on_jump: Optional[Callable[[int], None]] = None) -> None:
            super().__init__()
            self._all_rows = list(rows)
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
            self._search.textChanged.connect(lambda _t: self._apply())

            self._table = UnmatchedTable()
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
            if self._table is not None:
                self._apply()

        def _apply(self) -> None:
            if self._table is None:
                return
            visible = filter_unmatched(self._all_rows, self._search.text())
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

            self._manual_only = QtWidgets.QCheckBox("Manual only")
            self._changed_only = QtWidgets.QCheckBox("Changed only")

            layout = QtWidgets.QHBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self._text, 1)
            layout.addWidget(QtWidgets.QLabel("Min similarity"))
            layout.addWidget(self._min_similarity)
            layout.addWidget(QtWidgets.QLabel("Min confidence"))
            layout.addWidget(self._min_confidence)
            layout.addWidget(self._manual_only)
            layout.addWidget(self._changed_only)

            self._text.textChanged.connect(self._emit)
            self._min_similarity.valueChanged.connect(self._emit)
            self._min_confidence.valueChanged.connect(self._emit)
            self._manual_only.toggled.connect(self._emit)
            self._changed_only.toggled.connect(self._emit)

        def current_filter(self) -> MatchFilter:
            return MatchFilter(
                text=self._text.text(),
                min_similarity=self._min_similarity.value(),
                min_confidence=self._min_confidence.value(),
                manual_only=self._manual_only.isChecked(),
                changed_only=self._changed_only.isChecked(),
            )

        def _emit(self, *_args) -> None:
            self._on_changed(self.current_filter())

    class MatchedFunctionsForm(ida_kernwin.PluginForm):
        """Dockable panel listing matched functions."""

        def __init__(self, rows: Sequence[MatchRow],
                     on_jump: Optional[Callable[[int], None]] = None,
                     context_actions: Sequence = ()) -> None:
            super().__init__()
            self._all_rows = list(rows)
            self._on_jump = on_jump
            self._context_actions = tuple(context_actions)
            self._table: Optional[MatchTable] = None
            self._status: Optional[QtWidgets.QLabel] = None
            self.parent = None

        def OnCreate(self, form) -> None:
            # PluginForm is not a QObject and the widget IDA returns cannot be
            # subclassed, so the panel owns its children rather than deriving.
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)

            self._filter_bar = FilterBar(self._apply_filter)
            self._table = MatchTable()
            self._table.on_activated = self._activate
            self._table.context_actions = self._context_actions
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
            if self._table is not None:
                self._apply_filter(self._filter_bar.current_filter())

        def _apply_filter(self, match_filter: MatchFilter) -> None:
            if self._table is None:
                return
            visible = filter_rows(self._all_rows, match_filter)
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

    class StatisticsDialog(QtWidgets.QDialog):
        """Read-only summary of the two inputs."""

        def __init__(self, rows: Sequence[StatisticRow], parent=None) -> None:
            super().__init__(parent)
            self.setWindowTitle("BinDiff - Statistics")
            self.resize(720, 420)

            table = QtWidgets.QTableWidget(len(rows), 3, self)
            table.setHorizontalHeaderLabels(["", "Primary", "Secondary"])
            table.setEditTriggers(_no_edit_triggers())
            table.verticalHeader().setVisible(False)
            for index, row in enumerate(rows):
                for column, value in enumerate((row.label, row.primary,
                                                row.secondary)):
                    table.setItem(index, column,
                                  QtWidgets.QTableWidgetItem(value))
            try:
                table.horizontalHeader().setSectionResizeMode(
                    QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
            except AttributeError:
                table.horizontalHeader().setSectionResizeMode(
                    QtWidgets.QHeaderView.ResizeToContents)

            buttons = QtWidgets.QDialogButtonBox()
            try:
                buttons.setStandardButtons(
                    QtWidgets.QDialogButtonBox.StandardButton.Close)
            except AttributeError:
                buttons.setStandardButtons(QtWidgets.QDialogButtonBox.Close)
            buttons.rejected.connect(self.reject)

            layout = QtWidgets.QVBoxLayout(self)
            layout.addWidget(table)
            layout.addWidget(buttons)

    class AlgorithmConfigDialog(QtWidgets.QDialog):
        """Enable, disable and reorder the matching algorithms.

        Writes straight through to the engine config, so a change here takes
        effect on the next diff. Confidence values are shown but not editable:
        the engine reads those when it constructs its algorithm objects, which
        happens once per process, so editing them here would appear to work and
        then not.
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
                "drag to reorder. Confidence values are fixed for the lifetime "
                "of the process.")
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

        def _build_list(self, key: str) -> QtWidgets.QListWidget:
            widget = QtWidgets.QListWidget()
            try:
                widget.setDragDropMode(
                    QtWidgets.QAbstractItemView.DragDropMode.InternalMove)
            except AttributeError:
                widget.setDragDropMode(QtWidgets.QAbstractItemView.InternalMove)
            for step in self._config.get(key, []):
                item = QtWidgets.QListWidgetItem(
                    f"{step['name']}  (confidence {step.get('confidence', 0)})")
                item.setData(Qt.UserRole, step)
                try:
                    item.setCheckState(Qt.CheckState.Checked)
                except AttributeError:
                    item.setCheckState(Qt.Checked)
                widget.addItem(item)
            return widget

        @staticmethod
        def _selected_steps(widget: QtWidgets.QListWidget) -> List[dict]:
            steps = []
            for index in range(widget.count()):
                item = widget.item(index)
                try:
                    checked = item.checkState() == Qt.CheckState.Checked
                except AttributeError:
                    checked = item.checkState() == Qt.Checked
                if checked:
                    steps.append(item.data(Qt.UserRole))
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
