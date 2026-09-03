"""The workbench: one dock tab that is the whole plugin.

Six surfaces collapse into this one: the run strip owns the next and current
comparison, the scope tabs own which reading of the result the table shows,
the table is the judgement surface, the footer is the port confirmation, and
the status bar states the one preference that matters. Every fact drawn here
is read from the DiffSession; nothing is inferred locally and nothing is
asked of IDA that the session can answer.

Widgets exist only when IDA does; the module imports headless.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from bindiff.ida_env import ida_kernwin_if_loaded, qt_widgets_usable
from ida_plugin import session as actions
from ida_plugin.diff_runner import reject_reason
from ida_plugin.lenses import (LENSES, READY_TO_PORT, apply_lens, lens_by_key,
                               lens_counts)
from ida_plugin.porting import (DEFAULT_PORT_MIN_CONFIDENCE,
                                DEFAULT_PORT_MIN_SIMILARITY,
                                preview_symbol_ports)
from ida_plugin.filters import RuleSet
from ida_plugin.query import Query, parse_query
from ida_plugin.session import DiffSession, State
from ida_plugin.ui_logic import (DiffProgress, IncrementalFilter,
                                 filter_unmatched, format_elapsed,
                                 text_query_narrows)

IDA_AVAILABLE = qt_widgets_usable()
ida_kernwin = ida_kernwin_if_loaded()

# How often auto-save writes, when it is on. One number rather than a spinner:
# the old panel spent a row of screen on a value nobody changed, and the
# question the user actually has is "is it on".
AUTOSAVE_SECONDS = 60

if IDA_AVAILABLE:
    from bindiff.qt_shim import (Qt, QtCore, QtGui, QtWidgets,
                                 exec_widget)
    from ida_plugin.panels import (MatchTable, UnmatchedTable,
                                   _no_edit_triggers, _set_interactive,
                                   debounced)

    # -- enum spellings ---------------------------------------------------
    #
    # Qt6 scopes its enums and Qt5 does not, so every one of these is asked
    # for twice. Written as functions rather than module constants because
    # the module is imported before a binding is chosen in some processes.

    def _custom_context_menu():
        try:
            return Qt.ContextMenuPolicy.CustomContextMenu
        except AttributeError:
            return Qt.CustomContextMenu

    def _horizontal():
        try:
            return Qt.Orientation.Horizontal
        except AttributeError:
            return Qt.Horizontal

    def _instant_popup():
        button = QtWidgets.QToolButton
        try:
            return button.ToolButtonPopupMode.InstantPopup
        except AttributeError:
            return button.InstantPopup

    def _plural(count: int, word: str) -> str:
        return f"{count:,} {word}" + ("" if count == 1 else "s")

    class FilterDialog(QtWidgets.QDialog):
        """"Modify filters...", rebuilt over our own table.

        Laid out as IDA's is, because the point is that it is already
        familiar: the editor row reads as a sentence, Add appends to a list,
        and the list shows what is in force with a checkbox to suspend a rule
        without losing it.
        """

        def __init__(self, rules, parent=None) -> None:
            super().__init__(parent)
            from ida_plugin.filters import (ACTIONS, ANY_COLUMN, CONDITIONS,
                                            Rule, RuleSet, Unusable)
            from ida_plugin.ui_logic import COLUMNS

            self._Rule, self._RuleSet, self._Unusable = Rule, RuleSet, Unusable
            self.rules = rules
            self.setWindowTitle("Modify filters")

            self._column = QtWidgets.QComboBox()
            self._column.addItem("(any)", ANY_COLUMN)
            for key, label in COLUMNS:
                self._column.addItem(label, key)
            self._condition = QtWidgets.QComboBox()
            self._condition.addItems(CONDITIONS)
            self._value = QtWidgets.QLineEdit()
            self._action = QtWidgets.QComboBox()
            self._action.addItems(ACTIONS)

            row = QtWidgets.QHBoxLayout()
            for widget in (QtWidgets.QLabel("If column"), self._column,
                           self._condition, self._value,
                           QtWidgets.QLabel("then"), self._action):
                row.addWidget(widget, 1 if widget is self._value else 0)

            self._match_case = QtWidgets.QCheckBox("Match case")
            self._whole_words = QtWidgets.QCheckBox("Whole words")
            self._regex = QtWidgets.QCheckBox("Regular expression")
            # Regex replaces the condition rather than refining it, which is
            # how the dialog behaves and why the dropdown goes grey.
            self._regex.toggled.connect(
                lambda on: self._condition.setEnabled(not on))

            flags = QtWidgets.QHBoxLayout()
            for box in (self._match_case, self._whole_words, self._regex):
                flags.addWidget(box)
            flags.addStretch(1)
            add = QtWidgets.QPushButton("Add")
            add.setDefault(True)
            add.clicked.connect(self._add)
            reset = QtWidgets.QPushButton("Reset")
            reset.clicked.connect(self._reset)
            close = QtWidgets.QPushButton("Close")
            close.clicked.connect(self.accept)
            for button in (add, reset, close):
                flags.addWidget(button)

            self._error = QtWidgets.QLabel()
            self._error.setWordWrap(True)
            self._error.setVisible(False)

            self._list = QtWidgets.QTableWidget(0, 5)
            self._list.setHorizontalHeaderLabels(
                ["", "Column", "Condition", "Value", "Action"])
            self._list.horizontalHeader().setStretchLastSection(True)
            self._list.verticalHeader().setVisible(False)
            self._list.itemChanged.connect(self._toggled)

            layout = QtWidgets.QVBoxLayout(self)
            layout.addLayout(row)
            layout.addLayout(flags)
            layout.addWidget(self._error)
            layout.addWidget(QtWidgets.QLabel("Filter list"))
            layout.addWidget(self._list)
            self._repopulate()
            self._value.setFocus()

        def _add(self) -> None:
            text = self._value.text()
            if not text:
                return
            rule = self._Rule(
                value=text, column=self._column.currentData(),
                condition=self._condition.currentText(),
                action=self._action.currentText(),
                match_case=self._match_case.isChecked(),
                whole_words=self._whole_words.isChecked(),
                regex=self._regex.isChecked())
            try:
                candidate = self.rules.with_rule(rule)
            except self._Unusable as exc:
                # Said in the dialog, not in a modal box. A pattern that does
                # not parse must not be swallowed -- it would read as a filter
                # matching nothing -- but a modal here interrupts the editing
                # it is complaining about, and blocks anything driving the
                # dialog without a hand on the mouse.
                self._error.setText(str(exc))
                self._error.setVisible(True)
                return
            self._error.setVisible(False)
            self.rules = candidate
            self._value.clear()
            self._repopulate()

        def _reset(self) -> None:
            self.rules = self._RuleSet()
            self._repopulate()

        def _toggled(self, item) -> None:
            if item.column() != 0:
                return
            enabled = item.checkState() == Qt.CheckState.Checked
            index = item.row()
            if index < len(self.rules.rules) and \
                    self.rules.rules[index].enabled != enabled:
                self.rules = self.rules.toggled(index, enabled)

        def _repopulate(self) -> None:
            self._list.blockSignals(True)
            self._list.setRowCount(len(self.rules.rules))
            for index, rule in enumerate(self.rules.rules):
                check = QtWidgets.QTableWidgetItem()
                check.setFlags(Qt.ItemFlag.ItemIsUserCheckable
                               | Qt.ItemFlag.ItemIsEnabled)
                check.setCheckState(Qt.CheckState.Checked if rule.enabled
                                    else Qt.CheckState.Unchecked)
                self._list.setItem(index, 0, check)
                column = "*" if rule.column == "*" else rule.column
                for position, text in enumerate(
                        (column,
                         "matches" if rule.regex else rule.condition,
                         rule.value, rule.action), start=1):
                    cell = QtWidgets.QTableWidgetItem(text)
                    cell.setFlags(Qt.ItemFlag.ItemIsEnabled)
                    self._list.setItem(index, position, cell)
            self._list.resizeColumnsToContents()
            self._list.blockSignals(False)


    class RunStrip(QtWidgets.QWidget):
        """The next comparison and the current one, in two rows.

        It is also the panel protocol diff_runner.DiffRun expects: start,
        update_progress and finish. A diff started here therefore reports
        here, rather than opening a second window that has to be found and
        closed -- which is what the separate progress form was.

        Every one of those three is called from the UI thread, by the
        plugin's execute_sync post; nothing on this class touches a thread.
        """

        def __init__(self, session: DiffSession, handlers: Dict[str, Callable],
                     parent=None) -> None:
            super().__init__(parent)
            self._session = session
            self._handlers = handlers
            self._started = 0.0
            self._message = ""
            self._reported = False

            self._secondary = QtWidgets.QLineEdit()
            self._secondary.setPlaceholderText(
                "Binary, .i64 database or .BinExport — the other side; "
                "this database is always one side")
            self._secondary.setClearButtonEnabled(True)
            browse = QtWidgets.QPushButton("Browse…")
            browse.clicked.connect(self._browse)

            self._settings = QtWidgets.QToolButton()
            self._settings.setText("⚙")
            self._settings.setToolTip("Settings")
            menu = QtWidgets.QMenu(self._settings)
            configure = menu.addAction("Matching algorithms…")
            configure.triggered.connect(
                lambda *_: self._handlers["configure"]())
            self._autosave = menu.addAction(
                f"Auto-save every {AUTOSAVE_SECONDS} s")
            self._autosave.setCheckable(True)
            self._autosave.setChecked(True)
            self._autosave.triggered.connect(
                lambda checked=False: self._handlers["autosave"](
                    bool(checked), AUTOSAVE_SECONDS))
            self._settings.setMenu(menu)
            self._settings.setPopupMode(_instant_popup())

            self._stack = QtWidgets.QStackedWidget()
            self._compare = QtWidgets.QPushButton("Compare")
            self._compare.setToolTip(
                "Exports this database and compares it with the file above.\n"
                "A .BinExport is used as it is, so only this side is exported.")
            self._compare.clicked.connect(self._start)
            running = QtWidgets.QWidget()
            row = QtWidgets.QHBoxLayout(running)
            row.setContentsMargins(0, 0, 0, 0)
            self._bar = QtWidgets.QProgressBar()
            self._bar.setTextVisible(True)
            self._cancel = QtWidgets.QPushButton("Cancel")
            self._cancel.setToolTip(
                "Asks the worker to stop and keep what it has matched so far.")
            self._cancel.clicked.connect(lambda: self._handlers["cancel"]())
            row.addWidget(self._bar, 1)
            row.addWidget(self._cancel)
            self._stack.addWidget(self._compare)
            self._stack.addWidget(running)
            self._timer = QtCore.QTimer(self)
            self._timer.timeout.connect(self._tick)

            self._result_line = QtWidgets.QLabel("No result open")
            self._save = QtWidgets.QPushButton("Save")
            self._save.clicked.connect(lambda: self._handlers["save"]())
            self._close = QtWidgets.QPushButton("Close")
            self._close.clicked.connect(lambda: self._handlers["close"]())

            column = QtWidgets.QVBoxLayout(self)
            column.setContentsMargins(6, 6, 6, 4)
            column.setSpacing(4)
            top = QtWidgets.QHBoxLayout()
            top.addWidget(QtWidgets.QLabel("Compare with"))
            top.addWidget(self._secondary, 1)
            top.addWidget(browse)
            top.addWidget(self._settings)
            top.addWidget(self._stack)
            bottom = QtWidgets.QHBoxLayout()
            bottom.addWidget(self._result_line)
            bottom.addStretch(1)
            bottom.addWidget(self._save)
            bottom.addWidget(self._close)
            column.addLayout(top)
            column.addLayout(bottom)
            self.refresh_enabled()

        # -- the field ------------------------------------------------------

        def secondary_path(self) -> str:
            return self._secondary.text().strip()

        def suggest_secondary(self, path: Optional[str]) -> None:
            """Fills the field, but never over something already typed."""
            if path and not self.secondary_path():
                self._secondary.setText(str(path))

        def _browse(self) -> None:
            """Picks the other side.

            The plugin gets first refusal -- that is what the harness drives,
            and it is where a picker that knows about recent results would go
            -- and None means "nothing to offer, ask IDA".

            ask_file's second argument is IDA's default *filename*, not a
            filter list: a semicolon-separated set of masks is taken as one
            literal glob, matches nothing, and opens the dialog with every
            file greyed out. "*" rather than "*.*" because the other side may
            be a .BinExport, an .i64, an .idb, or a bare binary with no
            extension at all, and "*.*" is exactly the one that hides the last.
            """
            chosen = self._handlers["browse"]()
            if chosen is None and ida_kernwin is not None:
                current = self.secondary_path()
                chosen = ida_kernwin.ask_file(
                    False, current or "*",
                    "Select the other side: a binary, database or export")
            if chosen:
                self._secondary.setText(str(chosen))

        def _start(self) -> None:
            path = self.secondary_path()
            if not path:
                self._warn("Choose a file to compare with first.")
                return
            refused = reject_reason(path)
            if refused:
                self._warn(refused)
                return
            self._handlers["compare"](path)

        @staticmethod
        def _warn(message: str) -> None:
            if ida_kernwin is not None:
                ida_kernwin.warning(message)

        # -- what is open ----------------------------------------------------

        def set_result_line(self, text: str, tooltip: str = "") -> None:
            self._result_line.setText(text)
            self._result_line.setToolTip(tooltip)

        def refresh_enabled(self) -> None:
            can = self._session.can
            self._compare.setEnabled(can(actions.COMPARE))
            self._cancel.setEnabled(can(actions.CANCEL))
            self._save.setEnabled(can(actions.SAVE))
            self._close.setEnabled(can(actions.CLOSE))
            self._settings.setEnabled(can(actions.CONFIGURE))

        # -- the panel protocol DiffRun expects ------------------------------

        def start(self, title: str, started_at: Optional[float] = None) -> None:
            # `started_at` is for a strip that is picking up a comparison
            # already running -- the dock closed and was reopened. Without it
            # the clock would restart at zero and report a five-minute diff as
            # having just begun.
            self._started = time.monotonic() if started_at is None else started_at
            self._reported = False
            self._message = title
            self._bar.setRange(0, 0)
            self._bar.setFormat(title)
            self._stack.setCurrentIndex(1)
            self._timer.start(1000)
            self.refresh_enabled()

        def update_progress(self, progress: DiffProgress) -> None:
            percentage = progress.percentage
            if percentage is None:
                # An export cannot say how far along it is -- idalib's
                # auto-analysis does not call back -- so the bar says
                # "working" rather than inventing a fraction.
                self._bar.setRange(0, 0)
            else:
                self._bar.setRange(0, 100)
                self._bar.setValue(percentage)
            self._message = progress.describe()
            self._tick()

        def finish(self, message: str) -> None:
            self._timer.stop()
            self._reported = True
            self._stack.setCurrentIndex(0)
            self._result_line.setToolTip(
                f"{message} · took "
                f"{format_elapsed(time.monotonic() - self._started)}")
            self.refresh_enabled()

        def is_running(self) -> bool:
            return self._stack.currentIndex() == 1

        def has_reported(self) -> bool:
            """Whether this strip has already announced the end of a run.

            The session is still COMPARING while the result it produced is
            being opened -- finish_compare comes after open_result -- so
            "the session says a diff is running" is not on its own a reason
            to put the bar back on screen.
            """
            return self._reported

        def _tick(self) -> None:
            self._bar.setFormat(
                f"{self._message} · "
                f"{format_elapsed(time.monotonic() - self._started)}")

    class LensRow(QtWidgets.QWidget):
        """Which reading of the matches, and which subset of them.

        The three lenses are buttons rather than a dropdown because they are
        the three things this table is used for and one of them is always
        true; a dropdown would hide two thirds of that. The search field
        parses into chips, so a filter that is on can be seen and removed.
        """

        def __init__(self, on_lens: Callable[[str], None],
                     on_query: Callable[[], None],
                     on_remove_chip: Callable[[str], None],
                     on_columns: Callable[[], None], parent=None) -> None:
            super().__init__(parent)
            self._on_lens = on_lens
            self._on_remove_chip = on_remove_chip
            self._buttons: Dict[str, QtWidgets.QToolButton] = {}

            self._group = QtWidgets.QButtonGroup(self)
            self._group.setExclusive(True)
            for lens in LENSES:
                button = QtWidgets.QToolButton()
                button.setText(lens.label)
                button.setCheckable(True)
                button.setToolTip(lens.label)
                # clicked, not toggled: setChecked() emits toggled, so a
                # programmatic set_lens would call back into itself.
                button.clicked.connect(
                    lambda _checked=False, key=lens.key: self._on_lens(key))
                self._group.addButton(button)
                self._buttons[lens.key] = button
            self._buttons[LENSES[0].key].setChecked(True)

            self.search = QtWidgets.QLineEdit()
            self.search.setPlaceholderText(
                "name, address, or a filter like sim:<0.8")
            self.search.setClearButtonEnabled(True)
            self._debounce = debounced(self, on_query, 150)
            self.search.textChanged.connect(lambda _t: self._debounce.start())

            self._chips = QtWidgets.QWidget()
            self._chip_row = QtWidgets.QHBoxLayout(self._chips)
            self._chip_row.setContentsMargins(0, 0, 0, 0)
            self._chip_row.setSpacing(2)

            self.columns_button = QtWidgets.QToolButton()
            self.columns_button.setText("Columns ▾")
            self.columns_button.clicked.connect(lambda _c=False: on_columns())

            row = QtWidgets.QHBoxLayout(self)
            row.setContentsMargins(6, 2, 6, 2)
            row.setSpacing(6)
            for lens in LENSES:
                row.addWidget(self._buttons[lens.key])
            row.addWidget(self.search, 1)
            row.addWidget(self._chips)
            row.addWidget(self.columns_button)

        def set_lens(self, key: str) -> None:
            button = self._buttons.get(key)
            if button is not None:
                button.setChecked(True)

        def set_counts(self, counts: Dict[str, int]) -> None:
            for lens in LENSES:
                self._buttons[lens.key].setText(
                    f"{lens.label} {counts.get(lens.key, 0):,}")

        def set_chips(self, chips: Sequence[str]) -> None:
            """Rebuilds the chip strip.

            Rebuilt rather than diffed: there are never more than a handful,
            and a chip whose text no longer matches its term is the kind of
            wrong that reads as right.
            """
            while self._chip_row.count():
                item = self._chip_row.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
                    widget.deleteLater()
            for raw in chips:
                chip = QtWidgets.QToolButton()
                chip.setText(f"{raw} ✕")
                chip.setToolTip(f"Remove {raw}")
                chip.clicked.connect(
                    lambda _c=False, term=raw: self._on_remove_chip(term))
                self._chip_row.addWidget(chip)
            self._chips.setVisible(bool(chips))

    class PortFooter(QtWidgets.QWidget):
        """The confirmation, on screen before anything is written.

        A port writes into the primary database, where a wrong name is
        indistinguishable from analysis somebody did. So the threshold is the
        first control rather than an advanced setting, and the three outcomes
        a single count would hide are separated.
        """

        def __init__(self, on_threshold: Callable[[float], None],
                     on_review: Callable[[], None],
                     on_port: Callable[[], None], parent=None) -> None:
            super().__init__(parent)
            self._on_threshold = on_threshold

            self._slider = QtWidgets.QSlider(_horizontal())
            self._slider.setRange(0, 100)
            self._slider.setValue(round(DEFAULT_PORT_MIN_SIMILARITY * 100))
            self._slider.setMaximumWidth(160)
            self._value = QtWidgets.QLabel(f"{DEFAULT_PORT_MIN_SIMILARITY:.2f}")
            # The number tracks the handle immediately; only the work behind
            # it waits, because re-previewing per pixel of drag is a scan of
            # every shown row.
            self._slider.valueChanged.connect(self._show_value)
            self._debounce = debounced(self, self._emit_threshold, 150)
            self._slider.valueChanged.connect(lambda _v: self._debounce.start())

            self._summary = QtWidgets.QLabel("")
            self._review = QtWidgets.QPushButton("Review")
            self._review.setToolTip(
                "Select the matches whose name here would be replaced.")
            self._review.clicked.connect(lambda _c=False: on_review())
            self._port = QtWidgets.QPushButton("Port names + comments")
            self._port.clicked.connect(lambda _c=False: on_port())

            caption = QtWidgets.QLabel(
                f"Block coverage floor {DEFAULT_PORT_MIN_CONFIDENCE:.2f} · "
                "at 0.50 the measured precision was 93.8%")

            column = QtWidgets.QVBoxLayout(self)
            column.setContentsMargins(6, 2, 6, 4)
            column.setSpacing(2)
            row = QtWidgets.QHBoxLayout()
            row.addWidget(QtWidgets.QLabel("Write when similarity ≥"))
            row.addWidget(self._slider)
            row.addWidget(self._value)
            row.addWidget(self._summary, 1)
            row.addWidget(self._review)
            row.addWidget(self._port)
            column.addLayout(row)
            column.addWidget(caption)

        def threshold(self) -> float:
            return self._slider.value() / 100.0

        def _show_value(self, value: int) -> None:
            self._value.setText(f"{value / 100.0:.2f}")

        def _emit_threshold(self) -> None:
            self._on_threshold(self.threshold())

        def set_preview(self, preview, target_ids: Sequence[int]) -> None:
            """What a port of `target_ids` at this threshold would do."""
            self._summary.setText(preview.summary())
            replaces = len(preview.replaces_yours)
            self._review.setText(f"Review the {replaces:,}…")
            self._review.setEnabled(bool(replaces))
            self._review.setVisible(bool(replaces))
            wanted = set(target_ids)
            writes = sum(1 for port in preview.ports if port.match_id in wanted)
            self._port.setText(f"Port {_plural(writes, 'name')} + comments")
            self._port.setEnabled(bool(writes))

    class UnmatchedPage(QtWidgets.QWidget):
        """One side's unmatched functions, or why there are none to show.

        The empty state is not an empty table. A .BinDiff stores matches
        only, so without that side's .BinExport the unmatched list is not
        empty, it is unknown -- and a blank table is a claim that it is
        empty.
        """

        def __init__(self, session: DiffSession, handlers: Dict[str, Callable],
                     side: int, parent=None) -> None:
            super().__init__(parent)
            self._session = session
            self._handlers = handlers
            self._side = side
            self._rows: list = []
            self._filtered = IncrementalFilter(text_query_narrows,
                                               filter_unmatched)

            listing = QtWidgets.QWidget()
            column = QtWidgets.QVBoxLayout(listing)
            column.setContentsMargins(0, 0, 0, 0)
            self._search = QtWidgets.QLineEdit()
            self._search.setPlaceholderText("Filter by name or address…")
            self._search.setClearButtonEnabled(True)
            self._debounce = debounced(self, self._apply, 150)
            self._search.textChanged.connect(lambda _t: self._debounce.start())

            self._table = UnmatchedTable()
            self._table.setContextMenuPolicy(_custom_context_menu())
            self._table.customContextMenuRequested.connect(self._context_menu)
            self._table.selectionModel().selectionChanged.connect(
                lambda *_: self._on_selection())
            if side == 0:
                # Only this side is in the open database, so only this side
                # has somewhere to jump to.
                self._table.on_activated = (
                    lambda row: self._handlers["jump"](row.address))
            self._count = QtWidgets.QLabel("")
            column.addWidget(self._search)
            column.addWidget(self._table, 1)
            column.addWidget(self._count)

            missing = QtWidgets.QWidget()
            explain = QtWidgets.QVBoxLayout(missing)
            note = QtWidgets.QLabel(
                "The .BinExport for this side is not beside the result file. "
                "Unmatched functions live in the export.")
            note.setWordWrap(True)
            self._locate = QtWidgets.QPushButton("Locate…")
            self._locate.clicked.connect(
                lambda _c=False: self._handlers["locate_export"](self._side))
            explain.addStretch(1)
            explain.addWidget(note)
            explain.addWidget(self._locate)
            explain.addStretch(1)

            self._stack = QtWidgets.QStackedWidget()
            self._stack.addWidget(listing)
            self._stack.addWidget(missing)
            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self._stack)

        def refresh(self) -> None:
            # Nothing to point at an export for when no result is open.
            self._locate.setEnabled(self._session.can(actions.LOCATE_EXPORT))
            if self._session.meta is None or self._session.export_missing(
                    self._side):
                self._rows = []
                self._stack.setCurrentIndex(1)
                return
            try:
                self._rows = list(self._session.unmatched(self._side))
            except FileNotFoundError:
                self._rows = []
                self._stack.setCurrentIndex(1)
                return
            self._stack.setCurrentIndex(0)
            # New data invalidates the base a narrowing would have built on.
            self._filtered.invalidate()
            self._apply()

        def _apply(self) -> None:
            visible = self._filtered(self._rows, self._search.text())
            self._table.set_rows(visible)
            self._count.setText(
                f"{len(visible):,} of {len(self._rows):,} unmatched; "
                "library code hidden")

        def _on_selection(self) -> None:
            rows = self._table.selected_rows()
            self._session.choose_unmatched(
                self._side, rows[0].address if len(rows) == 1 else None)

        def _context_menu(self, position) -> None:
            rows = self._table.selected_rows()
            menu = QtWidgets.QMenu(self._table)
            pair = menu.addAction(
                "Pair with the chosen function on the other side")
            pair.setEnabled(self._session.can(actions.PAIR))
            pair.triggered.connect(lambda *_: self._handlers["pair"]())
            copy = menu.addAction("Copy address")
            # Not session.can(COPY): that answers for the *match* selection,
            # so it would grey this entry out over a row that is selected
            # right here. What this needs is a row under the cursor.
            copy.setEnabled(bool(rows))
            copy.triggered.connect(
                lambda *_: self._handlers[
                    "copy_here" if self._side == 0 else "copy_there"]())
            exec_widget(menu, self._table.viewport().mapToGlobal(position))

    class StatusBar(QtWidgets.QWidget):
        """How much is on screen, how much is picked, and the one preference.

        Following the selection is off by default: a view that jumps while
        someone is arrowing down a list takes the database out from under
        them, and it is the one behaviour that has to be asked for.
        """

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self._counts = QtWidgets.QLabel("")
            self._selected = QtWidgets.QLabel("")
            self._follow = QtWidgets.QToolButton()
            self._follow.setText("Follow selection in IDA View-A")
            self._follow.setCheckable(True)
            self._follow.setChecked(False)

            row = QtWidgets.QHBoxLayout(self)
            row.setContentsMargins(6, 2, 6, 2)
            row.setSpacing(6)
            row.addWidget(self._counts)
            row.addWidget(QtWidgets.QLabel("·"))
            row.addWidget(self._selected)
            row.addStretch(1)
            row.addWidget(self._follow)

        def follow(self) -> bool:
            return self._follow.isChecked()

        def set_counts(self, shown: int, total: int, selected: int) -> None:
            self._counts.setText(f"{shown:,} of {total:,} shown")
            self._selected.setText(f"{selected:,} selected")

    class Workbench(ida_kernwin.PluginForm):
        """One dock tab: the run strip, the scopes, the table, the footer.

        Six PluginForms became this. They each carried their own copy of what
        was open and each learned about a change separately, which is how
        three of them spent a session showing a result the fourth had closed.
        Here there is one subscription list and one refresh.
        """

        SCOPES = (("matches", "Matches"), ("only_here", "Only here"),
                  ("only_there", "Only there"), ("overview", "Overview"))

        def __init__(self, session: DiffSession,
                     handlers: Dict[str, Callable]) -> None:
            super().__init__()
            self._session = session
            self._handlers = handlers
            # Both are widgets, so both exist only between OnCreate and
            # OnClose. None rather than absent: the plugin hands run_strip to
            # DiffRun, and a missing attribute there is an AttributeError from
            # inside a worker callback, where nothing catches it.
            self.parent = None
            self.run_strip: Optional[RunStrip] = None
            self._lens = LENSES[0]
            self._query: Query = Query()
            self._rules = RuleSet()
            self._sort: Optional[Tuple[str, bool]] = None
            self._threshold = DEFAULT_PORT_MIN_SIMILARITY
            self._preview = None
            self._shown: list = []
            self._rows_source: Optional[list] = None
            self._subscriptions: List[tuple] = []
            self._filter = IncrementalFilter(self._narrows, self._select)

        # -- lifecycle -------------------------------------------------------

        def OnCreate(self, form) -> None:
            # PluginForm is not a QObject and the widget IDA hands back is,
            # so everything below hangs off `parent` rather than off self.
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            self.run_strip = RunStrip(self._session, self._handlers)

            self._tabs = QtWidgets.QTabBar()
            self._tabs.setExpanding(False)
            self._tabs.setDocumentMode(True)
            for _key, label in self.SCOPES:
                self._tabs.addTab(label)
            self._pages = QtWidgets.QStackedWidget()
            self._tabs.currentChanged.connect(self._on_scope_changed)

            self._pages.addWidget(self._matches_page())
            self._only_here = UnmatchedPage(self._session, self._handlers, 0)
            self._only_there = UnmatchedPage(self._session, self._handlers, 1)
            self._pages.addWidget(self._only_here)
            self._pages.addWidget(self._only_there)
            self._pages.addWidget(self._overview_page())

            self._status = StatusBar()

            layout.addWidget(self.run_strip)
            layout.addWidget(self._tabs)
            layout.addWidget(self._pages, 1)
            layout.addWidget(self._status)

            self._subscribe()
            self._rebuild()
            # The tints come from the palette, which is only right once the
            # widget is on screen and in IDA's theme.
            self._table.refresh_tints()

        def _matches_page(self):
            page = QtWidgets.QWidget()
            column = QtWidgets.QVBoxLayout(page)
            column.setContentsMargins(0, 0, 0, 0)
            column.setSpacing(0)

            self._lens_row = LensRow(self.set_lens, self._apply_search,
                                     self._remove_chip, self._show_columns)
            self._search = self._lens_row.search

            self._table = MatchTable()
            self._table.set_columns(self._lens.columns)
            self._table.on_activated = (
                lambda row: self._handlers["jump"](row.address_primary))
            # Not session.selection_changed: that fires for the *single*
            # match a detail view can show, so a reshuffle of a multi-row
            # selection never reaches it. The count in the status bar has to
            # follow every change, so it is refreshed from the table.
            self._table.on_selection_changed = self._on_table_selection
            self._table.on_sort_changed = self._on_sort_changed
            self._table.on_context_menu = self._show_context_menu

            self._footer = PortFooter(self._on_threshold, self._on_review,
                                      self._on_port)
            self._footer.setVisible(False)

            column.addWidget(self._lens_row)
            column.addWidget(self._table, 1)
            column.addWidget(self._footer)
            return page

        def _overview_page(self):
            self._overview = QtWidgets.QTableWidget(0, 3)
            self._overview.setEditTriggers(_no_edit_triggers())
            self._overview.verticalHeader().setVisible(False)
            self._overview.setAlternatingRowColors(True)
            self._overview.setWordWrap(False)
            metrics = self._overview.fontMetrics()
            self._overview.verticalHeader().setDefaultSectionSize(
                metrics.height() + 4)
            header = self._overview.horizontalHeader()
            _set_interactive(header)
            header.setStretchLastSection(True)
            return self._overview

        def OnClose(self, form) -> None:
            # Disconnected, not left connected and guarded: a session that
            # outlives the tab would otherwise keep calling into widgets Qt
            # has already deleted, and hold this form alive for the session.
            for signal, handler in self._subscriptions:
                signal.disconnect(handler)
            self._subscriptions.clear()
            self.parent = None
            self.run_strip = None

        def Show(self):
            return ida_kernwin.PluginForm.Show(
                self, "BinDiff",
                options=(ida_kernwin.PluginForm.WOPN_PERSIST
                         | ida_kernwin.PluginForm.WCLS_SAVE
                         | ida_kernwin.PluginForm.WOPN_RESTORE
                         | ida_kernwin.PluginForm.WOPN_TAB),
            )

        def _subscribe(self) -> None:
            pairs = (
                (self._session.state_changed, lambda _s: self._refresh_enabled()),
                (self._session.progress,
                 lambda p, _e: self.run_strip.update_progress(p)),
                (self._session.result_opened, lambda _m: self._rebuild()),
                (self._session.result_closed, self._rebuild),
                (self._session.matches_changed,
                 lambda _ids: self._on_matches_changed()),
                (self._session.dirty_changed,
                 lambda _d, _n: self._refresh_result_line()),
                (self._session.selection_changed, lambda _id: self._refresh_status()),
                (self._session.ported, lambda _l: self._refresh_rows()),
            )
            for signal, handler in pairs:
                signal.connect(handler)
                self._subscriptions.append((signal, handler))

        # -- entry points ----------------------------------------------------

        def show_scope(self, key: str) -> None:
            self.Show()
            if ida_kernwin is not None:
                widget = ida_kernwin.find_widget("BinDiff")
                if widget is not None:
                    ida_kernwin.activate_widget(widget, True)
            keys = [k for k, _ in self.SCOPES]
            if self.parent is not None and key in keys:
                self._tabs.setCurrentIndex(keys.index(key))

        def set_lens(self, key: str) -> None:
            self._lens = lens_by_key(key)
            if self.parent is None:
                return
            self._lens_row.set_lens(key)
            self._table.set_columns(self._lens.columns)
            # A different predicate is not a narrowing of the previous one.
            self._filter.invalidate()
            self._sort = None
            self._refresh_rows()

        def selected_ids(self) -> List[int]:
            return self._table.selected_ids() if self.parent is not None else []

        def chosen_unmatched(self, side: int) -> Optional[int]:
            return self._session.chosen_unmatched.get(side)

        # -- refreshing ------------------------------------------------------

        def _rebuild(self) -> None:
            if self.parent is None:
                return
            self._refresh_enabled()
            self._resume_progress()
            self._refresh_result_line()
            self._refresh_tabs()
            self._filter.invalidate()
            self._refresh_rows()
            self._refresh_unmatched()
            self._refresh_overview()

        def _resume_progress(self) -> None:
            """Puts the strip back on the running page for a diff already
            under way.

            The dock can be closed and reopened mid-comparison, and a fresh
            strip starts on the Compare button -- which reads as "nothing is
            happening" while a worker is running, and offers a second diff.
            The elapsed clock is taken from the session rather than from now,
            so reopening does not reset it.
            """
            session = self._session
            if (session.state is not State.COMPARING
                    or self.run_strip.is_running()
                    or self.run_strip.has_reported()):
                return
            progress = session.last_progress
            self.run_strip.start(
                progress.describe() if progress else "comparing…",
                started_at=session.compare_started)
            if progress is not None:
                self.run_strip.update_progress(progress)

        def _on_matches_changed(self) -> None:
            """An edit moves the counts, the unmatched lists and the
            overview too.

            Separate from _refresh_rows because that also runs on every
            keystroke in the search field, and rebuilding an unmatched list
            walks every match on both sides -- per keystroke, on a result
            with thousands of them. The overview belongs here for the
            opposite reason: it is two small reads, and its matched and
            unmatched counts are derived from the live match count, so
            leaving it out of an edit is how Statistics came to disagree
            with the table it sits beside.
            """
            self._refresh_tabs()
            self._refresh_rows()
            self._refresh_unmatched()
            self._refresh_overview()

        def _refresh_enabled(self) -> None:
            if self.parent is None:
                return
            self.run_strip.refresh_enabled()

        def _refresh_result_line(self) -> None:
            if self.parent is None:
                return
            meta = self._session.meta
            self.run_strip.set_result_line(
                meta.describe(self._session.edits) if meta else "No result open",
                meta.path if meta else "")
            self.run_strip.refresh_enabled()

        def _refresh_tabs(self) -> None:
            """The tab labels carry the counts, so the scopes are readable
            without opening them. A side whose export is missing says so
            rather than showing a zero it cannot stand behind."""
            meta = self._session.meta
            for index, (key, label) in enumerate(self.SCOPES):
                if meta is None or key == "overview":
                    self._tabs.setTabText(index, label)
                    continue
                if key == "matches":
                    self._tabs.setTabText(index, f"{label} {meta.matched:,}")
                    continue
                side = 0 if key == "only_here" else 1
                count = meta.only_here if side == 0 else meta.only_there
                self._tabs.setTabText(
                    index, f"{label} {count:,}" if count is not None
                    else f"{label} · export not found")

        def _refresh_rows(self) -> None:
            if self.parent is None:
                return
            rows = self._session.rows()
            if rows is not self._rows_source:
                # The cache holds a result, and a stale one hides rows the
                # new data has. Identity is exact here: the session hands
                # back the same list until something changes it.
                self._filter.invalidate()
                self._rows_source = rows
            self._shown = self._filter(rows, self._key())
            self._table.set_rows(self._shown)
            self._lens_row.set_counts(lens_counts(rows, self._threshold))
            self._refresh_outcome()
            self._refresh_status()

        def _refresh_outcome(self) -> None:
            """The Outcome column and the footer, which are the same preview."""
            if self._lens is not READY_TO_PORT:
                self._preview = None
                self._footer.setVisible(False)
                return
            ids = [row.match_id for row in self._shown]
            self._preview = preview_symbol_ports(
                self._session.controller.matches_for(ids),
                min_similarity=self._threshold)
            self._table.set_annotations(
                "outcome", {i: self._preview.outcome(i) for i in ids})
            self._footer.set_preview(self._preview, self._port_targets())
            self._footer.setVisible(True)

        def _refresh_unmatched(self) -> None:
            self._only_here.refresh()
            self._only_there.refresh()

        def _refresh_overview(self) -> None:
            meta = self._session.meta
            rows = self._session.statistics() if meta is not None else []
            self._overview.setHorizontalHeaderLabels(
                ["", meta.this_name if meta else "This database",
                 meta.other_name if meta else "Other binary"])
            self._overview.setRowCount(len(rows))
            for index, row in enumerate(rows):
                for column, value in enumerate((row.label, row.primary,
                                                row.secondary)):
                    self._overview.setItem(
                        index, column, QtWidgets.QTableWidgetItem(str(value)))
            self._overview.resizeColumnsToContents()

        def _refresh_status(self) -> None:
            if self.parent is None:
                return
            self._status.set_counts(len(self._shown),
                                    len(self._session.rows()),
                                    len(self._table.selected_ids()))

        # -- the shown set ---------------------------------------------------

        def _key(self) -> tuple:
            return (self._lens.key, self._threshold, self._sort, self._query,
                    self._rules)

        @staticmethod
        def _narrows(previous: tuple, current: tuple) -> bool:
            """Whether the previous result is a superset of what `current`
            selects. The lens and the threshold decide membership, so both
            must be unchanged; the sort only decides order, and apply_lens
            re-sorts whatever it is given."""
            was_lens, was_threshold, _was_sort, was_query, was_rules = previous
            lens, threshold, _sort, query, rules = current
            return (lens == was_lens and threshold == was_threshold
                    and query.narrows(was_query) and rules.narrows(was_rules))

        @staticmethod
        def _select(rows: Sequence, key: tuple) -> list:
            lens, threshold, sort, query, rules = key
            column, descending = sort if sort else (None, None)
            return apply_lens(rows, lens_by_key(lens), query, threshold,
                              sort_column=column, sort_descending=descending,
                              rules=rules)

        # -- the search field ------------------------------------------------

        def _apply_search(self) -> None:
            self._query = parse_query(self._search.text())
            self._lens_row.set_chips(self._query.chips())
            self._refresh_rows()

        def _remove_chip(self, raw: str) -> None:
            self._search.setText(str(self._query.without(raw)))

        def _show_columns(self) -> None:
            """The column menu belongs to the header, so the position it is
            given is in the header's coordinates -- via global, so the menu
            still opens under the button that asked for it."""
            button = self._lens_row.columns_button
            header = self._table.horizontalHeader()
            below = button.mapToGlobal(button.rect().bottomLeft())
            self._table.show_column_menu(header.mapFromGlobal(below))

        # -- the table -------------------------------------------------------

        def _on_scope_changed(self, index: int) -> None:
            self._pages.setCurrentIndex(index)

        def _on_table_selection(self, ids: Sequence[int]) -> None:
            self._session.set_selection(ids)
            self._refresh_status()
            if self._footer.isVisible():
                self._footer.set_preview(self._preview, self._port_targets())
            if self._status.follow() and len(ids) == 1:
                row = self._session.row(ids[0])
                if row is not None:
                    self._handlers["jump"](row.address_primary)

        def _on_sort_changed(self, column: str, descending: bool) -> None:
            self._sort = (column, descending)
            self._refresh_rows()

        def _show_context_menu(self, position) -> None:
            """Built fresh on every right-click, so every entry's enablement
            is asked of the session at the moment it is shown. IDA's own
            action state is what greyed four views out for a whole session."""
            can = self._session.can
            menu = QtWidgets.QMenu(self._table)
            entries = (
                ("Inspect", actions.INSPECT, lambda: self._handlers["inspect"]()),
                ("Graphs", actions.GRAPHS, lambda: self._handlers["graphs"]()),
                None,
                (self._port_label(), actions.PORT,
                 lambda: self._handlers["port"](self._current_threshold(),
                                                self.selected_ids())),
                ("Restore previous name", actions.RESTORE_NAME,
                 lambda: self._handlers["restore_name"]()),
                None,
                ("Verify", actions.VERIFY, lambda: self._handlers["verify"]()),
                ("Unmatch", actions.UNMATCH, lambda: self._handlers["unmatch"]()),
                None,
                ("Copy address here", actions.COPY,
                 lambda: self._handlers["copy_here"]()),
                ("Copy address there", actions.COPY,
                 lambda: self._handlers["copy_there"]()),
            )
            filters = QtWidgets.QMenu("Filters", menu)
            for entry in entries:
                if entry is None:
                    menu.addSeparator()
                    continue
                label, action, callback = entry
                item = menu.addAction(label)
                item.setEnabled(can(action))
                item.triggered.connect(lambda _checked=False, fn=callback: fn())

            # Always available: filtering is about the list, not about what
            # is selected in it, so it is never greyed out.
            menu.addSeparator()
            quick = menu.addAction("Quick filter")
            quick.setShortcut(QtGui.QKeySequence.StandardKey.Find)
            quick.triggered.connect(lambda _checked=False: self._focus_search())
            modify = menu.addAction("Modify filters…")
            modify.triggered.connect(lambda _checked=False: self._edit_filters())
            reset = menu.addAction("Reset filters")
            reset.setEnabled(bool(self._rules))
            reset.triggered.connect(lambda _checked=False: self._reset_filters())
            exec_widget(menu, self._table.viewport().mapToGlobal(position))

        def _edit_filters(self) -> None:
            """IDA's "Modify filters..." over our own table.

            Deliberately the same shape as the chooser's: one row that reads
            "If column <c> <condition> <value> then <action>", an Add button,
            and a list of what is in force. The rules are ours -- a chooser
            would bring its own but cannot tint a cell, which is what the
            whole Trust column rests on.
            """
            dialog = FilterDialog(self._rules, self._table)
            if exec_widget(dialog) and dialog.rules != self._rules:
                self._rules = dialog.rules
                self._refresh_rows()

        def _reset_filters(self) -> None:
            if self._rules:
                self._rules = RuleSet()
                self._refresh_rows()

        def _focus_search(self) -> None:
            """Quick filter, where IDA puts it."""
            self._search.setFocus()
            self._search.selectAll()

        def _port_label(self) -> str:
            ids = self.selected_ids()
            wanted = set(ids)
            comments = sum(row.comments_available for row in self._session.rows()
                           if row.match_id in wanted)
            label = f"Port {_plural(len(ids), 'name')}"
            return label + (f" + {_plural(comments, 'comment')}"
                            if comments else "") + "…"

        # -- porting ---------------------------------------------------------

        def _current_threshold(self) -> float:
            return (self._footer.threshold() if self._footer.isVisible()
                    else DEFAULT_PORT_MIN_SIMILARITY)

        def _port_targets(self) -> List[int]:
            """The selection, or everything on screen when nothing is picked.

            Never everything in the result: what a port writes has to be
            what the reader was looking at when they asked for it.
            """
            ids = self._table.selected_ids()
            return ids if ids else [row.match_id for row in self._shown]

        def _on_threshold(self, threshold: float) -> None:
            self._threshold = threshold
            # The inspector says "below the threshold" about the same number,
            # so it hears about the slider too. Optional because the handler
            # dict is also written by the harness, which has no inspector.
            self._handlers.get("threshold", lambda _t: None)(threshold)
            self._refresh_rows()

        def _on_review(self) -> None:
            if self._preview is None:
                return
            ids = [port.match_id for port in self._preview.replaces_yours]
            self._table.select_ids(ids)
            wanted = set(ids)
            for position, row in enumerate(self._table.rows):
                if row.match_id in wanted:
                    self._table.scrollTo(self._table.model().index(position, 0))
                    break

        def _on_port(self) -> None:
            self._handlers["port"](self._current_threshold(),
                                   self._port_targets())
