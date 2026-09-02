"""The match inspector: everything true of exactly one pair.

Tier 2 of the vocabulary rule lives here -- every engine token is drawn
beside its expansion and its value, all three together, so the table can
stay at seven plain-English columns and still leave nothing unsayable.

The content is `inspection.build_inspection`; this module only renders it.
Nothing is computed here that a headless test could not have checked.

Widgets exist only when IDA does; the module imports headless.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from bindiff.ida_env import ida_kernwin_if_loaded, qt_widgets_usable
from ida_plugin import session as actions
from ida_plugin.inspection import build_inspection
from ida_plugin.porting import DEFAULT_PORT_MIN_SIMILARITY
from ida_plugin.session import DiffSession

IDA_AVAILABLE = qt_widgets_usable()
ida_kernwin = ida_kernwin_if_loaded()

# The empty state. A sentence rather than a blank pane: an inspector with
# nothing in it otherwise reads as a match with nothing to say about it.
NOTHING_SELECTED = "Select a match to inspect it."

if IDA_AVAILABLE:
    from bindiff.qt_shim import QtGui, QtWidgets
    from ida_plugin.panels import _fixed_font_family, tints_for

    # -- enum spellings ---------------------------------------------------
    #
    # Qt6 scopes its enums and Qt5 does not, so each of these is asked for
    # twice. Functions rather than module constants, because the module is
    # imported before a binding is chosen in some processes.

    def _window_text_role():
        try:
            return QtGui.QPalette.ColorRole.WindowText
        except AttributeError:
            return QtGui.QPalette.WindowText

    def _changed_letters(changed) -> str:
        letters = "".join(letter for letter, _name, differs in changed
                          if differs)
        return letters if letters else "nothing"

    class InspectorForm(ida_kernwin.PluginForm):
        """Everything true of exactly one pair, engine vocabulary included.

        A second dock tab, closable and forgettable, re-openable from the
        table's own context menu. It is what lets the table drop to seven
        columns: detail has somewhere to live.
        """

        def __init__(self, session: DiffSession,
                     handlers: Dict[str, Callable]) -> None:
            super().__init__()
            self._session = session
            self._handlers = handlers
            self._threshold = DEFAULT_PORT_MIN_SIMILARITY
            self._current: Optional[int] = None
            # A widget, so it exists only between OnCreate and OnClose;
            # every entry point checks it rather than assuming a live form.
            self.parent = None
            self._subscriptions: List[tuple] = []

        # -- lifecycle -------------------------------------------------------

        def OnCreate(self, form) -> None:
            self.parent = self.FormToPyQtWidget(form)
            outer = QtWidgets.QVBoxLayout(self.parent)
            outer.setContentsMargins(0, 0, 0, 0)
            scroll = QtWidgets.QScrollArea()
            scroll.setWidgetResizable(True)
            self._body = QtWidgets.QWidget()
            self._layout = QtWidgets.QVBoxLayout(self._body)
            scroll.setWidget(self._body)
            outer.addWidget(scroll)
            self._subscribe()
            one = self._session.selected_ids
            self._render(one[0] if len(one) == 1 else None)

        def _subscribe(self) -> None:
            pairs = (
                (self._session.selection_changed, self._render),
                # An edit or a port does not change which match is shown, it
                # changes what is true of it -- the state, the name that
                # would be written, whether there is anything left to port.
                (self._session.matches_changed,
                 lambda _ids: self._render(self._current)),
                (self._session.ported, lambda _l: self._render(self._current)),
                (self._session.result_closed, lambda: self._render(None)),
            )
            for signal, handler in pairs:
                signal.connect(handler)
                self._subscriptions.append((signal, handler))

        def OnClose(self, form) -> None:
            # Disconnected, not left connected and guarded: a session that
            # outlives the tab would otherwise keep calling into widgets Qt
            # has already deleted, and hold this form alive for the session.
            for signal, handler in self._subscriptions:
                signal.disconnect(handler)
            self._subscriptions.clear()
            self.parent = None

        def Show(self):
            return ida_kernwin.PluginForm.Show(
                self, "Match inspector",
                options=(ida_kernwin.PluginForm.WOPN_PERSIST
                         | ida_kernwin.PluginForm.WCLS_SAVE
                         | ida_kernwin.PluginForm.WOPN_RESTORE
                         | ida_kernwin.PluginForm.WOPN_TAB),
            )

        # -- entry points ----------------------------------------------------

        def set_threshold(self, threshold: float) -> None:
            """The workbench's floor, so the "below the threshold" line here
            says the same number the footer does."""
            self._threshold = threshold
            self._render(self._current)

        # -- rendering -------------------------------------------------------

        @staticmethod
        def _tint(label, colour) -> None:
            """One label's text colour, through the palette.

            Not a stylesheet: a stylesheet colour is fixed at the moment it
            is written and survives a theme change, so the one thing it is
            used for here -- saying how much to trust a match -- would go
            unreadable the first time IDA switches to dark.
            """
            palette = label.palette()
            palette.setColor(_window_text_role(), colour)
            label.setPalette(palette)

        def _clear(self) -> None:
            while self._layout.count():
                item = self._layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

        def _heading(self, text: str, colour=None):
            label = QtWidgets.QLabel(text)
            font = label.font()
            font.setBold(True)
            label.setFont(font)
            if colour is not None:
                self._tint(label, colour)
            return label

        def _token(self, text: str, colour=None):
            """The engine's own word for a value, beside the value.

            Monospace because it is a literal -- what the config file, the
            SQLite column and the log all call this thing -- and dim because
            it is the second reading, not the first.
            """
            label = QtWidgets.QLabel(text)
            font = label.font()
            family = _fixed_font_family()
            if family:
                font.setFamily(family)
            font.setPointSizeF(max(font.pointSizeF() - 1.0, 1.0))
            label.setFont(font)
            if colour is not None:
                self._tint(label, colour)
            return label

        def _render(self, match_id) -> None:
            # Called from four signals and from set_threshold, any of which
            # can arrive while the tab is closed.
            if self.parent is None:
                return
            self._current = match_id
            self._clear()
            row = self._session.row(match_id) if match_id is not None else None
            if row is None:
                # Also the path for an id the session no longer knows: an
                # unmatched pair is gone from rows() while the selection is
                # still remembered.
                self._layout.addWidget(QtWidgets.QLabel(NOTHING_SELECTED))
                self._layout.addStretch(1)
                return
            view = build_inspection(row, self._session.meta,
                                    threshold=self._threshold)
            tints = tints_for(self.parent)

            title = QtWidgets.QLabel(view.title)
            font = title.font()
            font.setBold(True)
            font.setPointSizeF(font.pointSizeF() * 1.3)
            title.setFont(font)
            title.setWordWrap(True)
            self._layout.addWidget(title)
            self._layout.addWidget(QtWidgets.QLabel(view.subtitle))

            self._layout.addWidget(self._buttons(view, match_id))
            # An unknown verdict is a reason to look, not a reason to trust:
            # tints_for has no entry for it, so it reads as "check".
            tint = tints.get(view.trust, tints["check"])
            self._layout.addWidget(
                self._heading(f"Trust · {view.trust}", tint))
            explanation = QtWidgets.QLabel(view.trust_explanation)
            explanation.setWordWrap(True)
            self._layout.addWidget(explanation)

            self._layout.addWidget(self._measures(view, tints))
            caveat = QtWidgets.QLabel(view.coverage_caveat)
            caveat.setWordWrap(True)
            self._layout.addWidget(caveat)

            self._layout.addWidget(
                self._heading(f"Changed · {_changed_letters(view.changed)}"))
            self._layout.addWidget(self._changed(view, tints))

            self._layout.addWidget(self._heading("Would port"))
            for line in view.would_port:
                label = QtWidgets.QLabel(line)
                label.setWordWrap(True)
                self._layout.addWidget(label)

            self._layout.addWidget(
                self._token(f"Engine: {view.engine_algorithm}", tints["dim"]))
            self._layout.addStretch(1)

        def _buttons(self, view, match_id):
            """The four things there are to do to one pair.

            Port is the only one that writes, and it writes with both floors
            off on purpose: a row somebody opened and read is the judgement
            the floors stand in for, so applying them again here would refuse
            exactly the match the reader just decided about. Said with a
            keyword rather than by passing a threshold the handler has to
            read intent into -- the footer's slider reaches 0.00 too, and
            there it means the threshold and nothing else.
            """
            box = QtWidgets.QWidget()
            row = QtWidgets.QHBoxLayout(box)
            row.setContentsMargins(0, 0, 0, 0)

            port = QtWidgets.QPushButton(view.port_label)
            port.setEnabled(view.port_label != "Nothing to port"
                            and self._session.can(actions.PORT))
            port.setToolTip("Writes this pair, whatever the threshold says.")
            port.clicked.connect(
                lambda _c=False: self._handlers["port"](0.0, [match_id],
                                                        ignore_floors=True))
            row.addWidget(port)

            for label, action, key in (
                    ("Verify", actions.VERIFY, "verify"),
                    ("Unmatch", actions.UNMATCH, "unmatch"),
                    ("Graphs", actions.GRAPHS, "graphs")):
                button = QtWidgets.QPushButton(label)
                button.setEnabled(self._session.can(action))
                button.clicked.connect(
                    lambda _c=False, name=key: self._handlers[name]())
                row.addWidget(button)
            row.addStretch(1)
            return box

        def _measures(self, view, tints):
            """Label, value and engine token, in that order, for every
            number the result carries about this pair."""
            box = QtWidgets.QWidget()
            form = QtWidgets.QFormLayout(box)
            form.setContentsMargins(0, 0, 0, 0)
            for measure in view.measures:
                field = QtWidgets.QWidget()
                line = QtWidgets.QHBoxLayout(field)
                line.setContentsMargins(0, 0, 0, 0)
                line.addWidget(QtWidgets.QLabel(measure.value))
                line.addWidget(self._token(measure.token, tints["dim"]))
                line.addStretch(1)
                form.addRow(QtWidgets.QLabel(measure.label), field)
            return box

        def _changed(self, view, tints):
            """Every change letter, set or not.

            The unset ones are drawn dim rather than left out: the letters
            are a fixed alphabet, and a reader who cannot see the ones that
            did not fire has no way to tell an unchanged pair from a letter
            this build does not know about.
            """
            box = QtWidgets.QWidget()
            grid = QtWidgets.QGridLayout(box)
            grid.setContentsMargins(0, 0, 0, 0)
            for index, (letter, name, differs) in enumerate(view.changed):
                value = QtWidgets.QLabel("differs" if differs else "unchanged")
                token = self._token(letter, None if differs else tints["dim"])
                expansion = QtWidgets.QLabel(name)
                if not differs:
                    self._tint(expansion, tints["dim"])
                    self._tint(value, tints["dim"])
                grid.addWidget(token, index, 0)
                grid.addWidget(expansion, index, 1)
                grid.addWidget(value, index, 2)
            grid.setColumnStretch(2, 1)
            return box
