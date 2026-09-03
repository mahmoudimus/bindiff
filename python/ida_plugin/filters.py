"""Per-column filter rules, the shape IDA's own list views use.

IDA's choosers carry this and there is no API to borrow it: the quick filter,
the "Modify filters..." dialog and the column picker belong to the chooser
widget, and a QTableView cannot be given them. An embedded chooser would
bring them along, but its per-row colour cannot express a per-cell Trust tint
and its columns are fixed at construction, which the lenses change. So the
rules are rebuilt here, over the values the table already renders.

A rule reads the way the dialog does:

    If column (any) contains "memcpy" then include

Rules match against `ui_logic.cell_values`, so what you filter on is what you
can see -- "Sim contains 0.9" works because the cell says "0.94", not because
anything knows it is a float. That is also why a hidden column still filters:
the value exists whether or not the column is shown.

Combination is the part worth stating plainly, because a list of rules can
mean several things. A row survives when it matches **at least one** enabled
include (or there are none) and **no** enabled exclude. Excludes therefore
always win, which is what makes "everything except the CRT" one rule rather
than a rewrite of the include list.

No Qt and no IDA.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

ANY_COLUMN = "*"

CONTAINS = "contains"
IS = "is"
STARTS_WITH = "starts with"
ENDS_WITH = "ends with"
CONDITIONS = (CONTAINS, IS, STARTS_WITH, ENDS_WITH)

INCLUDE = "include"
EXCLUDE = "exclude"
ACTIONS = (INCLUDE, EXCLUDE)


@dataclass(frozen=True)
class Rule:
    """One line of the filter list.

    `column` is a key from ui_logic.COLUMNS, or ANY_COLUMN for "(any)".
    `regex` makes `value` a pattern and ignores `condition`, which is how the
    dialog behaves: the checkbox replaces the dropdown rather than refining
    it.
    """

    value: str
    column: str = ANY_COLUMN
    condition: str = CONTAINS
    action: str = INCLUDE
    match_case: bool = False
    whole_words: bool = False
    regex: bool = False
    enabled: bool = True

    def describe(self) -> str:
        """The rule as the dialog reads it, for a tooltip or a log line."""
        column = "(any)" if self.column == ANY_COLUMN else self.column
        how = "matches" if self.regex else self.condition
        flags = [name for name, on in (("case", self.match_case),
                                       ("whole words", self.whole_words))
                 if on]
        suffix = f" [{', '.join(flags)}]" if flags else ""
        return f"If {column} {how} {self.value!r} then {self.action}{suffix}"


class Unusable(ValueError):
    """A rule that cannot be compiled -- a regex that does not parse."""


def _predicate(rule: Rule) -> Callable[[str], bool]:
    """One rule compiled to a test over a single cell.

    Compiled once per rule rather than per row: a regex recompiled 10,000
    times is the difference between a filter that keeps up with typing and
    one that does not, and re.compile's own cache is capped and shared with
    everything else in the process.
    """
    value = rule.value if rule.match_case else rule.value.lower()

    if rule.regex or rule.whole_words:
        pattern = rule.value if rule.regex else r"\b%s\b" % re.escape(rule.value)
        try:
            compiled = re.compile(pattern,
                                  0 if rule.match_case else re.IGNORECASE)
        except re.error as exc:
            raise Unusable(f"{rule.value!r} is not a valid pattern: {exc}")
        # search() rather than match(): the dialog's "contains" reading holds
        # for a pattern too, and an anchored pattern can still say so itself.
        return lambda cell: compiled.search(cell) is not None

    if rule.condition == IS:
        return lambda cell: cell == value
    if rule.condition == STARTS_WITH:
        return lambda cell: cell.startswith(value)
    if rule.condition == ENDS_WITH:
        return lambda cell: cell.endswith(value)
    return lambda cell: value in cell


@dataclass
class _Compiled:
    test: Callable[[str], bool]
    index: Optional[int]      # None for "(any)"
    match_case: bool
    # A plain case-insensitive "(any) contains" -- the rule almost everyone
    # writes -- needs no per-cell work at all. It is answered against one
    # lowered haystack per row instead of seven lower() calls and a generator.
    plain: Optional[str] = None


# Joined with a character no rendered cell can contain, so a substring can
# never match across a boundary and report a hit that is not on screen.
_JOIN = "\x00"


class RuleSet:
    """A filter list, compiled once and applied to many rows.

    Construction does the work that would otherwise repeat per row: patterns
    compiled, column names resolved to indices, and the case-sensitive and
    case-insensitive rules separated so a row is lowered at most once per
    pass rather than once per rule.
    """

    def __init__(self, rules: Sequence[Rule] = (),
                 columns: Optional[Sequence[str]] = None) -> None:
        from ida_plugin.ui_logic import COLUMNS

        keys = [key for key, _label in COLUMNS] if columns is None \
            else list(columns)
        self.rules: Tuple[Rule, ...] = tuple(rules)
        self._includes: List[_Compiled] = []
        self._excludes: List[_Compiled] = []
        self._needs_lowering = False
        self._needs_haystack = False

        for rule in self.rules:
            if not rule.enabled or not rule.value:
                continue
            index = None
            if rule.column != ANY_COLUMN:
                if rule.column not in keys:
                    # A rule naming a column that no longer exists is dropped
                    # rather than treated as "(any)": silently widening a
                    # filter shows rows the reader excluded on purpose.
                    continue
                index = keys.index(rule.column)
            plain = None
            if (index is None and not rule.match_case and not rule.regex
                    and not rule.whole_words and rule.condition == CONTAINS):
                plain = rule.value.lower()
            compiled = _Compiled(_predicate(rule), index, rule.match_case,
                                 plain)
            (self._includes if rule.action == INCLUDE
             else self._excludes).append(compiled)
            if plain is not None:
                self._needs_haystack = True
            elif not rule.match_case:
                self._needs_lowering = True

    def __bool__(self) -> bool:
        return bool(self._includes or self._excludes)

    def matches(self, cells: Sequence[str]) -> bool:
        """Whether a row's rendered cells survive the list."""
        if not self._includes and not self._excludes:
            return True
        # Both built at most once per row, and only when a rule needs them.
        haystack = _JOIN.join(cells).lower() if self._needs_haystack else None
        lowered = [cell.lower() for cell in cells] if self._needs_lowering \
            else None

        for compiled in self._excludes:
            if self._holds(compiled, cells, lowered, haystack):
                return False
        if not self._includes:
            return True
        for compiled in self._includes:
            if self._holds(compiled, cells, lowered, haystack):
                return True
        return False

    @staticmethod
    def _holds(compiled: _Compiled, cells, lowered, haystack) -> bool:
        if compiled.plain is not None:
            return compiled.plain in haystack
        source = cells if compiled.match_case or lowered is None else lowered
        if compiled.index is not None:
            return (compiled.index < len(source)
                    and compiled.test(source[compiled.index]))
        # "(any)" short-circuits on the first cell that answers, which is why
        # the leading columns are the ones people search.
        for cell in source:
            if compiled.test(cell):
                return True
        return False

    def narrows(self, previous: "RuleSet") -> bool:
        """Only when the lists are identical.

        Adding an *include* widens -- a second include admits rows the first
        refused -- so "more rules means fewer rows" is false in general, and
        a cache built on it hides rows with no way to tell. Editing the list
        is one deliberate act; re-filtering everything then costs a pass,
        which is cheap next to being wrong.
        """
        return self.rules == previous.rules

    def with_rule(self, rule: Rule) -> "RuleSet":
        return RuleSet(self.rules + (rule,))

    def without(self, index: int) -> "RuleSet":
        return RuleSet(self.rules[:index] + self.rules[index + 1:])

    def toggled(self, index: int, enabled: bool) -> "RuleSet":
        rules = list(self.rules)
        rules[index] = replace(rules[index], enabled=enabled)
        return RuleSet(rules)
