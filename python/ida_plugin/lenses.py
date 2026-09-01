"""Lenses: the three sessions the matched table is used for.

A lens is a saved filter, sort and column set -- not a mode. "Needs a look"
is the audit; "Ready to port" is carrying work forward; "All" is hunting one
function, where the search field does the work. Each is a predicate over a
MatchRow plus the columns that session reads.

No Qt and no IDA.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ida_plugin.query import Query
from ida_plugin.ui_logic import (DEFAULT_VISIBLE_COLUMNS, ChangeType,
                                 MatchRow, is_generated_name, sort_rows)


@dataclass(frozen=True)
class Lens:
    key: str
    label: str
    columns: Tuple[str, ...]
    predicate: Callable[[MatchRow, float], bool]
    sort_column: str = "similarity"
    sort_descending: bool = True

    def select(self, rows: Sequence[MatchRow], threshold: float) -> List[MatchRow]:
        return [row for row in rows if self.predicate(row, threshold)]


def _needs_a_look(row: MatchRow, _threshold: float) -> bool:
    return row.trust != "strong" or bool(row.change_flags & int(ChangeType.STRUCTURAL))


def _ready_to_port(row: MatchRow, _threshold: float) -> bool:
    # Membership is "the other side has a name worth having". Whether it
    # will be written at the current threshold is the Outcome column's job,
    # so a row just below the line stays visible with its reason.
    return not is_generated_name(row.name_secondary)


def _everything(_row: MatchRow, _threshold: float) -> bool:
    return True


NEEDS_A_LOOK = Lens("needs_a_look", "Needs a look",
                    tuple(DEFAULT_VISIBLE_COLUMNS), _needs_a_look)
READY_TO_PORT = Lens("ready_to_port", "Ready to port",
                     ("trust", "this_database", "other_binary",
                      "comments_available", "changed", "outcome"),
                     _ready_to_port)
ALL = Lens("all", "All", tuple(DEFAULT_VISIBLE_COLUMNS), _everything)

LENSES = (NEEDS_A_LOOK, READY_TO_PORT, ALL)


def lens_by_key(key: str) -> Lens:
    for lens in LENSES:
        if lens.key == key:
            return lens
    raise ValueError(f"unknown lens {key!r}")


def apply_lens(rows: Sequence[MatchRow], lens: Lens, query: Query,
               threshold: float, *, sort_column: Optional[str] = None,
               sort_descending: Optional[bool] = None) -> List[MatchRow]:
    selected = [row for row in lens.select(rows, threshold) if query.matches(row)]
    column = sort_column or lens.sort_column
    descending = lens.sort_descending if sort_descending is None else sort_descending
    return sort_rows(selected, column, descending)


def lens_counts(rows: Sequence[MatchRow], threshold: float) -> Dict[str, int]:
    """How many rows each lens would show with an empty search, for the
    lens buttons' badges."""
    return {lens.key: len(lens.select(rows, threshold)) for lens in LENSES}
