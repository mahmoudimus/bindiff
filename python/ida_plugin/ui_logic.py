"""Pure presentation logic for the BinDiff plugin.

No Qt and no IDA imports, deliberately: everything here can be exercised in the
headless test harness, which is where the interesting behaviour -- sorting,
filtering, formatting, the change-flag decoding -- actually lives. The Qt layer
in panels.py does nothing but render these view objects and forward user
actions back. Same split d810 uses (`*_logic.py` beside `*_panel.py`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from typing import Callable, Iterable, List, Optional, Sequence


class ChangeType(IntFlag):
    """What differs between the two sides of a match.

    These are BinDiff's own flags, from change_classifier.h. The single-letter
    codes are the ones the engine prints, in that order, and are what the UI
    shows in its "Change" column -- a dash for each aspect that did not change,
    e.g. "G-O----" for a structural and operand change.
    """

    NONE = 0
    STRUCTURAL = 1 << 0
    INSTRUCTIONS = 1 << 1
    OPERANDS = 1 << 2
    BRANCH_INVERSION = 1 << 3
    ENTRY_POINT = 1 << 4
    LOOPS = 1 << 5
    CALLS = 1 << 6


# Order matters: it is the order the engine prints them in.
_CHANGE_CODES: Sequence[tuple[ChangeType, str, str]] = (
    (ChangeType.STRUCTURAL, "G", "Graph"),
    (ChangeType.INSTRUCTIONS, "I", "Instructions"),
    (ChangeType.OPERANDS, "O", "Operands"),
    (ChangeType.BRANCH_INVERSION, "J", "Jumps"),
    (ChangeType.ENTRY_POINT, "E", "Entry point"),
    (ChangeType.LOOPS, "L", "Loops"),
    (ChangeType.CALLS, "C", "Calls"),
)


def format_change_flags(flags: int) -> str:
    """Renders change flags the way the engine does, e.g. "G-O----"."""
    return "".join(
        code if flags & int(bit) else "-" for bit, code, _ in _CHANGE_CODES
    )


def describe_change_flags(flags: int) -> List[str]:
    """Human-readable names of the aspects that changed, for a tooltip."""
    return [name for bit, _, name in _CHANGE_CODES if flags & int(bit)]


def format_address(address: int) -> str:
    return f"0x{address:08X}"


@dataclass(frozen=True)
class MatchRow:
    """One row of the matched-functions view."""

    match_id: int
    similarity: float
    confidence: float
    change_flags: int
    address_primary: int
    name_primary: str
    address_secondary: int
    name_secondary: str
    algorithm: str
    manual: bool
    comments_ported: bool
    basic_blocks: int
    edges: int
    instructions: int

    @property
    def change_text(self) -> str:
        return format_change_flags(self.change_flags)

    @property
    def identical(self) -> bool:
        """Similarity 1.0 with nothing flagged as changed."""
        return self.similarity >= 1.0 and self.change_flags == 0


COLUMNS: Sequence[tuple[str, str]] = (
    ("similarity", "Similarity"),
    ("confidence", "Confidence"),
    ("change", "Change"),
    ("address_primary", "EA Primary"),
    ("name_primary", "Name Primary"),
    ("address_secondary", "EA Secondary"),
    ("name_secondary", "Name Secondary"),
    ("algorithm", "Algorithm"),
)


def _sort_key(column: str) -> Callable[[MatchRow], object]:
    if column == "change":
        return lambda row: row.change_text
    if column == "algorithm":
        return lambda row: row.algorithm.lower()
    if column in ("name_primary", "name_secondary"):
        return lambda row: getattr(row, column).lower()
    return lambda row: getattr(row, column)


def sort_rows(rows: Iterable[MatchRow], column: str,
              descending: bool = False) -> List[MatchRow]:
    """Sorts by a column name from COLUMNS.

    Names sort case-insensitively; everything else sorts naturally. Raises on an
    unknown column rather than silently returning the input order.
    """
    known = {name for name, _ in COLUMNS}
    if column not in known:
        raise ValueError(f"unknown column {column!r}; expected one of {sorted(known)}")
    return sorted(rows, key=_sort_key(column), reverse=descending)


@dataclass(frozen=True)
class MatchFilter:
    """The filter the matched-functions view applies.

    Every field is optional; an unset field does not constrain. `text` matches
    either function name, case-insensitively, and also matches an address when
    it parses as one ("0x401000", "401000").
    """

    text: str = ""
    min_similarity: float = 0.0
    min_confidence: float = 0.0
    manual_only: bool = False
    changed_only: bool = False

    def _address_query(self) -> Optional[int]:
        query = self.text.strip()
        if not query:
            return None
        try:
            return int(query, 16 if not query.lower().startswith("0x") else 0)
        except ValueError:
            return None

    def matches(self, row: MatchRow) -> bool:
        if row.similarity < self.min_similarity:
            return False
        if row.confidence < self.min_confidence:
            return False
        if self.manual_only and not row.manual:
            return False
        if self.changed_only and row.change_flags == 0:
            return False
        if not self.text:
            return True

        needle = self.text.lower()
        if needle in row.name_primary.lower() or needle in row.name_secondary.lower():
            return True
        address = self._address_query()
        return address is not None and address in (
            row.address_primary, row.address_secondary)


def filter_rows(rows: Iterable[MatchRow],
                match_filter: MatchFilter) -> List[MatchRow]:
    return [row for row in rows if match_filter.matches(row)]


@dataclass(frozen=True)
class StatisticRow:
    label: str
    primary: str
    secondary: str


def build_statistics(files, num_matches: int,
                     similarity: Optional[float] = None,
                     confidence: Optional[float] = None) -> List[StatisticRow]:
    """Builds the statistics view from the two FileInfo rows.

    `files` is what BinDiffDatabase.files() returns: index 0 primary, 1
    secondary, with counts that already include library code.
    """
    if len(files) != 2:
        raise ValueError(f"expected two input files, got {len(files)}")
    primary, secondary = files

    rows = [
        StatisticRow("File", primary.filename, secondary.filename),
        StatisticRow("Hash", primary.hash, secondary.hash),
        StatisticRow("Functions", str(primary.functions), str(secondary.functions)),
        StatisticRow("Matched functions", str(num_matches), str(num_matches)),
        StatisticRow("Unmatched functions",
                     str(primary.functions - num_matches),
                     str(secondary.functions - num_matches)),
        StatisticRow("Basic blocks", str(primary.basic_blocks),
                     str(secondary.basic_blocks)),
        StatisticRow("Instructions", str(primary.instructions),
                     str(secondary.instructions)),
        StatisticRow("Edges", str(primary.edges), str(secondary.edges)),
        StatisticRow("Calls", str(primary.calls), str(secondary.calls)),
    ]
    if similarity is not None:
        rows.append(StatisticRow("Similarity", f"{similarity:.2%}", ""))
    if confidence is not None:
        rows.append(StatisticRow("Confidence", f"{confidence:.2%}", ""))
    return rows


def rows_from_database(database) -> List[MatchRow]:
    """Adapts BinDiffDatabase.matches() into view rows."""
    return [
        MatchRow(
            match_id=match.id,
            similarity=match.similarity,
            confidence=match.confidence,
            change_flags=match.flags,
            address_primary=match.address_primary,
            name_primary=match.name_primary,
            address_secondary=match.address_secondary,
            name_secondary=match.name_secondary,
            algorithm=match.algorithm,
            manual=match.manual,
            comments_ported=match.comments_ported,
            basic_blocks=match.basic_blocks,
            edges=match.edges,
            instructions=match.instructions,
        )
        for match in database.matches()
    ]


def similarity_color(similarity: float) -> tuple[int, int, int]:
    """Maps a similarity to the engine's ramp: red -> yellow -> green.

    bindiff.json ships a 256-entry ramp for this; the endpoints here are the
    ones it is generated from (Deep Orange 500 -> Google Yellow A700 -> Light
    Green A400), interpolated rather than table-driven so the UI does not have
    to carry the table.
    """
    similarity = max(0.0, min(1.0, similarity))
    low = (0xFF, 0x57, 0x22)
    mid = (0xFF, 0x9E, 0x00)
    high = (0x84, 0xFA, 0x02)

    if similarity < 0.5:
        start, end, t = low, mid, similarity / 0.5
    else:
        start, end, t = mid, high, (similarity - 0.5) / 0.5
    return tuple(  # type: ignore[return-value]
        round(start[i] + (end[i] - start[i]) * t) for i in range(3)
    )

@dataclass(frozen=True)
class UnmatchedRow:
    """One row of an unmatched-functions view."""

    address: int
    name: str
    is_library: bool
    has_real_name: bool

    @property
    def address_text(self) -> str:
        return format_address(self.address)


UNMATCHED_COLUMNS: Sequence[tuple[str, str]] = (
    ("address", "Address"),
    ("name", "Name"),
    ("kind", "Kind"),
)


def unmatched_functions(functions: Iterable, matched_addresses: Iterable[int],
                        *, include_library: bool = False) -> List[UnmatchedRow]:
    """Functions present in a binary that no match refers to.

    A .BinDiff stores matches only, so this needs the function list from that
    side's .BinExport -- see bindiff.binexport.read_functions. `functions` is
    what that returns.

    Library, imported and thunk code is excluded by default. It is usually the
    bulk of what goes unmatched and it is rarely what anyone is looking for;
    burying a handful of genuinely unmatched functions under a few thousand
    thunks makes the view useless.
    """
    matched = set(matched_addresses)
    rows = []
    for function in functions:
        if function.address in matched:
            continue
        if function.is_library and not include_library:
            continue
        rows.append(UnmatchedRow(address=function.address,
                                 name=function.best_name or "",
                                 is_library=function.is_library,
                                 has_real_name=function.has_real_name))
    return sorted(rows, key=lambda row: row.address)


def sort_unmatched(rows: Iterable[UnmatchedRow], column: str,
                   descending: bool = False) -> List[UnmatchedRow]:
    known = {name for name, _ in UNMATCHED_COLUMNS}
    if column not in known:
        raise ValueError(f"unknown column {column!r}; expected one of {sorted(known)}")
    if column == "name":
        key = lambda row: row.name.lower()  # noqa: E731
    elif column == "kind":
        key = lambda row: (row.is_library, not row.has_real_name)  # noqa: E731
    else:
        key = lambda row: row.address  # noqa: E731
    return sorted(rows, key=key, reverse=descending)


def filter_unmatched(rows: Iterable[UnmatchedRow], text: str) -> List[UnmatchedRow]:
    """Name or address substring match, same rules as the matched view."""
    needle = text.strip().lower()
    if not needle:
        return list(rows)

    address_query = None
    try:
        address_query = int(needle, 16 if not needle.startswith("0x") else 0)
    except ValueError:
        pass

    return [row for row in rows
            if needle in row.name.lower() or row.address == address_query]
