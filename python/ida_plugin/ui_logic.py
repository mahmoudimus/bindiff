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
    # Totals for each side. Zero when the .BinExport inputs were not available:
    # the result file records only how much of a pair was matched, never how
    # much there was to match.
    basic_blocks_primary: int = 0
    basic_blocks_secondary: int = 0
    instructions_primary: int = 0
    instructions_secondary: int = 0
    edges_primary: int = 0
    edges_secondary: int = 0

    @property
    def has_totals(self) -> bool:
        """Whether the per-side columns hold anything worth showing."""
        return any((self.basic_blocks_primary, self.basic_blocks_secondary,
                    self.instructions_primary, self.instructions_secondary,
                    self.edges_primary, self.edges_secondary))

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
    ("comments_ported", "Comments Ported"),
    ("basic_blocks", "Matched Basic Blocks"),
    ("basic_blocks_primary", "Basic Blocks Primary"),
    ("basic_blocks_secondary", "Basic Blocks Secondary"),
    ("instructions", "Matched Instructions"),
    ("instructions_primary", "Instructions Primary"),
    ("instructions_secondary", "Instructions Secondary"),
    ("edges", "Matched Edges"),
    ("edges_primary", "Edges Primary"),
    ("edges_secondary", "Edges Secondary"),
)


def _sort_key(column: str) -> Callable[[MatchRow], object]:
    if column == "comments_ported":
        return lambda row: row.comments_ported
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


def parse_address_query(text: str) -> Optional[int]:
    """The address a filter query names, or None when it names no address.

    "401000" and "0x401000" both parse; a name does not. Bare digits are read
    as hex because that is how addresses are written in a disassembler.
    """
    query = text.strip()
    if not query:
        return None
    try:
        return int(query, 16 if not query.lower().startswith("0x") else 0)
    except ValueError:
        return None


def text_query_narrows(previous: str, current: str) -> bool:
    """True when `current` can only match a subset of what `previous` matched.

    Shared by the matched and unmatched views because both have the same trap.
    A query matches names by substring, which narrows as it grows, but matches
    addresses *exactly*, which does not: a function at 0x401 is not matched by
    "40" and is matched by "401", so extending the query adds it. Whenever
    either query names an address this returns False and the caller filters
    everything again.
    """
    if not current.startswith(previous):
        return False
    return (parse_address_query(previous) is None
            and parse_address_query(current) is None)


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
        return parse_address_query(self.text)

    def narrows(self, previous: "MatchFilter") -> bool:
        """True when this filter can only accept a subset of `previous`.

        Lets the view re-filter the rows it already has rather than all of
        them. On a 5956-row diff, typing "acrt" is otherwise four passes over
        everything, one per keystroke.

        Every bound must be at least as strict and the text must extend the
        previous text -- and there is one exception that makes the whole idea
        unsound if it is missed. `text` matches names by substring but matches
        addresses *exactly*, and exact matching does not narrow: a row at
        0x401 does not match "40" and does match "401", so extending the query
        adds it. Whenever either text parses as an address this returns False
        and the caller filters from the top.
        """
        if self.min_similarity < previous.min_similarity:
            return False
        if self.min_confidence < previous.min_confidence:
            return False
        if previous.manual_only and not self.manual_only:
            return False
        if previous.changed_only and not self.changed_only:
            return False
        return text_query_narrows(previous.text, self.text)

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


def cell_values(row: MatchRow) -> tuple:
    """One row's cells, in COLUMNS order.

    Here rather than in the Qt table so the formatting is testable without a
    GUI, and so the model that renders it stays a thin adapter.
    """
    return (
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


def rows_from_database(database, primary_details=None,
                      secondary_details=None) -> List[MatchRow]:
    """Adapts BinDiffDatabase.matches() into view rows.

    `primary_details` and `secondary_details` are what
    bindiff.binexport.read_function_details returns for each side. They are
    optional: without them the per-side count columns read zero, which is
    honest -- those totals are not in the result file -- and every other column
    still works.
    """
    primary_details = primary_details or {}
    secondary_details = secondary_details or {}

    def totals(details, address):
        detail = details.get(address)
        if detail is None:
            return (0, 0, 0)
        return (detail.basic_blocks, detail.instructions, detail.edges)

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
            basic_blocks_primary=totals(primary_details,
                                        match.address_primary)[0],
            instructions_primary=totals(primary_details,
                                        match.address_primary)[1],
            edges_primary=totals(primary_details, match.address_primary)[2],
            basic_blocks_secondary=totals(secondary_details,
                                          match.address_secondary)[0],
            instructions_secondary=totals(secondary_details,
                                          match.address_secondary)[1],
            edges_secondary=totals(secondary_details,
                                   match.address_secondary)[2],
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
class DiffProgress:
    """One progress report from a running diff.

    Built from the record `bindiff.headless` puts on the worker's stdout. The
    weighting between stages is the worker's decision -- only it knows whether
    there are exports to do -- so `fraction` is taken as given.
    """

    stage: str = ""
    message: str = ""
    fraction: Optional[float] = None
    step_index: Optional[int] = None
    step_count: Optional[int] = None
    matches: Optional[int] = None

    @classmethod
    def from_record(cls, record: dict) -> "DiffProgress":
        return cls(stage=record.get("stage", ""),
                   message=record.get("message", ""),
                   fraction=record.get("fraction"),
                   step_index=record.get("step_index"),
                   step_count=record.get("step_count"),
                   matches=record.get("matches"))

    @property
    def percentage(self) -> Optional[int]:
        """0-100, or None when the stage cannot say how far along it is.

        An export has no honest answer: idalib's auto-analysis does not call
        back. A bar shown for it should be indeterminate rather than invented.
        """
        if self.fraction is None:
            return None
        return max(0, min(100, round(self.fraction * 100)))

    def describe(self) -> str:
        """One line for a status label."""
        parts = [self.message or self.stage or "working"]
        if self.step_index is not None and self.step_count:
            parts.append(f"step {self.step_index + 1}/{self.step_count}")
        if self.matches is not None:
            parts.append(f"{self.matches} matched")
        return " - ".join(parts)


def format_elapsed(seconds: float) -> str:
    """Elapsed time for a status line: 47s, 3m 05s, 1h 02m."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


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


def unmatched_cell_values(row: "UnmatchedRow") -> tuple:
    """One unmatched row's cells, in UNMATCHED_COLUMNS order.

    Here rather than in the table for the same reason as cell_values: the
    model stays an adapter and the formatting is testable without a GUI.
    """
    kind = "library" if row.is_library else (
        "named" if row.has_real_name else "unnamed")
    return (row.address_text, row.name, kind)


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

    address_query = parse_address_query(needle)

    return [row for row in rows
            if needle in row.name.lower() or row.address == address_query]

# -- flow graph diff -------------------------------------------------------

@dataclass(frozen=True)
class GraphNode:
    """One basic block in a flow-graph diff view."""

    address: int
    lines: Sequence[str]
    matched: bool
    secondary_address: Optional[int] = None

    @property
    def title(self) -> str:
        head = format_address(self.address)
        if self.matched and self.secondary_address is not None:
            return f"{head}  ->  {format_address(self.secondary_address)}"
        return f"{head}  (unmatched)"


@dataclass(frozen=True)
class FlowGraphDiff:
    """A function's control flow, annotated with what the differ paired."""

    nodes: List[GraphNode]
    edges: List[tuple]

    @property
    def matched_count(self) -> int:
        return sum(1 for node in self.nodes if node.matched)

    @property
    def summary(self) -> str:
        total = len(self.nodes)
        matched = self.matched_count
        return (f"{matched} of {total} basic blocks matched, "
                f"{total - matched} changed or new")


def build_flow_graph_diff(blocks, edges,
                          matched_pairs) -> FlowGraphDiff:
    """Annotates a function's blocks with their match state.

    `blocks` is an iterable of (address, lines); `edges` an iterable of
    (source_address, target_address); `matched_pairs` the (primary, secondary)
    pairs the differ recorded for this function.

    Edges naming a block that is not in `blocks` are dropped rather than
    silently creating a node for it: a dangling edge usually means the caller
    passed inconsistent inputs, and inventing the missing block would hide it.
    """
    matched = dict(matched_pairs)

    nodes = []
    index_by_address = {}
    for address, lines in blocks:
        index_by_address[address] = len(nodes)
        nodes.append(GraphNode(address=address, lines=list(lines),
                               matched=address in matched,
                               secondary_address=matched.get(address)))

    resolved = []
    for source, target in edges:
        if source in index_by_address and target in index_by_address:
            resolved.append((index_by_address[source], index_by_address[target]))
    return FlowGraphDiff(nodes=nodes, edges=resolved)

# -- column visibility -----------------------------------------------------

# Eighteen columns is more than fits on a screen, and the C++ chooser showed
# all of them too. These are the ones worth seeing by default; the per-side
# counts and the ported flag are available but off, because they are reference
# figures rather than something to scan.
DEFAULT_VISIBLE_COLUMNS: Sequence[str] = (
    "similarity", "confidence", "change",
    "address_primary", "name_primary",
    "address_secondary", "name_secondary",
    "algorithm",
)


class ColumnVisibility:
    """Which of COLUMNS the match table shows.

    Kept out of the widget so the rules -- defaults, the refusal to hide
    everything, and how a saved set survives a column being added or removed --
    are testable without a display.
    """

    def __init__(self, visible: Optional[Iterable[str]] = None) -> None:
        known = {name for name, _ in COLUMNS}
        if visible is None:
            self._visible = set(DEFAULT_VISIBLE_COLUMNS)
        else:
            # Unknown names are dropped rather than kept: a saved set from an
            # older version may name a column that no longer exists, and
            # carrying it would make is_visible() answer for a column the table
            # has no index for.
            self._visible = {name for name in visible if name in known}
        if not self._visible:
            self._visible = set(DEFAULT_VISIBLE_COLUMNS)

    def is_visible(self, name: str) -> bool:
        return name in self._visible

    def set_visible(self, name: str, visible: bool) -> bool:
        """Shows or hides one column. Returns whether the change was applied.

        Hiding the last visible column is refused: a table with no columns
        cannot be recovered from through the header menu that would have to be
        used to undo it.
        """
        known = {name_ for name_, _ in COLUMNS}
        if name not in known:
            raise ValueError(f"unknown column {name!r}")
        if visible:
            self._visible.add(name)
            return True
        if self._visible == {name}:
            return False
        self._visible.discard(name)
        return True

    def toggle(self, name: str) -> bool:
        return self.set_visible(name, not self.is_visible(name))

    def reset(self) -> None:
        self._visible = set(DEFAULT_VISIBLE_COLUMNS)

    def show_all(self) -> None:
        self._visible = {name for name, _ in COLUMNS}

    def visible_columns(self) -> List[tuple]:
        """The visible (name, label) pairs, in COLUMNS order."""
        return [(name, label) for name, label in COLUMNS
                if name in self._visible]

    def to_list(self) -> List[str]:
        """Serialisable form, in COLUMNS order so it reads predictably."""
        return [name for name, _ in COLUMNS if name in self._visible]

    @classmethod
    def from_list(cls, names) -> "ColumnVisibility":
        return cls(names)
