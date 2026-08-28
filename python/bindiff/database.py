"""Read/write access to a .BinDiff result database.

Deliberately plain sqlite3 rather than Cython: this is the layer most likely to
change while building a UI on top, and it should be editable without rebuilding
an extension. The engine (the actual diffing) stays in C++ where it belongs.

Schema, from DatabaseWriter::PrepareDatabase:

    file                one row per input binary, id 1 = primary, 2 = secondary.
                        `functions` counts non-library functions only, with the
                        rest in `libfunctions`; a total is the two summed.
    function            THE MATCH TABLE. One row per matched function pair:
                        address1/name1 and address2/name2 side by side, plus
                        similarity, confidence, flags, algorithm (FK), evaluate,
                        commentsported and the pair's basicblocks/edges/
                        instructions counts. UNIQUE(address1, address2).
    basicblock          matched basic block pairs, FK functionid -> function.id
    instruction         matched instruction pairs, FK -> basicblock.id
    functionalgorithm   id -> step name, e.g. "function: manual"
    metadata            version, the two file ids, overall similarity/confidence

There is no functionmatch table and no per-input function list: unmatched
functions are not stored. Recovering them means comparing these matches against
the function lists in the two .BinExport inputs.

Two conventions worth knowing:

* A match is *manual* when its confidence is 1.0 and its algorithm name
  contains "manual" -- the rule FixedPointInfo::IsManual() applies. The
  `evaluate` column is not that flag; DatabaseWriter always writes 0 to it.
* Addresses are stored as signed BIGINTs. An address above 2**63 comes back
  negative from sqlite and has to be masked; see _to_unsigned.
"""

import sqlite3
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence

MANUAL_ALGORITHM = "function: manual"

_UINT64_MASK = (1 << 64) - 1
_INT64_MIN = -(1 << 63)


def _to_unsigned(value: int) -> int:
    """sqlite stores addresses as signed 64-bit; undo that."""
    return value & _UINT64_MASK if value < 0 else value


def _to_signed(value: int) -> int:
    """Inverse of _to_unsigned, for values on their way back into sqlite."""
    value &= _UINT64_MASK
    return value + _INT64_MIN * 2 if value >= (1 << 63) else value


@dataclass
class FunctionMatch:
    """One row of the `function` table."""

    id: int
    address_primary: int
    name_primary: str
    address_secondary: int
    name_secondary: str
    similarity: float
    confidence: float
    flags: int
    algorithm: str
    comments_ported: bool
    basic_blocks: int
    edges: int
    instructions: int

    @property
    def manual(self) -> bool:
        return self.confidence == 1.0 and "manual" in self.algorithm


@dataclass
class FileInfo:
    """One row of the `file` table. Counts include library code."""

    id: int
    filename: str
    exe_filename: str
    hash: str
    functions: int
    calls: int
    basic_blocks: int
    edges: int
    instructions: int


class BinDiffDatabase:
    """A .BinDiff file, opened for reading or for editing.

    Edits are ordinary sqlite writes inside a transaction; call commit() to keep
    them or rollback() to discard. Nothing is buffered in a parallel Python
    structure, so there is no way for the object and the file to disagree.

        with BinDiffDatabase.open("a_vs_b.BinDiff", read_only=False) as db:
            db.add_manual_match(0x401000, 0x401050)
            db.commit()
    """

    def __init__(self, connection: sqlite3.Connection, path: str,
                 read_only: bool):
        self._connection = connection
        self._path = path
        self._read_only = read_only

    @classmethod
    def open(cls, path: str, read_only: bool = True) -> "BinDiffDatabase":
        """Opens `path`. Refuses to create one: sqlite would happily make an
        empty database out of a typo, and an empty .BinDiff reads as a diff that
        found nothing rather than as an error."""
        uri = f"file:{path}?mode={'ro' if read_only else 'rw'}"
        try:
            connection = sqlite3.connect(uri, uri=True)
        except sqlite3.OperationalError as exc:
            raise FileNotFoundError(f"cannot open {path}: {exc}") from exc
        connection.row_factory = sqlite3.Row
        db = cls(connection, path, read_only)
        db._check_schema()
        return db

    def _check_schema(self) -> None:
        names = {row["name"] for row in self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        missing = {"function", "functionalgorithm", "file"} - names
        if missing:
            raise ValueError(
                f"{self._path} is not a .BinDiff database "
                f"(missing tables: {', '.join(sorted(missing))})")

    def __enter__(self) -> "BinDiffDatabase":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None and not self._read_only:
            self.rollback()
        self.close()

    def close(self) -> None:
        self._connection.close()

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    @property
    def path(self) -> str:
        return self._path

    # -- reading ------------------------------------------------------------

    def matches(self, order_by_similarity: bool = True) -> List[FunctionMatch]:
        order = "ORDER BY f.similarity DESC" if order_by_similarity else "ORDER BY f.id"
        rows = self._connection.execute(f"""
            SELECT f.id, f.address1, f.name1, f.address2, f.name2,
                   f.similarity, f.confidence, f.flags,
                   COALESCE(a.name, '') AS algorithm,
                   f.commentsported, f.basicblocks, f.edges, f.instructions
            FROM function AS f
            LEFT JOIN functionalgorithm AS a ON f.algorithm = a.id
            {order}
        """)
        return [self._row_to_match(row) for row in rows]

    def __iter__(self) -> Iterator[FunctionMatch]:
        return iter(self.matches())

    def __len__(self) -> int:
        return self.num_matches()

    @staticmethod
    def _row_to_match(row: sqlite3.Row) -> FunctionMatch:
        return FunctionMatch(
            id=row["id"],
            address_primary=_to_unsigned(row["address1"]),
            name_primary=row["name1"] or "",
            address_secondary=_to_unsigned(row["address2"]),
            name_secondary=row["name2"] or "",
            similarity=row["similarity"],
            confidence=row["confidence"],
            flags=row["flags"] or 0,
            algorithm=row["algorithm"],
            comments_ported=bool(row["commentsported"]),
            basic_blocks=row["basicblocks"] or 0,
            edges=row["edges"] or 0,
            instructions=row["instructions"] or 0,
        )

    def num_matches(self) -> int:
        return self._connection.execute(
            "SELECT COUNT(*) FROM function").fetchone()[0]

    def find_match(self, *, primary: Optional[int] = None,
                   secondary: Optional[int] = None) -> Optional[FunctionMatch]:
        """Returns the match involving an address, or None.

        A function participates in at most one match per side, so at most one
        row can come back.
        """
        if (primary is None) == (secondary is None):
            raise ValueError("pass exactly one of primary= or secondary=")
        column = "address1" if primary is not None else "address2"
        address = _to_signed(primary if primary is not None else secondary)
        row = self._connection.execute(f"""
            SELECT f.id, f.address1, f.name1, f.address2, f.name2,
                   f.similarity, f.confidence, f.flags,
                   COALESCE(a.name, '') AS algorithm,
                   f.commentsported, f.basicblocks, f.edges, f.instructions
            FROM function AS f
            LEFT JOIN functionalgorithm AS a ON f.algorithm = a.id
            WHERE f.{column} = ?
        """, (address,)).fetchone()
        return self._row_to_match(row) if row else None

    def files(self) -> List[FileInfo]:
        """The two input binaries. Counts include library code."""
        rows = self._connection.execute("""
            SELECT id, filename, exefilename, hash,
                   functions + libfunctions AS functions,
                   calls,
                   basicblocks + libbasicblocks AS basicblocks,
                   edges + libedges AS edges,
                   instructions + libinstructions AS instructions
            FROM file ORDER BY id
        """)
        return [FileInfo(id=r["id"], filename=r["filename"],
                         exe_filename=r["exefilename"], hash=r["hash"],
                         functions=r["functions"], calls=r["calls"],
                         basic_blocks=r["basicblocks"], edges=r["edges"],
                         instructions=r["instructions"]) for r in rows]

    def instruction_matches(self, match_id: Optional[int] = None
                            ) -> List[tuple]:
        """Matched instruction address pairs, as (primary, secondary).

        These come from the `instruction` table, joined up through `basicblock`
        to the function match. They are what makes precise comment porting
        possible: a function-level match alone would only let you guess where
        inside the function a comment belongs.
        """
        query = """
            SELECT i.address1, i.address2
            FROM instruction AS i
            INNER JOIN basicblock AS b ON i.basicblockid = b.id
        """
        params: tuple = ()
        if match_id is not None:
            query += " WHERE b.functionid = ?"
            params = (match_id,)
        return [(_to_unsigned(row[0]), _to_unsigned(row[1]))
                for row in self._connection.execute(query, params)]

    def basic_block_matches(self, match_id: int) -> List[tuple]:
        """Matched basic block pairs for one function match.

        What makes a flow-graph diff possible: it says which blocks of the
        primary function were paired, and with what on the secondary side.
        Blocks absent from this list are what actually changed.
        """
        rows = self._connection.execute(
            "SELECT address1, address2 FROM basicblock WHERE functionid = ?",
            (match_id,))
        return [(_to_unsigned(r[0]), _to_unsigned(r[1])) for r in rows]

    def algorithms(self) -> dict:
        """Maps algorithm name -> id."""
        return {row["name"]: row["id"] for row in self._connection.execute(
            "SELECT id, name FROM functionalgorithm")}

    # -- writing ------------------------------------------------------------

    def _require_writable(self) -> None:
        if self._read_only:
            raise PermissionError(
                "database opened read-only; reopen with read_only=False")

    def _manual_algorithm_id(self) -> int:
        row = self._connection.execute(
            "SELECT id FROM functionalgorithm WHERE name = ?",
            (MANUAL_ALGORITHM,)).fetchone()
        if row is not None:
            return row["id"]
        # Every database DatabaseWriter produces has this row, but a
        # hand-assembled one might not.
        next_id = (self._connection.execute(
            "SELECT COALESCE(MAX(id), 0) FROM functionalgorithm"
        ).fetchone()[0]) + 1
        self._connection.execute(
            "INSERT INTO functionalgorithm VALUES (?, ?)",
            (next_id, MANUAL_ALGORITHM))
        return next_id

    def add_manual_match(self, primary_address: int, secondary_address: int,
                         *, name_primary: str = "",
                         name_secondary: str = "") -> FunctionMatch:
        """Records a manual match between two function entry points.

        Manual means confidence 1.0 against the "function: manual" algorithm,
        which is what makes IsManual() true on read-back.

        Raises ValueError if either function is already matched. The schema's
        UNIQUE(address1, address2) only stops the identical pair being inserted
        twice; it would happily let one function match two different ones, which
        is not a state the format is meant to represent.
        """
        self._require_writable()

        existing = self.find_match(primary=primary_address)
        if existing is not None:
            raise ValueError(
                f"primary 0x{primary_address:x} is already matched to "
                f"0x{existing.address_secondary:x}")
        existing = self.find_match(secondary=secondary_address)
        if existing is not None:
            raise ValueError(
                f"secondary 0x{secondary_address:x} is already matched to "
                f"0x{existing.address_primary:x}")

        algorithm_id = self._manual_algorithm_id()
        next_id = (self._connection.execute(
            "SELECT COALESCE(MAX(id), 0) FROM function").fetchone()[0]) + 1

        # Counts are left at 0: they describe how much of the two functions the
        # differ managed to pair up, and a manual match has paired nothing at
        # the basic block level. Running an incremental diff would fill them in.
        self._connection.execute(
            "INSERT INTO function VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (next_id,
             _to_signed(primary_address), name_primary,
             _to_signed(secondary_address), name_secondary,
             1.0, 1.0, 0, algorithm_id, 0, 0, 0, 0, 0))
        return self.find_match(primary=primary_address)

    def delete_matches(self, ids: Sequence[int]) -> int:
        """Deletes matches by row id, with their basic block and instruction
        rows. Returns how many were deleted."""
        self._require_writable()
        ids = list(ids)
        if not ids:
            return 0
        placeholders = ",".join("?" * len(ids))
        # instruction -> basicblock -> function, so unwind in that order;
        # sqlite does not enforce these foreign keys by default.
        self._connection.execute(
            f"DELETE FROM instruction WHERE basicblockid IN "
            f"(SELECT id FROM basicblock WHERE functionid IN ({placeholders}))",
            ids)
        self._connection.execute(
            f"DELETE FROM basicblock WHERE functionid IN ({placeholders})", ids)
        cursor = self._connection.execute(
            f"DELETE FROM function WHERE id IN ({placeholders})", ids)
        return cursor.rowcount

    def confirm_matches(self, ids: Sequence[int]) -> int:
        """Marks matches as manually confirmed: full confidence against the
        manual algorithm. Returns how many rows changed."""
        self._require_writable()
        ids = list(ids)
        if not ids:
            return 0
        algorithm_id = self._manual_algorithm_id()
        placeholders = ",".join("?" * len(ids))
        cursor = self._connection.execute(
            f"UPDATE function SET confidence = 1.0, algorithm = ? "
            f"WHERE id IN ({placeholders})", [algorithm_id] + ids)
        return cursor.rowcount

    def set_comments_ported(self, ids: Sequence[int],
                            ported: bool = True) -> int:
        """Records whether comments have been ported for these matches.

        This is bookkeeping only -- it does not move any comment. The caller is
        what actually reads and writes them in the disassembler.
        """
        self._require_writable()
        ids = list(ids)
        if not ids:
            return 0
        placeholders = ",".join("?" * len(ids))
        cursor = self._connection.execute(
            f"UPDATE function SET commentsported = ? "
            f"WHERE id IN ({placeholders})", [1 if ported else 0] + ids)
        return cursor.rowcount
