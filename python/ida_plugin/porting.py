"""Porting names and comments from the secondary binary into the primary.

Split the same way as the UI: planning is pure and testable, applying touches
IDA and is guarded. The plan is also worth having on its own -- it is what a
"preview before applying" dialog would show.

Where the data comes from matters:

* Names are in the .BinDiff itself. The `function` table carries name2 for
  every match, so renaming needs nothing else.
* Comments are *not*. A .BinDiff stores matches only, so the comments have to
  be read from the secondary .BinExport (bindiff.load_comments), and placed
  using the instruction-level address pairs in the `instruction` table. Without
  those pairs you would only know which function a comment belonged to, not
  where in it.

This replaces ResultsWrapper::PortComments, which set a comments_ported flag on
each match and touched nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from bindiff.ida_env import is_interactive


@dataclass(frozen=True)
class SymbolPort:
    """A rename to apply to the primary database."""

    address: int
    new_name: str
    old_name: str
    match_id: int


@dataclass(frozen=True)
class CommentPort:
    """A comment to write into the primary database."""

    address: int
    text: str
    secondary_address: int
    match_id: int


def _is_generated_name(name: str) -> bool:
    """True for a name IDA generated rather than one a person chose.

    Porting is only useful in one direction: an auto-generated name on the
    secondary side carries no information, and overwriting a real primary name
    with one would be a regression.
    """
    if not name:
        return True
    return name.startswith(("sub_", "loc_", "locret_", "unknown_libname_",
                            "nullsub_", "j_sub_", "def_", "byte_", "word_",
                            "dword_", "qword_", "off_", "unk_", "asc_",
                            "algn_", "stru_", "flt_", "dbl_", "xmmword_",
                            "ymmword_"))


def plan_symbol_ports(matches: Iterable, *, min_similarity: float = 0.0,
                      min_confidence: float = 0.0,
                      overwrite_existing: bool = False) -> List[SymbolPort]:
    """Decides which primary functions should take their match's name.

    Skips a match when the secondary name is auto-generated (nothing to learn),
    when the names already agree, or -- unless `overwrite_existing` -- when the
    primary already has a name of its own. Thresholds let a caller refuse to
    trust weak matches, which is the whole reason the engine records
    similarity and confidence per match.
    """
    ports: List[SymbolPort] = []
    for match in matches:
        if match.similarity < min_similarity or match.confidence < min_confidence:
            continue
        if _is_generated_name(match.name_secondary):
            continue
        if match.name_primary == match.name_secondary:
            continue
        if not overwrite_existing and not _is_generated_name(match.name_primary):
            continue
        ports.append(SymbolPort(address=match.address_primary,
                                new_name=match.name_secondary,
                                old_name=match.name_primary,
                                match_id=match.id))
    return ports


def plan_comment_ports(database, comments_by_address: Dict[int, str], *,
                       match_ids: Optional[Sequence[int]] = None,
                       min_similarity: float = 0.0,
                       min_confidence: float = 0.0) -> List[CommentPort]:
    """Maps secondary comments onto primary addresses.

    `comments_by_address` is what bindiff.load_comments() returns for the
    *secondary* .BinExport. Placement uses the instruction pairs recorded for
    each match, so a comment lands on the instruction it was attached to rather
    than somewhere in the right function.
    """
    wanted = set(match_ids) if match_ids is not None else None
    ports: List[CommentPort] = []

    for match in database.matches():
        if wanted is not None and match.id not in wanted:
            continue
        if match.similarity < min_similarity or match.confidence < min_confidence:
            continue
        for primary_address, secondary_address in database.instruction_matches(
                match.id):
            text = comments_by_address.get(secondary_address)
            if text:
                ports.append(CommentPort(address=primary_address, text=text,
                                         secondary_address=secondary_address,
                                         match_id=match.id))
    return ports


@dataclass
class PortResult:
    """What actually happened, as opposed to what was planned."""

    applied: int = 0
    skipped: int = 0
    failed: int = 0

    @property
    def attempted(self) -> int:
        return self.applied + self.skipped + self.failed


def apply_symbol_ports(ports: Sequence[SymbolPort],
                       rename: Optional[Callable[[int, str], bool]] = None
                       ) -> PortResult:
    """Applies renames to the open database.

    `rename` is injected so this is testable without IDA; it defaults to
    ida_name.set_name with SN_NOWARN. A rename that IDA rejects (a name already
    taken, say) counts as failed rather than aborting the run -- porting a few
    hundred names should not stop on the first collision.
    """
    if rename is None:
        rename = _ida_rename

    result = PortResult()
    for port in ports:
        try:
            if rename(port.address, port.new_name):
                result.applied += 1
            else:
                result.failed += 1
        except Exception:
            result.failed += 1
    return result


def apply_comment_ports(ports: Sequence[CommentPort],
                        set_comment: Optional[Callable[[int, str], bool]] = None
                        ) -> PortResult:
    """Writes comments into the open database. `set_comment` is injectable."""
    if set_comment is None:
        set_comment = _ida_set_comment

    result = PortResult()
    for port in ports:
        try:
            if set_comment(port.address, port.text):
                result.applied += 1
            else:
                result.failed += 1
        except Exception:
            result.failed += 1
    return result


def mark_as_library(addresses: Sequence[int]) -> PortResult:
    """Flags functions as library code (FUNC_LIB).

    The "import as external library" variant of porting: the names come from a
    known library, so the primary functions are marked as library code and drop
    out of the analyst's view the same way IDA's own library detection would
    make them.
    """
    if not is_interactive():
        raise RuntimeError("marking functions requires a running IDA database")
    import ida_funcs

    result = PortResult()
    for address in addresses:
        try:
            function = ida_funcs.get_func(address)
            if function is None:
                result.skipped += 1
                continue
            function.flags |= ida_funcs.FUNC_LIB
            if ida_funcs.update_func(function):
                result.applied += 1
            else:
                result.failed += 1
        except Exception:
            result.failed += 1
    return result


def _ida_rename(address: int, name: str) -> bool:
    if not is_interactive():
        raise RuntimeError("renaming requires a running IDA database")
    import ida_name

    return bool(ida_name.set_name(address, name, ida_name.SN_NOWARN))


def _ida_set_comment(address: int, text: str) -> bool:
    if not is_interactive():
        raise RuntimeError("commenting requires a running IDA database")
    import ida_bytes

    return bool(ida_bytes.set_cmt(address, text, False))
