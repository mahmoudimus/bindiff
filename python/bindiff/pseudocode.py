"""Comments written in the decompiler view, as plain data.

Hex-Rays keeps these somewhere else entirely. A comment you type in the
pseudocode window is stored in the decompiler's own netnode, keyed by a
`treeloc_t` -- an address plus an *item preciser* saying where on that line
it sits -- and reached through restore_user_cmts / save_user_cmts. It is not
a disassembly comment: set_cmt never sees it, and neither does BinExport,
whose comment table is the disassembly's.

So on a real database the same note can exist twice, at two addresses:

    disassembly comment  @ 0x180097611   the `mov ecx, 0C9A1h`
    decompiler comment   @ 0x180097616   the `call`, itp 69

Porting only the first is what made an imported function show the comment in
the disassembly and not in the pseudocode -- the thing that renders the
pseudocode line was never copied.

This module is pure data so it can be tested without IDA. Reading and writing
live in pseudocode_ida.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

# Bumped when the shape changes. Shares the type sidecar's file, so a reader
# that predates this simply finds no such key.
PSEUDOCODE_FORMAT_VERSION = 1


@dataclass(frozen=True)
class PseudocodeComment:
    """One comment in one decompiled function.

    `function` is the entry point, which is how Hex-Rays files them and how a
    match is keyed. `address` and `item` are the treeloc: an address inside
    the function and Hex-Rays' item preciser. `item` is carried across
    verbatim -- it names a position in the printed line (after the semicolon,
    on argument three) and means the same thing in either database.
    """

    function: int
    address: int
    item: int
    text: str


def to_json(comments: Sequence[PseudocodeComment]) -> list:
    return [{"function": c.function, "address": c.address,
             "item": c.item, "text": c.text} for c in comments]


def from_json(entries: Iterable[dict]) -> List[PseudocodeComment]:
    """Reads them back, dropping anything without text.

    Tolerant of a missing section: a sidecar written before this existed has
    no such key, and that is an older file rather than a broken one.
    """
    out = []
    for entry in entries or ():
        text = entry.get("text")
        if not text:
            continue
        try:
            out.append(PseudocodeComment(function=int(entry["function"]),
                                         address=int(entry["address"]),
                                         item=int(entry["item"]),
                                         text=text))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def by_function(comments: Iterable[PseudocodeComment]
                ) -> Dict[int, List[PseudocodeComment]]:
    """Grouped by entry point, which is how a match addresses them."""
    grouped: Dict[int, List[PseudocodeComment]] = {}
    for comment in comments:
        grouped.setdefault(comment.function, []).append(comment)
    return grouped


def translate(comments: Sequence[PseudocodeComment],
              address_map: Dict[int, int],
              function: int) -> List[PseudocodeComment]:
    """Moves comments onto the primary's addresses.

    `address_map` maps secondary addresses to primary ones, which is what the
    result file's matched instruction pairs give. A comment whose address did
    not match is dropped rather than guessed at: Hex-Rays would take a wrong
    treeloc silently and then discard it as an orphan at the next
    decompilation, which looks exactly like the comment never having been
    ported.
    """
    out = []
    for comment in comments:
        primary = address_map.get(comment.address)
        if primary is None:
            continue
        out.append(PseudocodeComment(function=function, address=primary,
                                     item=comment.item, text=comment.text))
    return out
