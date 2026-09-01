"""Reads and writes Hex-Rays pseudocode comments in an open database.

Runs where a database is open: the worker's idalib process for reading, IDA
itself for writing. Everything that does not need IDA lives in
bindiff.pseudocode.

The decompiler may not be present -- Hex-Rays is licensed separately and is
not in every install -- so every entry point here degrades to "none" rather
than raising. A missing decompiler is a smaller loss than a failed export.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from bindiff.pseudocode import PseudocodeComment


def decompiler() -> Optional[object]:
    """ida_hexrays, initialised, or None when there is no decompiler.

    init_hexrays_plugin() is what says whether it is *usable*, as against
    importable: the module imports in an install without a licence and every
    call then fails.
    """
    try:
        import ida_hexrays
    except ImportError:
        return None
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
    except Exception:
        return None
    return ida_hexrays


def read_pseudocode_comments(entries: Optional[Sequence[int]] = None
                             ) -> List[PseudocodeComment]:
    """Every decompiler comment in this database.

    Reads the stored comments, never decompiles. restore_user_cmts is a
    netnode read, so this costs a pass over the function list and nothing
    more -- 10,435 functions in well under a second. Decompiling them to find
    out would cost minutes and change nothing: a comment nobody wrote is not
    stored.
    """
    hexrays = decompiler()
    if hexrays is None:
        return []
    import ida_funcs

    if entries is None:
        entries = [ida_funcs.get_func_ea_by_num(i)
                   if hasattr(ida_funcs, "get_func_ea_by_num")
                   else ida_funcs.getn_func(i).start_ea
                   for i in range(ida_funcs.get_func_qty())]

    out: List[PseudocodeComment] = []
    for entry in entries:
        if entry is None or entry == 0xFFFFFFFFFFFFFFFF:
            continue
        try:
            stored = hexrays.restore_user_cmts(entry)
        except Exception:
            continue
        if not stored:
            continue
        for location, comment in stored.items():
            text = str(comment)
            if not text.strip():
                continue
            out.append(PseudocodeComment(function=entry,
                                         address=location.ea,
                                         item=int(location.itp),
                                         text=text))
    return out


def apply_pseudocode_comments(comments: Sequence[PseudocodeComment]
                              ) -> Tuple[int, int]:
    """Writes them into the open database. Returns (written, refused).

    Merged into whatever the function already has rather than replacing it:
    save_user_cmts takes the whole set for a function, so writing only the
    new ones would delete every comment already there.

    A comment is verified by decompiling the function afterwards. Hex-Rays
    accepts any treeloc and then silently drops the ones that do not land on
    a ctree item -- they become "orphan comments" at the next decompilation.
    Counting a write as success without that check would report a number that
    is right at the moment it is printed and wrong by the time anyone looks.
    """
    hexrays = decompiler()
    if hexrays is None:
        return (0, len(comments))

    from bindiff.pseudocode import by_function

    written = refused = 0
    for entry, group in by_function(comments).items():
        try:
            stored = hexrays.restore_user_cmts(entry)
            if stored is None:
                stored = hexrays.user_cmts_new()
            for comment in group:
                location = hexrays.treeloc_t()
                location.ea = comment.address
                location.itp = comment.item
                stored[location] = hexrays.citem_cmt_t(comment.text)
            hexrays.save_user_cmts(entry, stored)
        except Exception:
            refused += len(group)
            continue

        # Decompiling reconciles what was stored against the ctree, so what
        # survives here is what the user will see.
        kept = _surviving(hexrays, entry)
        for comment in group:
            if (comment.address, comment.item) in kept:
                written += 1
            else:
                refused += 1
    return (written, refused)


def _surviving(hexrays, entry: int) -> set:
    """The (address, item) pairs the decompiler still holds for a function.

    Best effort: a function that will not decompile is not evidence that the
    comment was lost, so the write is trusted in that case rather than being
    reported as refused for a reason that has nothing to do with it.
    """
    try:
        function = hexrays.decompile(entry)
        if function is None:
            raise RuntimeError("did not decompile")
        stored = function.user_cmts
    except Exception:
        stored = None
    if stored is None:
        try:
            stored = hexrays.restore_user_cmts(entry)
        except Exception:
            return _ALL
    if stored is None:
        return _ALL
    return {(location.ea, int(location.itp)) for location, _ in stored.items()}


class _Everything:
    """Stands in when survival could not be established, so an unverifiable
    write counts as written rather than as lost."""

    def __contains__(self, _item) -> bool:
        return True


_ALL = _Everything()
