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

import inspect
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from bindiff.ida_env import database_is_open


# How good a match has to be before its name or comments are copied.
#
# Not zero, which is what these were. Porting writes into the primary database
# and a wrong name is not obviously wrong afterwards -- it looks like analysis
# somebody did. Measured on nine pairs of real stripped programs, porting every
# match copies 1440 names of which **516 are wrong**: 36% of the engine's
# judgeable matches disagree with ground truth, because the weakest matching
# steps pair up whatever is left over and the engine records that in the
# similarity and confidence it stores.
#
# What a floor on both costs and buys, from that measurement:
#
#   floor   ported   wrong   precision   share of correct kept
#    0.0      1440     516       64.2%                  100.0%
#    0.3       886     117       86.8%                   83.2%
#    0.5       676      42       93.8%                   68.6%
#    0.8       507      15       97.0%                   53.2%
#
# 0.5 is chosen because the asymmetry is severe: a skipped port costs a rename
# the user can still do by hand, and a wrong port costs a wrong name they have
# no reason to doubt. Raising it further buys little and loses a lot.
#
# A caller who wants the old behaviour passes 0.0 explicitly, which is a
# different thing from getting it by default.
DEFAULT_PORT_MIN_SIMILARITY = 0.5
DEFAULT_PORT_MIN_CONFIDENCE = 0.5


@dataclass(frozen=True)
class SymbolPort:
    """A rename to apply to the primary database."""

    address: int
    new_name: str
    old_name: str
    match_id: int


@dataclass(frozen=True)
class CommentPort:
    """A comment to write into the primary database.

    `kind` decides where it goes. A function comment written with set_cmt
    lands on the first instruction instead of on the function, which looks
    almost right and is not: it does not show in the functions list, does not
    survive a re-analysis of that instruction, and is not what was copied.
    """

    address: int
    text: str
    secondary_address: int
    match_id: int
    kind: str = "instruction"

    @property
    def is_function_comment(self) -> bool:
        return self.kind == "function"


def _is_generated_name(name: str) -> bool:
    """True for a name IDA generated rather than one a person chose.

    Delegates to ui_logic, which the view filters use too. Two copies is how
    one of them learns about a new prefix and the other does not, and the
    symptom would be a filter that promises rows the porting rules then
    refuse.
    """
    from ida_plugin.ui_logic import is_generated_name

    return is_generated_name(name)


def explain_symbol_port_skips(
        matches: Iterable, *,
        min_similarity: float = DEFAULT_PORT_MIN_SIMILARITY,
        min_confidence: float = DEFAULT_PORT_MIN_CONFIDENCE,
        overwrite_existing: bool = False) -> dict:
    """Why matches were not renamed, counted by reason.

    plan_symbol_ports drops matches for four different reasons and says
    nothing about it, so "renamed 9 function(s)" out of ten selected leaves
    the tenth unaccounted for -- and the most common reason, that the primary
    already has a name, is a deliberate refusal that looks like a failure.

    Mirrors plan_symbol_ports' conditions in the same order. Both walking the
    same list twice is worth the duplication only because they are next to
    each other and tested together; if a third caller appears, they should be
    one pass returning both.
    """
    reasons: dict = {}

    def note(key):
        reasons[key] = reasons.get(key, 0) + 1

    for match in matches:
        if match.similarity < min_similarity or match.confidence < min_confidence:
            note("below the similarity or confidence floor")
        elif _is_generated_name(match.name_secondary):
            note("the match has no real name to give")
        elif match.name_primary == match.name_secondary:
            note("already named the same")
        elif not overwrite_existing and not _is_generated_name(match.name_primary):
            note("already named here, and renaming would overwrite it")
    return reasons


def plan_symbol_ports(
        matches: Iterable, *,
        min_similarity: float = DEFAULT_PORT_MIN_SIMILARITY,
        min_confidence: float = DEFAULT_PORT_MIN_CONFIDENCE,
        overwrite_existing: bool = False) -> List[SymbolPort]:
    """Decides which primary functions should take their match's name.

    Skips a match when it is too weak to trust (see the thresholds above),
    when the secondary name is auto-generated (nothing to learn), when the
    names already agree, or -- unless `overwrite_existing` -- when the primary
    already has a name of its own.

    The thresholds are why the engine records similarity and confidence per
    match, and they default to refusing weak matches rather than accepting
    them: this writes into the user's database.
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


def plan_comment_ports(
        database, comments_by_address: Dict[int, object], *,
        match_ids: Optional[Sequence[int]] = None,
        min_similarity: float = DEFAULT_PORT_MIN_SIMILARITY,
        min_confidence: float = DEFAULT_PORT_MIN_CONFIDENCE
) -> List[CommentPort]:
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
        # A function comment belongs to the function, so it is looked up at
        # the match's own addresses rather than through an instruction pair.
        # Going through instruction pairs loses it whenever the entry
        # instruction did not match, which is common: a changed prologue
        # means the first matched pair starts a few bytes in, and the comment
        # sits on an address nothing points at. On the measured pair that
        # cost 124 of 243 function comments.
        entry = comments_by_address.get(match.address_secondary)
        if entry:
            ports.extend(
                port for port in _ports_for(entry, match.address_primary,
                                            match.address_secondary, match.id)
                if port.kind == "function")

        for primary_address, secondary_address in database.instruction_matches(
                match.id):
            found = comments_by_address.get(secondary_address)
            if not found:
                continue
            ports.extend(
                port for port in _ports_for(found, primary_address,
                                            secondary_address, match.id)
                # Function comments are handled above; a matched entry
                # instruction would otherwise plan the same comment twice.
                if port.kind != "function")
    return ports


def _ports_for(found, primary_address, secondary_address, match_id):
    """One or more ports from whatever the caller had at an address.

    Accepts a plain string, which is what the old comment loader returned and
    what several tests still pass, or a list of bindiff.comments
    ExportedComment, which carries the type. A function comment and an
    instruction comment at one address are two ports: they go to different
    places in IDA and neither substitutes for the other.

    Without this the list itself was handed to set_cmt as the comment text,
    which fails with "argument 2 of type 'char const *'" -- a type error from
    inside IDA rather than anywhere near the mistake.
    """
    if isinstance(found, str):
        return [CommentPort(address=primary_address, text=found,
                            secondary_address=secondary_address,
                            match_id=match_id)]

    ports = []
    for comment in found:
        text = getattr(comment, "text", None)
        if not isinstance(text, str) or not text:
            continue
        kind = ("function" if getattr(comment, "is_function_comment", False)
                else "instruction")
        ports.append(CommentPort(address=primary_address, text=text,
                                 secondary_address=secondary_address,
                                 match_id=match_id, kind=kind))
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
                        set_comment: Optional[Callable[..., bool]] = None
                        ) -> PortResult:
    """Writes comments into the open database. `set_comment` is injectable.

    Each port knows whether it is a function comment or an instruction one and
    the writer is told, because they go to different places in IDA.
    """
    if set_comment is None:
        set_comment = _ida_set_comment

    # Whether the writer takes a kind is decided once, by looking, rather
    # than by calling it and catching TypeError. Catching it caught the wrong
    # one: a TypeError raised *inside* IDA -- set_cmt refusing a comment that
    # was not a string -- looked like an old two-argument stub, so it retried
    # and failed identically, and the traceback blamed the retry.
    takes_kind = True
    try:
        parameters = inspect.signature(set_comment).parameters
        takes_kind = len(parameters) >= 3 or any(
            p.kind is inspect.Parameter.VAR_POSITIONAL for p in
            parameters.values())
    except (TypeError, ValueError):
        # A builtin or C function with no introspectable signature.
        takes_kind = True

    result = PortResult()
    for port in ports:
        try:
            written = (set_comment(port.address, port.text, port.kind)
                       if takes_kind
                       else set_comment(port.address, port.text))
        except Exception:
            result.failed += 1
            continue
        result.applied += 1 if written else 0
        result.failed += 0 if written else 1
    return result


def mark_as_library(addresses: Sequence[int]) -> PortResult:
    """Flags functions as library code (FUNC_LIB).

    The "import as external library" variant of porting: the names come from a
    known library, so the primary functions are marked as library code and drop
    out of the analyst's view the same way IDA's own library detection would
    make them.
    """
    if not database_is_open():
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
    if not database_is_open():
        raise RuntimeError("renaming requires a running IDA database")
    import ida_name

    # SN_NOCHECK and SN_FORCE, not the defaults. Measured over all 1,347
    # planned renames on the real pair: the defaults applied 0, adding
    # SN_NOCHECK applied 509, adding SN_FORCE applied 1,347.
    #
    # SN_NOCHECK is about characters. A .BinDiff stores demangled C++ names --
    # "CPaneFrameWnd::OnSizing(uint,tagRECT *)" -- and IDA refuses those as
    # identifiers: backticks, spaces, asterisks and colons are not legal in a
    # name. Measured on the real pair, the default flags renamed 0 of 3
    # planned and reported nothing, because a refusal is a False return and
    # not an exception.
    #
    # SN_NOCHECK accepts the name and replaces what it cannot keep, giving
    # CPaneFrameWnd::OnSizing(uint,tagRECT__). Imperfect, and much better than
    # leaving sub_13000E870.
    #
    # SN_FORCE is about collisions, which are the larger half: 719 of the 838
    # names SN_NOCHECK alone could not place were duplicates. C++ thunks and
    # template instances demangle identically --
    # "COleControl::FireEvent(long,uchar *,...)" occurs at four addresses --
    # and IDA refuses a name already in use. SN_FORCE appends a numeric
    # suffix, which is what IDA does for its own duplicates and what diaphora
    # hand-rolls with a "_{i}" loop.
    #
    # So some functions end up as name_0 and name_1. That is honest about
    # there being several, and better than leaving them all sub_.
    return bool(ida_name.set_name(
        address, name,
        ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE))


def _ida_set_comment(address: int, text: str,
                     kind: str = "instruction") -> bool:
    if not database_is_open():
        raise RuntimeError("commenting requires an open IDA database")
    import ida_bytes
    import ida_funcs

    if kind == "function":
        function = ida_funcs.get_func(address)
        if function is not None:
            # Non-repeatable: a repeatable function comment is echoed at every
            # call site, which is rarely what someone wrote it for.
            return bool(ida_funcs.set_func_cmt(function, text, False))
        # No function here -- fall through rather than lose the comment.
    return bool(ida_bytes.set_cmt(address, text, False))
