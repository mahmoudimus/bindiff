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
from dataclasses import dataclass, field
from typing import (Callable, Dict, Iterable, List, Optional, Sequence,
                    Set, Tuple)

from bindiff.ida_env import database_is_open
from ida_plugin.ui_logic import (STATE_PORTED, STATE_REFUSED, STATE_REPLACED,
                                 STATE_SKIPPED, is_generated_name)


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


OUTCOME_WILL_WRITE = "will write"
OUTCOME_REPLACES_YOURS = "replaces yours"
OUTCOME_ALREADY_NAMED = "already named"
OUTCOME_BELOW_THRESHOLD = "below threshold"
OUTCOME_NOTHING = "nothing to write"


@dataclass(frozen=True)
class PortPreview:
    """What a port at one threshold would do, before it does it.

    The footer is the confirmation: it separates the three outcomes a single
    count hides, and it is on screen before anything is written. 516 of
    1,440 unthresholded writes were wrong on the measured corpus; the
    threshold is therefore the first control, not an advanced setting.
    """

    threshold: float
    will_write: Tuple[SymbolPort, ...]
    replaces_yours: Tuple[SymbolPort, ...]
    already_named: Tuple[int, ...]
    below_threshold: Tuple[int, ...]
    nothing_to_write: Tuple[int, ...]

    def __post_init__(self) -> None:
        # Built once, because the caller asks per row: the workbench takes one
        # outcome for every row it shows on every refresh, so scanning the
        # buckets would make a redraw quadratic in the size of the result --
        # 10,000 matches against 10,000 shown rows, per keystroke. Set through
        # object.__setattr__ since the dataclass is frozen, and derived from
        # the fields, so it stays out of eq and repr.
        by_id: Dict[int, str] = {}
        for port in self.will_write:
            by_id.setdefault(port.match_id, OUTCOME_WILL_WRITE)
        for port in self.replaces_yours:
            by_id.setdefault(port.match_id, OUTCOME_REPLACES_YOURS)
        for match_id in self.already_named:
            by_id.setdefault(match_id, OUTCOME_ALREADY_NAMED)
        for match_id in self.below_threshold:
            by_id.setdefault(match_id, OUTCOME_BELOW_THRESHOLD)
        for match_id in self.nothing_to_write:
            by_id.setdefault(match_id, OUTCOME_NOTHING)
        object.__setattr__(self, "_by_id", by_id)

    @property
    def ports(self) -> List[SymbolPort]:
        return list(self.will_write) + list(self.replaces_yours)

    def outcome(self, match_id: int) -> str:
        """The bucket this match is in, or "" for an id the preview never saw."""
        return self._by_id.get(match_id, "")

    def summary(self) -> str:
        """The footer, counting each outcome separately.

        A write that overwrites a name the user chose is counted on its own
        line rather than folded into the total: it is the one outcome the
        reader might want to stop, and a single "N will be written" hides it.
        """
        parts = [f"{len(self.will_write):,} will be written"]
        if self.already_named:
            parts.append(f"{len(self.already_named):,} already named, skipped")
        if self.replaces_yours:
            parts.append(f"{len(self.replaces_yours):,} replace a name you wrote")
        if self.below_threshold:
            parts.append(f"{len(self.below_threshold):,} below {self.threshold:.2f}")
        return " · ".join(parts)


def preview_symbol_ports(matches: Iterable, *, min_similarity: float,
                         min_confidence: float = DEFAULT_PORT_MIN_CONFIDENCE
                         ) -> PortPreview:
    """Sorts every match into the bucket a port at this threshold puts it in.

    Same conditions as plan_symbol_ports, but nothing is dropped: every match
    id lands somewhere, so a row can show its outcome.

    "Nothing to write" is tested before the threshold, unlike in
    plan_symbol_ports, where the order cannot be observed because both mean
    "skip". Here it can: a match whose secondary side has only a generated
    name has nothing to give at *any* threshold, so it must not move buckets
    as the slider does -- a row that reads "below threshold" invites raising
    the threshold to fix something the threshold does not control.
    """
    will_write: List[SymbolPort] = []
    replaces: List[SymbolPort] = []
    already: List[int] = []
    below: List[int] = []
    nothing: List[int] = []
    for match in matches:
        if _is_generated_name(match.name_secondary):
            nothing.append(match.id)
        elif match.similarity < min_similarity or match.confidence < min_confidence:
            below.append(match.id)
        elif match.name_primary == match.name_secondary:
            already.append(match.id)
        else:
            port = SymbolPort(address=match.address_primary,
                              new_name=match.name_secondary,
                              old_name=match.name_primary, match_id=match.id)
            (will_write if _is_generated_name(match.name_primary)
             else replaces).append(port)
    return PortPreview(min_similarity, tuple(will_write), tuple(replaces),
                       tuple(already), tuple(below), tuple(nothing))


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

    selected = [match for match in database.matches()
                if (wanted is None or match.id in wanted)
                and match.similarity >= min_similarity
                and match.confidence >= min_confidence]
    # One query for the whole selection. Asking per match walks an unindexed
    # join once per match: 110 seconds for 1237 of them, with the UI frozen
    # throughout, to produce seven comments.
    pairs_by_match = database.instruction_matches_for(
        [match.id for match in selected])

    for match in selected:
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

        for primary_address, secondary_address in pairs_by_match.get(
                match.id, ()):
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
    # Where a write was refused. IDA's setters return False rather than
    # raising, so without these a comment the database rejected is
    # indistinguishable from one that was never planned -- which is exactly
    # the question asked when a single comment goes missing from an import.
    failed_addresses: List[int] = field(default_factory=list)
    # The matches that took something. Counts alone cannot answer "which of
    # these did I import", which is what the result view has to show once a
    # selection has been imported and the next one is being chosen.
    applied_matches: Set[int] = field(default_factory=set)

    @property
    def attempted(self) -> int:
        return self.applied + self.skipped + self.failed

    def record(self, port, written: bool) -> None:
        """Counts one write. Takes the port, not an address, because what
        happened has to be attributable to a match as well as to a place."""
        if written:
            self.applied += 1
            self.applied_matches.add(port.match_id)
        else:
            self.failed += 1
            self.failed_addresses.append(port.address)


@dataclass(frozen=True)
class LedgerEntry:
    """One row's worth of what a port did."""

    match_id: int
    outcome: str
    address: int
    old_name: str
    new_name: str
    comments_written: int = 0

    @property
    def reversible(self) -> bool:
        return (self.outcome in (STATE_PORTED, STATE_REPLACED)
                and self.old_name != self.new_name)


class PortLedger:
    """Per-row record of what a port did, for the State column and for undo.

    "Renamed 9 function(s)" dropped the interesting case. Each row here is
    addressable, and a ported or replaced name can be reversed one at a time
    -- the undo that ships before real undo exists. Session-only: the
    .BinDiff has one flag (commentsported) and the schema is not extended.
    """

    def __init__(self) -> None:
        self._entries: Dict[int, LedgerEntry] = {}

    def record(self, entry: LedgerEntry) -> None:
        self._entries[entry.match_id] = entry

    def entry(self, match_id: int) -> Optional[LedgerEntry]:
        return self._entries.get(match_id)

    def outcome(self, match_id: int) -> Optional[str]:
        found = self._entries.get(match_id)
        return found.outcome if found else None

    def forget(self, match_id: int) -> None:
        self._entries.pop(match_id, None)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        """The entries, in the order they were recorded.

        A copy, so a caller merging one ledger into another -- which is what
        the session does with a port's delta -- cannot trip over the dict
        changing size while it reads.
        """
        return iter(list(self._entries.values()))

    def counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self._entries.values():
            counts[entry.outcome] = counts.get(entry.outcome, 0) + 1
        return counts

    def summary(self) -> str:
        counts = self.counts()
        parts = [f"Ported {counts.get(STATE_PORTED, 0):,}"]
        if counts.get(STATE_REPLACED):
            parts.append(f"{counts[STATE_REPLACED]:,} replaced a name you wrote")
        if counts.get(STATE_SKIPPED):
            parts.append(f"{counts[STATE_SKIPPED]:,} skipped")
        if counts.get(STATE_REFUSED):
            parts.append(f"{counts[STATE_REFUSED]:,} refused by IDA")
        return " · ".join(parts)

    def reversal(self, match_id: int) -> Optional[SymbolPort]:
        """The port that would put the old name back, or None.

        Only a name this session actually wrote can be taken back, which is
        what `reversible` decides -- offering to "undo" a row nothing was
        written to would write a name that was never there.
        """
        entry = self._entries.get(match_id)
        if entry is None or not entry.reversible:
            return None
        return SymbolPort(address=entry.address, new_name=entry.old_name,
                          old_name=entry.new_name, match_id=match_id)


def build_ledger(preview: PortPreview, symbols: PortResult,
                 comments: Optional[PortResult], *,
                 into: Optional[PortLedger] = None) -> PortLedger:
    """Turns a preview plus what the writes returned into per-row outcomes.

    A planned write that neither landed nor was refused is skipped, not
    failed: IDA reports refusal by returning False, so the only evidence a
    write was attempted at all is the address in `failed_addresses`.
    """
    ledger = into if into is not None else PortLedger()
    wrote_comment = comments.applied_matches if comments is not None else set()

    def note(match_id, outcome, address=0, old="", new=""):
        ledger.record(LedgerEntry(match_id, outcome, address, old, new,
                                  1 if match_id in wrote_comment else 0))

    attempted = ([(port, STATE_PORTED) for port in preview.will_write]
                 + [(port, STATE_REPLACED) for port in preview.replaces_yours])
    for port, written_outcome in attempted:
        if port.match_id in symbols.applied_matches:
            outcome = written_outcome
        elif port.address in symbols.failed_addresses:
            outcome = STATE_REFUSED
        else:
            outcome = STATE_SKIPPED
        note(port.match_id, outcome, port.address, port.old_name, port.new_name)

    for match_id in (preview.already_named + preview.below_threshold
                     + preview.nothing_to_write):
        note(match_id, STATE_SKIPPED)
    return ledger


def apply_symbol_ports(ports: Sequence[SymbolPort],
                       rename: Optional[Callable[[int, str], bool]] = None
                       ) -> PortResult:
    """Applies renames to the open database.

    `rename` is injected so this is testable without IDA; it defaults to
    idaapi.set_name with SN_NOWARN. A rename that IDA rejects (a name already
    taken, say) counts as failed rather than aborting the run -- porting a few
    hundred names should not stop on the first collision.
    """
    if rename is None:
        rename = _ida_rename

    result = PortResult()
    for port in ports:
        try:
            written = rename(port.address, port.new_name)
        except Exception:
            result.failed += 1
            result.failed_addresses.append(port.address)
            continue
        result.record(port, written)
    return result


def plan_stack_name_ports(database, names_by_operand, match_ids=None,
                          min_similarity: float = None,
                          min_confidence: float = None) -> list:
    """Which stack variables to rename, addressed by instruction.

    `names_by_operand` is bindiff.stack_names.stack_names_by_operand for the
    secondary export: {address: {operand index: StackName}}, generated names
    already dropped.

    The offset is deliberately not carried. A .BinExport records the raw
    displacement in the instruction and the two sides do not agree about it --
    987 of 2910 matched operands differed on the measured pair -- so the name
    travels with the instruction and the primary's own offset is resolved
    against the database when the rename is applied.
    """
    from bindiff.stack_names import names_a_whole_variable
    from bindiff.stack_names_ida import StackNamePort

    if min_similarity is None:
        min_similarity = DEFAULT_PORT_MIN_SIMILARITY
    if min_confidence is None:
        min_confidence = DEFAULT_PORT_MIN_CONFIDENCE

    wanted = set(match_ids) if match_ids is not None else None
    selected = [match for match in database.matches()
                if (wanted is None or match.id in wanted)
                and match.similarity >= min_similarity
                and match.confidence >= min_confidence]
    if not selected:
        return []
    pairs_by_match = database.instruction_matches_for(
        [match.id for match in selected])

    ports = []
    for match in selected:
        for primary_address, secondary_address in pairs_by_match.get(
                match.id, ()):
            found = names_by_operand.get(secondary_address)
            if not found:
                continue
            for operand_index, entry in sorted(found.items()):
                if not names_a_whole_variable(entry.name):
                    continue
                ports.append(StackNamePort(
                    function=match.address_primary,
                    address=primary_address,
                    operand_index=operand_index,
                    name=entry.name))
    return ports


def restoring_rename(rename: Optional[Callable[[int, str], bool]] = None,
                     clear: Optional[Callable[[int], bool]] = None
                     ) -> Callable[[int, str], bool]:
    """The rename `apply_symbol_ports` should use to *undo* a port.

    Undoing differs from porting in one case, and it is the flagship one: a
    name ported over IDA's own `sub_13000E870`. Writing that string back
    would give the address a user-defined name that merely looks generated --
    IDA would keep it through a rebase or a re-analysis, and the function
    would no longer count as unnamed anywhere IDA itself decides. Clearing
    the name hands the address back to IDA, which regenerates the same
    `sub_` from the address.

    Both callables are injectable so the choice is testable without IDA;
    `apply_symbol_ports` keeps its two-argument `rename` contract.
    """
    do_rename = _ida_rename if rename is None else rename
    do_clear = _ida_clear_name if clear is None else clear

    def restore(address: int, name: str) -> bool:
        if _is_generated_name(name):
            return do_clear(address)
        return do_rename(address, name)

    return restore


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
            result.failed_addresses.append(port.address)
            continue
        result.record(port, written)
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
    from bindiff.ida import api

    idaapi = api()
    result = PortResult()
    for address in addresses:
        try:
            function = idaapi.get_func(address)
            if function is None:
                result.skipped += 1
                continue
            function.flags |= idaapi.FUNC_LIB
            if idaapi.update_func(function):
                result.applied += 1
            else:
                result.failed += 1
        except Exception:
            result.failed += 1
    return result


def _ida_rename(address: int, name: str) -> bool:
    if not database_is_open():
        raise RuntimeError("renaming requires a running IDA database")
    from bindiff.ida import api

    idaapi = api()

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
    return bool(idaapi.set_name(
        address, name,
        idaapi.SN_NOWARN | idaapi.SN_NOCHECK | idaapi.SN_FORCE))


def _ida_clear_name(address: int) -> bool:
    """Removes the user-defined name, leaving IDA to regenerate its own.

    SN_NOCHECK for the same reason _ida_rename uses it, and no SN_FORCE:
    there is no name to collide with. Guarded on an open database the same
    way, and a refusal is a False return here too.
    """
    if not database_is_open():
        raise RuntimeError("renaming requires a running IDA database")
    from bindiff.ida import api

    idaapi = api()
    return bool(idaapi.set_name(address, "", idaapi.SN_NOCHECK))


def _ida_set_comment(address: int, text: str,
                     kind: str = "instruction") -> bool:
    if not database_is_open():
        raise RuntimeError("commenting requires an open IDA database")
    from bindiff.ida import api

    idaapi = api()
    if kind == "function":
        function = idaapi.get_func(address)
        if function is not None:
            # Non-repeatable: a repeatable function comment is echoed at every
            # call site, which is rarely what someone wrote it for.
            return bool(idaapi.set_func_cmt(function, text, False))
        # No function here -- fall through rather than lose the comment.
    return bool(idaapi.set_cmt(address, text, False))
