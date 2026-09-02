"""Renames stack variables in an open database.

The reading half is bindiff.stack_names, which pulls names out of a
.BinExport. This is the half that needs IDA, and it needs it for two things,
not one.

**The offset cannot be carried across.** A .BinExport records the raw
displacement in the instruction, and the two sides of a diff do not agree
about it: on the measured pair 987 of 2910 matched operands had different
displacements, a third of them. So the name travels with the *instruction*,
through the match, and the primary's own frame offset is resolved here by
asking IDA what the operand refers to -- calc_stkvar_struc_offset, which is
the only thing that knows.

**The frame is a type.** Since IDA 9.0 a function's frame is a tinfo_t UDT
whose members sit at struct offsets, renamed with tinfo_t.rename_udm. It
returns a tinfo_code_t, and unlike set_name it really does refuse: a name
already taken in the same frame comes back as TERR_* rather than being
silently applied.

What this does not reach is the decompiler. Hex-Rays names its own local
variables, in its own store, and a frame member renamed here does not appear
in the pseudocode -- the same split as comments, and for the same reason.

**Do not follow 9.4's deprecation warnings here.** It asks for
get_func_frame_ea and calc_stkvar_struc_offset_ea; neither exists on 9.1,
which is the compatibility leg. Verified with tools/scripts/ida_frame_probe.py
on both: the un-suffixed spellings are present on 9.1 and 9.4, the _ea ones
only on 9.4, and everything else this uses -- find_udm, rename_udm,
STRMEM_OFFSET, TERR_OK -- behaves identically, refusal code included.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from bindiff.ida import Unavailable  # noqa: F401  (re-exported for callers)


@dataclass(frozen=True)
class StackNamePort:
    """A rename to apply, addressed the way the match addresses it.

    No offset: the primary's own frame offset is not knowable from the export
    and is resolved against the database at apply time.
    """

    function: int
    address: int
    operand_index: int
    name: str


@dataclass
class StackNameResult:
    applied: int = 0
    # A member that already carried this name. Not a failure and not work.
    unchanged: int = 0
    # The operand did not resolve to a frame variable in this database.
    unresolved: int = 0
    # rename_udm refused -- almost always a name already taken in the frame,
    # which is real information rather than a mishap.
    refused: int = 0
    # Renames that replaced a name a person had already given this slot.
    replaced: int = 0
    refusals: List[Tuple[int, str]] = field(default_factory=list)


def apply_stack_names(ports: Sequence[StackNamePort]) -> StackNameResult:
    """Renames the frame members the ports point at.

    Grouped by function because the frame is fetched per function and the
    same slot is usually referenced by several instructions -- the first port
    to resolve to a given offset wins and the rest read as unchanged.
    """
    from bindiff import ida
    from bindiff.ida_env import database_is_open
    from bindiff.stack_names import is_generated_name

    if not ports:
        return StackNameResult()
    if not database_is_open():
        raise RuntimeError("renaming a stack variable requires an open "
                           "IDA database")

    # One facade, so a spelling that moved between versions is fixed in
    # bindiff.ida rather than here. Checked up front: finding out halfway
    # through that the frame API has moved leaves half a database renamed.
    api = ida.api()
    for name in ("calc_stkvar_struc_offset", "get_func_frame",
                 "STRMEM_OFFSET", "udm_t", "insn_t", "decode_insn"):
        ida.first_available(name)

    result = StackNameResult()
    by_function: Dict[int, List[StackNamePort]] = {}
    for port in ports:
        by_function.setdefault(port.function, []).append(port)

    for entry, group in by_function.items():
        function = api.get_func(entry)
        if function is None:
            result.unresolved += len(group)
            continue
        frame = ida.frame_of(function)
        if frame is None:
            result.unresolved += len(group)
            continue

        done: Set[int] = set()
        for port in group:
            offset = _stack_offset(api, ida, function, port)
            if offset is None:
                result.unresolved += 1
                continue
            if offset in done:
                result.unchanged += 1
                continue

            member = api.udm_t()
            member.offset = offset * 8
            index = frame.find_udm(member, api.STRMEM_OFFSET)
            if index < 0:
                result.unresolved += 1
                continue
            if member.name == port.name:
                result.unchanged += 1
                done.add(offset)
                continue

            code = frame.rename_udm(index, port.name)
            if code != 0:
                result.refused += 1
                if len(result.refusals) < 20:
                    result.refusals.append((port.address, port.name))
                continue
            result.applied += 1
            done.add(offset)
            if not is_generated_name(member.name):
                result.replaced += 1
    return result


def _stack_offset(api, ida, function, port: StackNamePort) -> Optional[int]:
    """The frame offset the operand refers to, or None if it refers to none.

    Decoded here rather than trusted from the export: the export says what
    the *other* binary's operand meant. The offset itself, and the rules for
    refusing one, live in bindiff.ida -- both builds return values outside
    the frame and the guard belongs with the call.
    """
    instruction = api.insn_t()
    if api.decode_insn(instruction, port.address) <= 0:
        return None
    if port.operand_index >= len(instruction.ops):
        return None
    return ida.stack_offset(function, instruction, port.operand_index)
