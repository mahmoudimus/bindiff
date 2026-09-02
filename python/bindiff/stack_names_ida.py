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


class Unavailable(Exception):
    """This IDA does not expose an API this needs."""


# What calc_stkvar_struc_offset returns for an operand that is not a stack
# variable. BADADDR rather than -1 or None, so it has to be spelled out.
#
# It is not the only value to refuse. On the measured pair 74 operands came
# back BADADDR and another 97 came back a number outside any frame -- a
# negative displacement read as unsigned, most likely. Multiplying one of
# those by 8 for a bit offset overflows uint64 and the rename raises instead
# of skipping, so the real test is whether the offset lands inside this
# function's frame.
_NOT_A_STACK_VARIABLE = 0xFFFFFFFFFFFFFFFF


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
    from bindiff.ida_env import database_is_open
    from bindiff.stack_names import is_generated_name

    if not ports:
        return StackNameResult()
    if not database_is_open():
        raise RuntimeError("renaming a stack variable requires an open "
                           "IDA database")

    import ida_frame
    import ida_funcs
    import ida_typeinf
    import ida_ua

    for module, name in ((ida_frame, "calc_stkvar_struc_offset"),
                         (ida_frame, "get_func_frame"),
                         (ida_typeinf, "STRMEM_OFFSET")):
        if getattr(module, name, None) is None:
            raise Unavailable(
                f"{module.__name__} has no {name}; the frame API has moved "
                "and this needs updating")

    result = StackNameResult()
    by_function: Dict[int, List[StackNamePort]] = {}
    for port in ports:
        by_function.setdefault(port.function, []).append(port)

    for entry, group in by_function.items():
        function = ida_funcs.get_func(entry)
        if function is None:
            result.unresolved += len(group)
            continue
        frame = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame, function):
            result.unresolved += len(group)
            continue

        frame_size = frame.get_size()
        done: Set[int] = set()
        for port in group:
            offset = _stack_offset(ida_ua, ida_frame, function, port,
                                   frame_size)
            if offset is None:
                result.unresolved += 1
                continue
            if offset in done:
                result.unchanged += 1
                continue

            member = ida_typeinf.udm_t()
            member.offset = offset * 8
            index = frame.find_udm(member, ida_typeinf.STRMEM_OFFSET)
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


def _stack_offset(ida_ua, ida_frame, function, port: StackNamePort,
                  frame_size: int) -> Optional[int]:
    """The frame offset the operand refers to, or None if it refers to none.

    Decoded here rather than trusted from the export: the export says what
    the *other* binary's operand meant.
    """
    instruction = ida_ua.insn_t()
    if ida_ua.decode_insn(instruction, port.address) <= 0:
        return None
    if port.operand_index >= len(instruction.ops):
        return None
    try:
        offset = ida_frame.calc_stkvar_struc_offset(
            function, instruction, port.operand_index)
    except Exception:
        return None
    if offset == _NOT_A_STACK_VARIABLE:
        return None
    # An offset outside the frame is not a member of it, whatever it means.
    if not 0 <= offset < frame_size:
        return None
    return offset
