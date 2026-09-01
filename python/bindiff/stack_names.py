"""Reads stack-variable names out of a .BinExport.

BinExport2 has no locals table, which is why this looks impossible at first
and why upstream issue #13 ("Variable names are not being imported anymore")
has no obvious fix. The names are there, in a place worth knowing about: a
stack operand is recorded as an Expression of type IMMEDIATE_INT carrying both
the displacement and its name --

    type=IMMEDIATE_INT  symbol='arg_0'  immediate=8

-- so an operand yields the name *and* the frame offset, which is what a
rename on the other side needs. Nothing else in the schema carries either.

Reading `symbol` without checking the type does not work: every expression
kind uses that field, so registers, size prefixes and operators come back as
"names" -- rbp, ss:, b8. The type is the whole filter.

Names IDA generated carry nothing -- var_50 in one binary has no relationship
to var_50 in another -- so they are dropped rather than copied over names the
target already generated for itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

# IDA's own naming for stack slots and arguments, plus the other auto-generated
# prefixes that can appear in an operand. A name matching these was invented by
# the disassembler on the other side and means nothing here.
# IDA's own naming for stack slots, arguments and saved registers. A name
# matching these was invented by the disassembler on the other side and means
# nothing here -- var_50 in one binary has no relationship to var_50 in
# another.
#
# The trailing-offset forms are not an edge case: "var_30+8" and "var_128+4"
# are how IDA renders a reference into the middle of a slot, and they are
# common enough that missing them left a quarter of the "human-named"
# operands looking meaningful when none of them were. "var_s0" is a saved
# register slot.
_GENERATED = re.compile(
    r"^(var|arg|lvar|s|sp|dst|src)_[0-9A-Fa-f]+(?:[+-][0-9A-Fa-f]+)?$|"
    r"^var_s[0-9A-Fa-f]+(?:[+-][0-9A-Fa-f]+)?$|"
    r"^(sub|loc|off|unk|byte|word|dword|qword|xmmword|ymmword|flt|dbl|stru|"
    r"asc|algn)_[0-9A-Fa-f]+(?:[+-][0-9A-Fa-f]+)?$",
    re.IGNORECASE)


def _signed(value: int) -> int:
    """A 64-bit unsigned displacement read back as the offset it represents.

    Frame offsets below the frame pointer are negative and arrive as very
    large unsigned integers; -104 as 18446744073709551512 is not a number
    anyone can act on.
    """
    return value - (1 << 64) if value >= (1 << 63) else value


@dataclass(frozen=True)
class StackName:
    """A named stack operand on one instruction.

    `offset` is the frame displacement the disassembler recorded, which is what
    identifies the variable being named.
    """

    address: int
    operand_index: int
    name: str
    offset: int = 0


def is_generated_name(name: str) -> bool:
    """True for a name the disassembler invented rather than a person."""
    return bool(_GENERATED.match(name or ""))


def _instruction_addresses(proto) -> Dict[int, int]:
    """Address of every instruction, by index.

    BinExport2 omits `address` when an instruction follows the previous one.
    """
    addresses: Dict[int, int] = {}
    running = 0
    for index, instruction in enumerate(proto.instruction):
        if instruction.HasField("address"):
            running = instruction.address
        elif index:
            running += len(proto.instruction[index - 1].raw_bytes)
        addresses[index] = running
    return addresses


def read_stack_names(binexport_path, include_generated: bool = False
                     ) -> List[StackName]:
    """Every named stack operand in an export.

    With `include_generated` the var_50s come too, which is only useful for
    inspecting an export -- porting them would replace one meaningless name
    with another.
    """
    from bindiff._pb import binexport2_pb2

    proto = binexport2_pb2.BinExport2()
    proto.ParseFromString(Path(binexport_path).read_bytes())
    addresses = _instruction_addresses(proto)

    found: List[StackName] = []
    integer_type = binexport2_pb2.BinExport2.Expression.IMMEDIATE_INT
    for index, instruction in enumerate(proto.instruction):
        address = addresses.get(index)
        if address is None:
            continue
        for operand_index, operand_id in enumerate(instruction.operand_index):
            if operand_id >= len(proto.operand):
                continue
            for expression_id in proto.operand[operand_id].expression_index:
                if expression_id >= len(proto.expression):
                    continue
                expression = proto.expression[expression_id]
                # An immediate that carries a symbol is a named displacement:
                # a frame variable, an argument, or a named constant. Any
                # other expression type with a symbol is a register, a size
                # prefix or an operator, none of which is a variable.
                if expression.type != integer_type or not expression.symbol:
                    continue
                if not include_generated and is_generated_name(
                        expression.symbol):
                    continue
                found.append(StackName(
                    address=address,
                    operand_index=operand_index,
                    name=expression.symbol,
                    offset=_signed(expression.immediate)
                    if expression.HasField("immediate") else 0))
    return found


def stack_names_by_operand(binexport_path) -> Dict[int, Dict[int, StackName]]:
    """{address: {operand index: StackName}}, generated names excluded.

    Keyed the way an instruction match is keyed, so a caller can look up what
    the other side called an operand it is looking at, and at what offset.
    """
    grouped: Dict[int, Dict[int, StackName]] = {}
    for entry in read_stack_names(binexport_path):
        grouped.setdefault(entry.address, {})[entry.operand_index] = entry
    return grouped
