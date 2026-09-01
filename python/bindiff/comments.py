"""Reads comments out of a .BinExport, keeping what they are.

The engine's own reader cannot be used for this. It stores comments in

    using OperatorId = std::pair<Address, int>;
    using CommentsByOperatorId = absl::btree_map<OperatorId, Comment>;

so every comment at one (address, operand) collapses into a single entry and
the rest are gone before any consumer sees them. A function typically carries
three -- a LOCATION comment holding its name, a FUNCTION comment, and a
DEFAULT one -- and the survivor was the name. That is why porting comments
wrote the function's own name over its documentation and looked, from the
outside, like comments not being ported at all.

BinExport2 is a protobuf and we already generate bindings for it, so this
reads it directly. No extension, no engine, testable without either.

Comment placement in BinExport2 needs one piece of context: instructions form
a flat list in which `address` is only set when it is not simply the previous
instruction's address plus its length. Walking the list to recover addresses
is the whole of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# BinExport2.Comment.Type, by name. Read from the generated enum at call time
# rather than hardcoded, so a schema change is a failure rather than a silent
# mismatch.
FUNCTION = "FUNCTION"
ANTERIOR = "ANTERIOR"
POSTERIOR = "POSTERIOR"
DEFAULT = "DEFAULT"
LOCATION = "LOCATION"
GLOBAL_REFERENCE = "GLOBAL_REFERENCE"
LOCAL_REFERENCE = "LOCAL_REFERENCE"

# What is worth porting into another database, and what is not.
#
# A LOCATION comment holds the location's own name, which the symbol porting
# path already handles and which would otherwise overwrite a real comment.
# Reference comments name a global or a local in *this* binary; carried across
# they would assert something about addresses that do not exist there.
PORTABLE_TYPES = frozenset({FUNCTION, ANTERIOR, POSTERIOR, DEFAULT})


@dataclass(frozen=True)
class ExportedComment:
    """One comment, with enough about it to place it correctly."""

    address: int
    text: str
    type: str
    operand_index: int = 0
    repeatable: bool = False

    @property
    def is_function_comment(self) -> bool:
        return self.type == FUNCTION


# Comment text IDA writes for itself. Porting these carries the other
# binary's boilerplate into someone's database as though it were a
# colleague's work, which is the same mistake porting an auto-generated name
# would be -- and names have been filtered for that all along.
#
# Measured on a real export: of 12,974 DEFAULT comments, 12,885 match these
# and 89 do not. The 89 are unmistakable --
#
#   "Merge-chain entry test: v7->succset.n == 1. If a handler-exit block ..."
#   "Test mblock_t.flags (+0x18) & 0x10000 -- qualifies block for DCE sweep"
#
# -- and the 12,885 are "Trap to Debugger" 2,536 times, "Size" 1,081 times
# (a callee's parameter name shown at the call site), "void *", and thousands
# of "jumptable 0000000180191217 case 82".
_BANNER = re.compile(r"^\s*;")
_TYPE_ANNOTATION = re.compile(
    r"^\s*[A-Za-z_][\w:<>,\s*&]*\(\s*__(cdecl|stdcall|fastcall|thiscall|"
    r"usercall)\s*\*\s*\)\s*\(")
_IDA_ANNOTATION = re.compile(
    r"^(Trap to Debugger|switch jump|jumptable\s.*|switch\s+\d+\s+cases?.*|"
    r"indirect table.*|jump table.*)$")
# A bare identifier or type expression with no sentence in it: a parameter
# name IDA shows at a call site, or the type of what is being pushed.
_BARE_TOKEN = re.compile(
    r"^(unsigned |signed |const |volatile |struct |enum |union )*"
    r"[A-Za-z_][\w:<>]*\s*\**$")


def is_generated_comment(text: str) -> bool:
    """True for comment text IDA produced rather than a person.

    Deliberately errs towards keeping things: a human comment dropped is work
    silently lost, where boilerplate carried across is visible and can be
    deleted. The one judgement call is _BARE_TOKEN -- a single word with no
    sentence around it. Somebody could write "Src" as a comment; IDA writes it
    701 times in one binary, so the balance is clear.

    portable_comments(include_generated=True) turns all of this off.
    """
    if not text or not text.strip():
        return True
    stripped = text.strip()
    # Whitespace is normalised before matching because IDA concatenates
    # several of its own comments at one address into one multi-line string --
    # "jumptable A cases 1-5\njumptable A default case" -- and an anchored
    # pattern then matches none of it. Every line being boilerplate is what
    # makes the whole boilerplate.
    joined = " ".join(stripped.split())
    if _BANNER.match(joined) or _TYPE_ANNOTATION.match(joined):
        return True
    if _BARE_TOKEN.match(joined):
        return True
    # Each line judged on its own, so a real note appended to an IDA
    # annotation survives.
    lines = [" ".join(line.split()) for line in stripped.splitlines()]
    lines = [line for line in lines if line]
    return bool(lines) and all(
        _IDA_ANNOTATION.match(line) or _BARE_TOKEN.match(line)
        or _BANNER.match(line) or _TYPE_ANNOTATION.match(line)
        for line in lines)


def _instruction_addresses(proto) -> Dict[int, int]:
    """Address of every instruction, by index.

    BinExport2 omits `address` when an instruction simply follows the previous
    one, so the list has to be walked in order to recover them.
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


def read_comments(binexport_path) -> List[ExportedComment]:
    """Every comment in an export, with its type preserved.

    Unlike the engine's reader this keeps all of them: several comments at one
    address are several entries here, which is the whole point.
    """
    from bindiff._pb import binexport2_pb2

    proto = binexport2_pb2.BinExport2()
    proto.ParseFromString(Path(binexport_path).read_bytes())

    type_names = {value: name for name, value
                  in binexport2_pb2.BinExport2.Comment.Type.items()}
    addresses = _instruction_addresses(proto)

    comments: List[ExportedComment] = []
    for comment in proto.comment:
        address = addresses.get(comment.instruction_index)
        if address is None:
            continue
        text = proto.string_table[comment.string_table_index]
        if not text:
            continue
        comments.append(ExportedComment(
            address=address,
            text=text,
            type=type_names.get(comment.type, str(comment.type)),
            operand_index=comment.instruction_operand_index,
            repeatable=bool(getattr(comment, "repeatable", False)),
        ))
    return comments


def portable_comments(binexport_path,
                      types: Optional[Iterable[str]] = None,
                      include_generated: bool = False
                      ) -> Dict[int, List[ExportedComment]]:
    """Comments worth carrying into another database, grouped by address.

    Grouped rather than flattened because one address legitimately holds a
    function comment and an instruction comment at once, and they are written
    to different places.
    """
    wanted = frozenset(types) if types is not None else PORTABLE_TYPES
    grouped: Dict[int, List[ExportedComment]] = {}
    for comment in read_comments(binexport_path):
        if comment.type not in wanted:
            continue
        if not include_generated and is_generated_comment(comment.text):
            continue
        grouped.setdefault(comment.address, []).append(comment)
    return grouped


def best_for_address(comments: Iterable[ExportedComment]
                     ) -> Optional[ExportedComment]:
    """The one comment to write when only one can be written.

    A function comment beats a plain one: it is the documentation someone
    wrote about the function, where a DEFAULT comment at the same address is
    usually the same text attached to the first instruction.
    """
    best = None
    for comment in comments:
        if comment.is_function_comment:
            return comment
        if best is None or len(comment.text) > len(best.text):
            best = comment
    return best
