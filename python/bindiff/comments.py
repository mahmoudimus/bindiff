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
                      types: Optional[Iterable[str]] = None
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
