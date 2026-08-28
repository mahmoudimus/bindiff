"""Reading the parts of a .BinExport that a .BinDiff does not carry.

A result file records matches only. Anything about the functions that were
*not* matched -- and any per-function total, as opposed to the matched counts
-- has to come from the .BinExport inputs. That is what blocks the unmatched
views and the count columns, so this reads just enough to unblock them:
the function list of each side.

Only the call graph vertices are touched. A .BinExport of a large binary is
tens of megabytes of instructions and expressions that nothing here needs; the
proto is parsed in full because that is what protobuf does, but nothing walks
the rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Optional


class FunctionType(IntEnum):
    """Mirrors BinExport2.CallGraph.Vertex.Type."""

    NORMAL = 0
    LIBRARY = 1
    IMPORTED = 2
    THUNK = 3
    INVALID = 4


@dataclass(frozen=True)
class ExportedFunction:
    address: int
    name: str
    demangled_name: str
    type: FunctionType

    @property
    def is_library(self) -> bool:
        """Library, imported and thunk code is not the analyst's own.

        BinDiff counts these separately (file.libfunctions), and an unmatched
        view that buries real unmatched functions under a few thousand library
        thunks is not usable.
        """
        return self.type in (FunctionType.LIBRARY, FunctionType.IMPORTED,
                             FunctionType.THUNK)

    @property
    def has_real_name(self) -> bool:
        """True when the name came from symbols rather than being generated."""
        return bool(self.name) and not self.name.startswith(
            ("sub_", "loc_", "nullsub_", "j_sub_", "unknown_libname_"))

    @property
    def best_name(self) -> str:
        return self.demangled_name or self.name


def _load_pb2():
    """Imports the generated bindings, with an actionable error if absent.

    They are generated at build time rather than checked in, so that they
    always match the schema in the tree.
    """
    try:
        from bindiff._pb import binexport2_pb2
    except ImportError as exc:
        raise ImportError(
            "binexport2_pb2 is missing. Generate the protobuf bindings with:\n"
            "  ./tools/scripts/run_tests_docker.sh build\n"
            "or run protoc over binexport2.proto into python/bindiff/_pb/"
        ) from exc
    return binexport2_pb2


def read_functions(binexport_path: str) -> List[ExportedFunction]:
    """Returns every function in a .BinExport, matched or not."""
    binexport2_pb2 = _load_pb2()

    proto = binexport2_pb2.BinExport2()
    with open(binexport_path, "rb") as handle:
        data = handle.read()
    if not data:
        raise ValueError(f"{binexport_path} is empty")
    try:
        proto.ParseFromString(data)
    except Exception as exc:
        raise ValueError(f"{binexport_path} is not a .BinExport: {exc}") from exc

    if not proto.call_graph.vertex:
        raise ValueError(
            f"{binexport_path} has no call graph; it may be truncated")

    functions = []
    for vertex in proto.call_graph.vertex:
        functions.append(ExportedFunction(
            address=vertex.address,
            name=vertex.mangled_name,
            demangled_name=vertex.demangled_name,
            type=FunctionType(vertex.type),
        ))
    return functions


def read_metadata(binexport_path: str) -> Dict[str, str]:
    """Executable name and hash, for checking a .BinExport against a database."""
    binexport2_pb2 = _load_pb2()

    proto = binexport2_pb2.BinExport2()
    with open(binexport_path, "rb") as handle:
        proto.ParseFromString(handle.read())
    return {
        "executable_name": proto.meta_information.executable_name,
        "executable_id": proto.meta_information.executable_id,
        "architecture_name": proto.meta_information.architecture_name,
    }


def find_binexports_for(database_path: str) -> tuple:
    """Guesses the two .BinExport files a .BinDiff came from.

    The engine names results "<primary>_vs_<secondary>.BinDiff" and writes them
    beside the exports, so the names can usually be recovered. Returns
    (primary, secondary), either of which may be None -- the caller is expected
    to ask rather than guess wrongly.
    """
    import re
    from pathlib import Path

    path = Path(database_path)
    match = re.match(r"(.+)_vs_(.+)\.BinDiff$", path.name, re.IGNORECASE)
    if not match:
        return (None, None)

    primary = path.parent / f"{match.group(1)}.BinExport"
    secondary = path.parent / f"{match.group(2)}.BinExport"
    return (str(primary) if primary.is_file() else None,
            str(secondary) if secondary.is_file() else None)

@dataclass(frozen=True)
class FunctionDetail:
    """Per-function totals, as opposed to the matched counts in a .BinDiff.

    The result file records how much of a pair the differ managed to pair up;
    these are the totals for one side, which is the other half of every
    "matched N of M" column.
    """

    address: int
    basic_blocks: int
    instructions: int
    edges: int


def read_function_details(binexport_path: str) -> Dict[int, FunctionDetail]:
    """Per-function basic block, instruction and edge totals, by address.

    Costlier than read_functions: instruction addresses in a .BinExport are
    delta-encoded -- an instruction only stores its address when it does not
    simply follow the previous one -- so resolving which flow graph starts
    where means walking the whole instruction table once. That is linear, but
    on a large binary it is a real pass over hundreds of thousands of entries,
    so callers should do it once and keep the result rather than per function.
    """
    binexport2_pb2 = _load_pb2()

    proto = binexport2_pb2.BinExport2()
    with open(binexport_path, "rb") as handle:
        proto.ParseFromString(handle.read())

    # Resolve every instruction address in one pass.
    addresses: List[int] = []
    current = 0
    for instruction in proto.instruction:
        if instruction.HasField("address"):
            current = instruction.address
        addresses.append(current)
        current += len(instruction.raw_bytes)

    def block_instruction_indices(block) -> range:
        """A block's instruction indices, as index ranges.

        end_index is omitted when the range holds a single element, which is
        the space optimisation the schema documents.
        """
        for index_range in block.instruction_index:
            begin = index_range.begin_index
            end = (index_range.end_index if index_range.HasField("end_index")
                   else begin + 1)
            yield from range(begin, end)

    details: Dict[int, FunctionDetail] = {}
    for flow_graph in proto.flow_graph:
        block_indices = list(flow_graph.basic_block_index)
        if not block_indices:
            continue

        entry_block = proto.basic_block[flow_graph.entry_basic_block_index]
        entry_instructions = list(block_instruction_indices(entry_block))
        if not entry_instructions:
            continue
        entry_address = addresses[entry_instructions[0]]

        instruction_count = 0
        for block_index in block_indices:
            instruction_count += sum(
                1 for _ in block_instruction_indices(proto.basic_block[block_index]))

        details[entry_address] = FunctionDetail(
            address=entry_address,
            basic_blocks=len(block_indices),
            instructions=instruction_count,
            edges=len(flow_graph.edge),
        )
    return details

