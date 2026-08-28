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
