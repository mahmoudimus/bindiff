"""Building a metadata sidecar from a .BinExport alone.

This is the producer that needs no disassembler. Everything it emits is
recovered from the export itself, so a sidecar can be built for any
.BinExport that already exists -- including the checked-in fixtures, which is
what makes the feature testable against ground truth in CI.

The IDA-only extractors (prototypes, stack frames, anything from Hex-Rays)
live in metadata_ida.py and add features to the same file.
"""

from __future__ import annotations

from typing import Dict, List, Set

from bindiff.metadata import (
    BinaryMetadata,
    FunctionMetadata,
    imports_feature,
)

# Call graph vertex types that denote code the analyst did not write. Their
# names come from the import table rather than from symbols, which is why they
# survive stripping. Mirrors BinExport2.CallGraph.Vertex.Type.
_LIBRARY_TYPES = (1, 2, 3)  # LIBRARY, IMPORTED, THUNK

# Below this a function's import set is too small to identify it: two functions
# that each call only malloc() are not thereby the same function. Measured
# effect is small either way, but it keeps obvious noise out of the file.
MIN_IMPORTS = 2


def _load_pb2():
    try:
        from bindiff._pb import binexport2_pb2
    except ImportError as exc:
        raise ImportError(
            "binexport2_pb2 is missing. Generate the protobuf bindings with:\n"
            "  ./tools/scripts/run_tests_docker.sh build"
        ) from exc
    return binexport2_pb2


def _instruction_addresses(proto) -> List[int]:
    """Resolves every instruction address in one pass.

    Addresses are delta-encoded: an instruction stores its own address only
    when it does not simply follow the previous one.
    """
    addresses: List[int] = []
    current = 0
    for instruction in proto.instruction:
        if instruction.HasField("address"):
            current = instruction.address
        addresses.append(current)
        current += len(instruction.raw_bytes)
    return addresses


def _block_instruction_indices(block):
    """A basic block's instruction indices.

    Stored as `[begin, end)` ranges, with `end` omitted when the range holds a
    single element.
    """
    for index_range in block.instruction_index:
        begin = index_range.begin_index
        end = (index_range.end_index if index_range.HasField("end_index")
               else begin + 1)
        yield from range(begin, end)


def import_sets(proto) -> Dict[int, Set[str]]:
    """Maps each function's entry point to the imports it calls.

    Only direct calls are followed. Going transitive was considered and left
    out: it would make a function's set depend on code it does not contain, so
    an unrelated change deep in a callee would move the key.
    """
    addresses = _instruction_addresses(proto)
    named = {
        vertex.address: (vertex.demangled_name or vertex.mangled_name)
        for vertex in proto.call_graph.vertex
        if vertex.type in _LIBRARY_TYPES and vertex.mangled_name
    }

    result: Dict[int, Set[str]] = {}
    for flow_graph in proto.flow_graph:
        block_indices = list(flow_graph.basic_block_index)
        if not block_indices:
            continue
        entry_block = proto.basic_block[flow_graph.entry_basic_block_index]
        entry_instructions = list(_block_instruction_indices(entry_block))
        if not entry_instructions:
            continue

        imports: Set[str] = set()
        for block_index in block_indices:
            block = proto.basic_block[block_index]
            for instruction_index in _block_instruction_indices(block):
                for target in proto.instruction[instruction_index].call_target:
                    name = named.get(target)
                    if name:
                        imports.add(name)
        result[addresses[entry_instructions[0]]] = imports
    return result


def build_sidecar(binexport_path: str,
                  min_imports: int = MIN_IMPORTS) -> BinaryMetadata:
    """Builds the metadata a .BinExport can supply on its own.

    The digest is left empty here and filled in by write_sidecar, which is the
    only place that has both the file and its contents in hand.
    """
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

    metadata = BinaryMetadata(
        executable_id=proto.meta_information.executable_id)
    sets = import_sets(proto)
    for address, imports in sorted(sets.items()):
        if len(imports) < min_imports:
            continue
        metadata.functions.append(FunctionMetadata(
            address=address,
            features=[imports_feature(imports)],
            # Kept so a match can be explained. Truncated because a function
            # calling two hundred imports does not need all of them recorded
            # to make the point, and the file is read on every diff.
            attributes={"imports": ",".join(sorted(imports)[:32])},
        ))

    if not metadata.functions:
        metadata.warnings.append(
            f"no function in {binexport_path} calls at least {min_imports} "
            f"named imports; the import feature will contribute nothing")
    return metadata
