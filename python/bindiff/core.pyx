# distutils: language = c++
# cython: language_level = 3

"""
Cython implementation for BinDiff core types.
"""

import json
from libcpp.string cimport string
from libc.stdint cimport uint64_t
from libcpp.pair cimport pair
from libcpp.vector cimport vector
from typing import List, Tuple, Optional

cimport bindiff.core as core_types


def get_config() -> dict:
    """Returns the configuration currently in effect, as a dict.

    This is the real engine configuration -- the same structure as
    bindiff.json. The keys that decide what the differ actually does are
    "function_matching" and "basic_block_matching": ordered lists of
    {"name": ..., "confidence": ...}. A step whose name is absent from the list
    is not run.
    """
    return json.loads(core_types.GetConfigJson().decode('utf-8'))


def get_default_config() -> dict:
    """Returns the compiled-in default configuration as a dict."""
    return json.loads(core_types.GetDefaultConfigJson().decode('utf-8'))


def set_config(config: dict) -> None:
    """Installs `config`, merged over the defaults.

    A partial dict is a patch: anything unset keeps its default. The two
    matching step lists are the exception -- if you supply one, it is used
    verbatim, in the order given. That is what lets you disable a step: leave it
    out. Omit the key entirely to keep the default list.

    Enabling, disabling and reordering steps take effect on the next diff.
    Changing a step's *confidence* does not: those values are read when the
    algorithm objects are first constructed, so a confidence change needs a
    fresh process.

    Not thread-safe against a running diff -- the configuration is a global the
    differ reads while it works. Call this between diffs.
    """
    if not isinstance(config, dict):
        raise TypeError(f"config must be a dict, got {type(config).__name__}")
    cdef string encoded = json.dumps(config).encode('utf-8')
    core_types.SetConfigJson(encoded)


def reset_config() -> None:
    """Restores the compiled-in defaults."""
    set_config(get_default_config())


class FunctionInfo:
    """Information about a function."""

    def __init__(self, address: int, name: str, demangled_name: str,
                 basic_block_count: int, edge_count: int,
                 instruction_count: int, md_index: float):
        self.address = address
        self.name = name
        self.demangled_name = demangled_name
        self.basic_block_count = basic_block_count
        self.edge_count = edge_count
        self.instruction_count = instruction_count
        self.md_index = md_index

    def __repr__(self):
        return (f"FunctionInfo(address=0x{self.address:x}, name='{self.name}', "
                f"blocks={self.basic_block_count}, instructions={self.instruction_count})")


class BasicBlockInfo:
    """Information about a basic block."""

    def __init__(self, address: int, instruction_count: int, md_index: float):
        self.address = address
        self.instruction_count = instruction_count
        self.md_index = md_index

    def __repr__(self):
        return (f"BasicBlockInfo(address=0x{self.address:x}, "
                f"instructions={self.instruction_count})")


class MatchInfo:
    """Information about a function match."""

    def __init__(self, primary_address: int, secondary_address: int,
                 primary_name: str, secondary_name: str,
                 similarity: float, confidence: float,
                 algorithm_id: int, algorithm_name: str,
                 is_manual: bool, flags: int):
        self.primary_address = primary_address
        self.secondary_address = secondary_address
        self.primary_name = primary_name
        self.secondary_name = secondary_name
        self.similarity = similarity
        self.confidence = confidence
        self.algorithm_id = algorithm_id
        self.algorithm_name = algorithm_name
        self.is_manual = is_manual
        self.flags = flags

    def __repr__(self):
        return (f"MatchInfo(0x{self.primary_address:x} '{self.primary_name}' -> "
                f"0x{self.secondary_address:x} '{self.secondary_name}', "
                f"similarity={self.similarity:.3f})")


class StatisticsInfo:
    """Statistics about a diff."""

    def __init__(self, primary_function_count: int, secondary_function_count: int,
                 matched_function_count: int,
                 primary_basic_block_count: int, secondary_basic_block_count: int,
                 matched_basic_block_count: int,
                 primary_instruction_count: int, secondary_instruction_count: int,
                 matched_instruction_count: int,
                 primary_edge_count: int, secondary_edge_count: int,
                 matched_edge_count: int):
        self.primary_function_count = primary_function_count
        self.secondary_function_count = secondary_function_count
        self.matched_function_count = matched_function_count
        self.primary_basic_block_count = primary_basic_block_count
        self.secondary_basic_block_count = secondary_basic_block_count
        self.matched_basic_block_count = matched_basic_block_count
        self.primary_instruction_count = primary_instruction_count
        self.secondary_instruction_count = secondary_instruction_count
        self.matched_instruction_count = matched_instruction_count
        self.primary_edge_count = primary_edge_count
        self.secondary_edge_count = secondary_edge_count
        self.matched_edge_count = matched_edge_count

    @property
    def primary_unmatched_function_count(self) -> int:
        """Number of unmatched functions in primary binary."""
        return self.primary_function_count - self.matched_function_count

    @property
    def secondary_unmatched_function_count(self) -> int:
        """Number of unmatched functions in secondary binary."""
        return self.secondary_function_count - self.matched_function_count

    @property
    def function_similarity(self) -> float:
        """Function similarity ratio (0.0 to 1.0)."""
        total = self.primary_function_count + self.secondary_function_count
        if total == 0:
            return 0.0
        return (2.0 * self.matched_function_count) / total

    @property
    def basic_block_similarity(self) -> float:
        """Basic block similarity ratio (0.0 to 1.0)."""
        total = self.primary_basic_block_count + self.secondary_basic_block_count
        if total == 0:
            return 0.0
        return (2.0 * self.matched_basic_block_count) / total

    @property
    def instruction_similarity(self) -> float:
        """Instruction similarity ratio (0.0 to 1.0)."""
        total = self.primary_instruction_count + self.secondary_instruction_count
        if total == 0:
            return 0.0
        return (2.0 * self.matched_instruction_count) / total

    def __repr__(self):
        return (f"StatisticsInfo(functions={self.matched_function_count}/"
                f"{self.primary_function_count}/{self.secondary_function_count}, "
                f"similarity={self.function_similarity:.2%})")


def diff(primary_path: str, secondary_path: str, output_path: str) -> int:
    """
    Diff two binary files and save results to a database.

    Args:
        primary_path: Path to primary BinExport file
        secondary_path: Path to secondary BinExport file
        output_path: Path to output database file

    Returns:
        0 on success, negative error code on failure
        -1: Failed to read primary binary
        -2: Failed to read secondary binary
        -3: Failed to create output database
        -4: Failed to write results
        -99: Unexpected error

    Example:
        >>> import bindiff
        >>> result = bindiff.diff('binary1.BinExport', 'binary2.BinExport', 'diff.db')
        >>> if result == 0:
        ...     print("Diff completed successfully")
    """
    cdef string c_primary = primary_path.encode('utf-8')
    cdef string c_secondary = secondary_path.encode('utf-8')
    cdef string c_output = output_path.encode('utf-8')
    cdef int result

    # Release the GIL for the duration: this is the long pole, and holding it
    # would block every other Python thread in the process (in IDA, the UI).
    with nogil:
        result = core_types.DiffBinaries(c_primary, c_secondary, c_output)
    return result


def incremental_diff(primary_path: str, secondary_path: str,
                     existing_path: str,
                     output_path: str = None) -> int:
    """Re-runs matching over whatever an earlier diff left unmatched.

    The matches already in `existing_path` are re-created as fixed points
    first, and every matching step skips a function that already has one, so
    they survive untouched -- manual matches included. Only the remainder is
    considered.

    A match naming a function that is not present in these two .BinExport
    inputs is skipped rather than seeded, so pointing this at a result file
    from different binaries degrades to a plain diff instead of producing
    nonsense.

    `output_path` defaults to `existing_path`, i.e. updating in place.

    Returns the number of newly found matches, or a negative code on failure:
    -1/-2 reading the inputs, -3/-4 writing the database, -99 unexpected.
    """
    if output_path is None:
        output_path = existing_path

    cdef string c_primary = primary_path.encode('utf-8')
    cdef string c_secondary = secondary_path.encode('utf-8')
    cdef string c_existing = existing_path.encode('utf-8')
    cdef string c_output = output_path.encode('utf-8')
    cdef int result

    with nogil:
        result = core_types.IncrementalDiff(c_primary, c_secondary,
                                            c_existing, c_output)
    return result


def load_comments(binexport_path: str) -> dict:
    """Returns {address: comment} from a .BinExport.

    Comments live in the .BinExport, not in the .BinDiff -- the result file
    stores matches only. Porting comments into the primary database therefore
    needs the *secondary* .BinExport, which is what this reads.
    """
    cdef string c_path = binexport_path.encode('utf-8')
    cdef vector[pair[uint64_t, string]] c_comments
    with nogil:
        c_comments = core_types.LoadComments(c_path)

    comments = {}
    for entry in c_comments:
        comments[int(entry.first)] = entry.second.decode('utf-8', 'replace')
    return comments


def load_matches(database_path: str) -> List[MatchInfo]:
    """
    Load function matches from a diff database.

    Args:
        database_path: Path to BinDiff database

    Returns:
        List of MatchInfo objects

    Example:
        >>> matches = bindiff.load_matches('diff.db')
        >>> for match in matches[:10]:
        ...     print(f"{match.primary_name} -> {match.secondary_name}")
    """
    cdef string c_path = database_path.encode('utf-8')
    cdef vector[core_types.CMatchInfo] c_matches
    with nogil:
        c_matches = core_types.LoadMatches(c_path)

    matches = []
    for c_match in c_matches:
        match = MatchInfo(
            primary_address=c_match.primary_address,
            secondary_address=c_match.secondary_address,
            primary_name=c_match.primary_name.decode('utf-8'),
            secondary_name=c_match.secondary_name.decode('utf-8'),
            similarity=c_match.similarity,
            confidence=c_match.confidence,
            algorithm_id=c_match.algorithm_id,
            algorithm_name=c_match.algorithm_name.decode('utf-8'),
            is_manual=c_match.is_manual,
            flags=c_match.flags
        )
        matches.append(match)

    return matches


def load_statistics(database_path: str) -> StatisticsInfo:
    """
    Load statistics from a diff database.

    Args:
        database_path: Path to BinDiff database

    Returns:
        StatisticsInfo object

    Example:
        >>> stats = bindiff.load_statistics('diff.db')
        >>> print(f"Function similarity: {stats.function_similarity:.2%}")
    """
    cdef string c_path = database_path.encode('utf-8')
    cdef core_types.CStatisticsInfo c_stats
    with nogil:
        c_stats = core_types.LoadStatistics(c_path)

    return StatisticsInfo(
        primary_function_count=c_stats.primary_function_count,
        secondary_function_count=c_stats.secondary_function_count,
        matched_function_count=c_stats.matched_function_count,
        primary_basic_block_count=c_stats.primary_basic_block_count,
        secondary_basic_block_count=c_stats.secondary_basic_block_count,
        matched_basic_block_count=c_stats.matched_basic_block_count,
        primary_instruction_count=c_stats.primary_instruction_count,
        secondary_instruction_count=c_stats.secondary_instruction_count,
        matched_instruction_count=c_stats.matched_instruction_count,
        primary_edge_count=c_stats.primary_edge_count,
        secondary_edge_count=c_stats.secondary_edge_count,
        matched_edge_count=c_stats.matched_edge_count
    )


# Expose classes for call graph and flow graph access
# These would require more complex wrapping, so we keep them minimal for now
class CallGraph:
    """CallGraph wrapper (placeholder for future implementation)."""
    pass

class FlowGraph:
    """FlowGraph wrapper (placeholder for future implementation)."""
    pass

class FixedPoint:
    """FixedPoint wrapper (placeholder for future implementation)."""
    pass
