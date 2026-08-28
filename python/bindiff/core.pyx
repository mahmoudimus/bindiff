# distutils: language = c++
# cython: language_level = 3

"""
Cython implementation for BinDiff core types.
"""

from libcpp.string cimport string
from libcpp.vector cimport vector
from typing import List, Tuple, Optional

cimport bindiff.core as core_types


class Config:
    """Configuration for BinDiff operations."""

    def __init__(self):
        """Initialize with default configuration."""
        self.use_all_algorithms = True
        self.min_confidence = 0.0
        self.min_similarity = 0.0

    def to_dict(self):
        """Convert configuration to dictionary."""
        return {
            'use_all_algorithms': self.use_all_algorithms,
            'min_confidence': self.min_confidence,
            'min_similarity': self.min_similarity,
        }


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
