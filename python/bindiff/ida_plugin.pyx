# distutils: language = c++
# cython: language_level = 3

"""
Cython implementation for BinDiff IDA plugin types.

This module provides Python wrappers for the complete BinDiff Results API,
enabling full IDA plugin functionality in Python.
"""

from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.memory cimport unique_ptr
from typing import List, Tuple, Optional
from enum import IntEnum

cimport bindiff.ida_plugin as ida_types


class ChangeType(IntEnum):
    """Change classification types."""
    NONE = 0
    STRUCTURAL_CHANGE = 1
    INSTRUCTIONS_CHANGED = 2
    OPERANDS_CHANGED = 3
    BASIC_BLOCKS_ADDED = 4
    BASIC_BLOCKS_REMOVED = 5


class PortCommentsKind(IntEnum):
    """Comment porting modes."""
    NORMAL = 0
    AS_EXTERNAL_LIB = 1


class Match:
    """Represents a function match."""

    def __init__(self, desc: 'ida_types.MatchDescription'):
        self.similarity = desc.similarity
        self.confidence = desc.confidence
        self.change_type = ChangeType(desc.change_type)
        self.address_primary = desc.address_primary
        self.name_primary = desc.name_primary.decode('utf-8')
        self.address_secondary = desc.address_secondary
        self.name_secondary = desc.name_secondary.decode('utf-8')
        self.comments_ported = desc.comments_ported
        self.algorithm_name = desc.algorithm_name.decode('utf-8')
        self.basic_block_count = desc.basic_block_count
        self.basic_block_count_primary = desc.basic_block_count_primary
        self.basic_block_count_secondary = desc.basic_block_count_secondary
        self.edge_count = desc.edge_count
        self.edge_count_primary = desc.edge_count_primary
        self.edge_count_secondary = desc.edge_count_secondary
        self.instruction_count = desc.instruction_count
        self.instruction_count_primary = desc.instruction_count_primary
        self.instruction_count_secondary = desc.instruction_count_secondary
        self.manual = desc.manual

    def __repr__(self):
        return (f"Match(0x{self.address_primary:x} '{self.name_primary}' -> "
                f"0x{self.address_secondary:x} '{self.name_secondary}', "
                f"similarity={self.similarity:.3f}, manual={self.manual})")


class UnmatchedFunction:
    """Represents an unmatched function."""

    def __init__(self, desc: 'ida_types.UnmatchedDescription'):
        self.address = desc.address
        self.name = desc.name.decode('utf-8')
        self.basic_block_count = desc.basic_block_count
        self.instruction_count = desc.instruction_count
        self.edge_count = desc.edge_count

    def __repr__(self):
        return (f"UnmatchedFunction(0x{self.address:x} '{self.name}', "
                f"blocks={self.basic_block_count}, instructions={self.instruction_count})")


class Statistic:
    """Represents a diff statistic."""

    def __init__(self, desc: 'ida_types.StatisticDescription'):
        self.name = desc.name.decode('utf-8')
        self.is_count = desc.is_count
        if desc.is_count:
            self.value = desc.count
        else:
            self.value = desc.value

    def __repr__(self):
        if self.is_count:
            return f"Statistic('{self.name}': {self.value})"
        else:
            return f"Statistic('{self.name}': {self.value:.4f})"


cdef class BindiffResults:
    """
    Python wrapper for BinDiff Results.

    This class provides the complete API from ida/results.h, allowing full
    IDA plugin functionality to be implemented in Python.

    Example:
        >>> results = BindiffResults.create()
        >>> results.read_from_file('diff.BinDiff')
        >>> print(f"Matches: {results.num_matches}")
        >>> for i in range(results.num_matches):
        ...     match = results.get_match(i)
        ...     print(match)
    """

    cdef unique_ptr[ida_types.ResultsWrapper] _results

    def __cinit__(self):
        pass

    @staticmethod
    def create():
        """
        Create a new BindiffResults object.

        Returns:
            BindiffResults object, or None if creation fails
        """
        cdef BindiffResults obj = BindiffResults()
        obj._results = ida_types.ResultsWrapper.Create()
        if not obj._results:
            return None
        return obj

    # Matched functions

    @property
    def num_matches(self) -> int:
        """Number of matched functions."""
        return self._results.get().GetNumMatches()

    def get_match(self, index: int) -> Match:
        """
        Get match by index.

        Args:
            index: Match index (0-based)

        Returns:
            Match object
        """
        cdef ida_types.MatchDescription desc = self._results.get().GetMatchDescription(index)
        return Match(desc)

    def get_matches(self) -> List[Match]:
        """Get all matches."""
        return [self.get_match(i) for i in range(self.num_matches)]

    def get_primary_address(self, index: int) -> int:
        """Get primary address for match at index."""
        return self._results.get().GetPrimaryAddress(index)

    def get_secondary_address(self, index: int) -> int:
        """Get secondary address for match at index."""
        return self._results.get().GetSecondaryAddress(index)

    def get_match_primary_address(self, index: int) -> int:
        """Get match primary address at index."""
        return self._results.get().GetMatchPrimaryAddress(index)

    def get_match_secondary_address(self, index: int) -> int:
        """Get match secondary address at index."""
        return self._results.get().GetMatchSecondaryAddress(index)

    # Unmatched functions

    @property
    def num_unmatched_primary(self) -> int:
        """Number of unmatched functions in primary binary."""
        return self._results.get().GetNumUnmatchedPrimary()

    @property
    def num_unmatched_secondary(self) -> int:
        """Number of unmatched functions in secondary binary."""
        return self._results.get().GetNumUnmatchedSecondary()

    def get_unmatched_primary(self, index: int) -> UnmatchedFunction:
        """Get unmatched primary function by index."""
        cdef ida_types.UnmatchedDescription desc = (
            self._results.get().GetUnmatchedDescriptionPrimary(index))
        return UnmatchedFunction(desc)

    def get_unmatched_secondary(self, index: int) -> UnmatchedFunction:
        """Get unmatched secondary function by index."""
        cdef ida_types.UnmatchedDescription desc = (
            self._results.get().GetUnmatchedDescriptionSecondary(index))
        return UnmatchedFunction(desc)

    def get_all_unmatched_primary(self) -> List[UnmatchedFunction]:
        """Get all unmatched primary functions."""
        return [self.get_unmatched_primary(i) for i in range(self.num_unmatched_primary)]

    def get_all_unmatched_secondary(self) -> List[UnmatchedFunction]:
        """Get all unmatched secondary functions."""
        return [self.get_unmatched_secondary(i) for i in range(self.num_unmatched_secondary)]

    # Statistics

    @property
    def num_statistics(self) -> int:
        """Number of statistics."""
        return self._results.get().GetNumStatistics()

    def get_statistic(self, index: int) -> Statistic:
        """Get statistic by index."""
        cdef ida_types.StatisticDescription desc = (
            self._results.get().GetStatisticDescription(index))
        return Statistic(desc)

    def get_all_statistics(self) -> List[Statistic]:
        """Get all statistics."""
        return [self.get_statistic(i) for i in range(self.num_statistics)]

    # Match manipulation

    def delete_matches(self, indices: List[int]) -> int:
        """
        Delete matches by indices.

        Args:
            indices: List of match indices to delete

        Returns:
            0 on success, -1 on error
        """
        cdef vector[size_t] c_indices
        for i in indices:
            c_indices.push_back(i)
        return self._results.get().DeleteMatches(c_indices)

    def add_match(self, primary_address: int, secondary_address: int) -> int:
        """
        Add a manual match.

        Args:
            primary_address: Primary function address
            secondary_address: Secondary function address

        Returns:
            0 on success, -1 on error
        """
        return self._results.get().AddMatch(primary_address, secondary_address)

    def confirm_matches(self, indices: List[int]) -> int:
        """
        Confirm matches as manually verified.

        Args:
            indices: List of match indices to confirm

        Returns:
            0 on success, -1 on error
        """
        cdef vector[size_t] c_indices
        for i in indices:
            c_indices.push_back(i)
        return self._results.get().ConfirmMatches(c_indices)

    # Comment/symbol porting

    def port_comments(self, indices: List[int],
                     kind: PortCommentsKind = PortCommentsKind.NORMAL) -> int:
        """
        Port comments/symbols from matches.

        Args:
            indices: List of match indices
            kind: PortCommentsKind.NORMAL or PortCommentsKind.AS_EXTERNAL_LIB

        Returns:
            0 on success, -1 on error
        """
        cdef vector[size_t] c_indices
        for i in indices:
            c_indices.push_back(i)
        return self._results.get().PortComments(c_indices, int(kind))

    def port_comments_by_address(self, start_source: int, end_source: int,
                                 start_target: int, end_target: int,
                                 min_confidence: float = 0.0,
                                 min_similarity: float = 0.0) -> int:
        """
        Port comments/symbols by address range.

        Args:
            start_source: Start address in source binary
            end_source: End address in source binary
            start_target: Start address in target binary
            end_target: End address in target binary
            min_confidence: Minimum match confidence (0.0-1.0)
            min_similarity: Minimum match similarity (0.0-1.0)

        Returns:
            0 on success, -1 on error
        """
        return self._results.get().PortCommentsByAddress(
            start_source, end_source, start_target, end_target,
            min_confidence, min_similarity)

    # Diff operations

    def incremental_diff(self) -> int:
        """
        Re-run diff with current matches.

        Returns:
            0 on success, -1 on error
        """
        return self._results.get().IncrementalDiff()

    def mark_ported_comments_in_database(self):
        """Mark ported comments in the database."""
        self._results.get().MarkPortedCommentsInDatabase()

    # Visual diff preparation

    def prepare_visual_diff(self, index: int) -> Tuple[bool, str]:
        """
        Prepare flow graph visual diff for match.

        Args:
            index: Match index

        Returns:
            Tuple of (success, message)
        """
        cdef string message
        cdef bool result = self._results.get().PrepareVisualDiff(index, &message)
        return result, message.decode('utf-8')

    def prepare_visual_call_graph_diff(self, index: int) -> Tuple[bool, str]:
        """
        Prepare call graph visual diff for match.

        Args:
            index: Match index

        Returns:
            Tuple of (success, message)
        """
        cdef string message
        cdef bool result = self._results.get().PrepareVisualCallGraphDiff(index, &message)
        return result, message.decode('utf-8')

    # File I/O

    def read_from_file(self, filename: str) -> int:
        """
        Load results from BinDiff database file.

        Args:
            filename: Path to .BinDiff file

        Returns:
            0 on success, -1 on error
        """
        cdef string c_filename = filename.encode('utf-8')
        return self._results.get().ReadFromFile(c_filename)

    def write_to_file(self, filename: str) -> int:
        """
        Save results to BinDiff database file.

        Args:
            filename: Path to .BinDiff file

        Returns:
            0 on success, -1 on error
        """
        cdef string c_filename = filename.encode('utf-8')
        return self._results.get().WriteToFile(c_filename)

    # State management

    @property
    def is_incomplete(self) -> bool:
        """Whether results were loaded from disk (incomplete state)."""
        return self._results.get().is_incomplete()

    @property
    def is_modified(self) -> bool:
        """Whether results have been modified."""
        return self._results.get().is_modified()

    def set_modified(self):
        """Mark results as modified."""
        self._results.get().set_modified()

    @property
    def should_reset_selection(self) -> bool:
        """Whether choosers should reset their selection."""
        return self._results.get().should_reset_selection()

    @should_reset_selection.setter
    def should_reset_selection(self, value: bool):
        """Set whether choosers should reset selection."""
        self._results.get().set_should_reset_selection(value)
