"""
BinDiff Results Management

High-level interface for working with BinDiff results databases.
"""

from typing import List, Optional
from .core import load_matches, load_statistics, MatchInfo, StatisticsInfo


class Results:
    """
    High-level interface for BinDiff results.

    This class provides a convenient way to load and analyze BinDiff results
    from a database file.

    Example:
        >>> results = Results.load('diff.db')
        >>> print(f"Total matches: {results.num_matches}")
        >>> for match in results.matches[:10]:
        ...     print(f"{match.primary_name} -> {match.secondary_name}")
    """

    def __init__(self, database_path: str):
        """
        Initialize Results from a database path.

        Args:
            database_path: Path to BinDiff database file
        """
        self.database_path = database_path
        self._matches: Optional[List[MatchInfo]] = None
        self._statistics: Optional[StatisticsInfo] = None

    @classmethod
    def load(cls, database_path: str) -> 'Results':
        """
        Load results from a database file.

        Args:
            database_path: Path to BinDiff database file

        Returns:
            Results object

        Example:
            >>> results = Results.load('diff.db')
        """
        return cls(database_path)

    @property
    def matches(self) -> List[MatchInfo]:
        """
        Get all function matches.

        Returns:
            List of MatchInfo objects sorted by similarity (descending)
        """
        if self._matches is None:
            self._matches = load_matches(self.database_path)
        return self._matches

    @property
    def statistics(self) -> StatisticsInfo:
        """
        Get diff statistics.

        Returns:
            StatisticsInfo object
        """
        if self._statistics is None:
            self._statistics = load_statistics(self.database_path)
        return self._statistics

    @property
    def num_matches(self) -> int:
        """Number of matched functions."""
        return len(self.matches)

    @property
    def num_unmatched_primary(self) -> int:
        """Number of unmatched functions in primary binary."""
        return self.statistics.primary_unmatched_function_count

    @property
    def num_unmatched_secondary(self) -> int:
        """Number of unmatched functions in secondary binary."""
        return self.statistics.secondary_unmatched_function_count

    def get_match(self, index: int) -> MatchInfo:
        """
        Get match by index.

        Args:
            index: Match index (0-based)

        Returns:
            MatchInfo object
        """
        return self.matches[index]

    def get_matches_by_similarity(self, min_similarity: float = 0.0,
                                  max_similarity: float = 1.0) -> List[MatchInfo]:
        """
        Filter matches by similarity range.

        Args:
            min_similarity: Minimum similarity (0.0 to 1.0)
            max_similarity: Maximum similarity (0.0 to 1.0)

        Returns:
            List of MatchInfo objects within the similarity range
        """
        return [m for m in self.matches
                if min_similarity <= m.similarity <= max_similarity]

    def get_matches_by_confidence(self, min_confidence: float = 0.0) -> List[MatchInfo]:
        """
        Filter matches by minimum confidence.

        Args:
            min_confidence: Minimum confidence (0.0 to 1.0)

        Returns:
            List of MatchInfo objects with confidence >= min_confidence
        """
        return [m for m in self.matches if m.confidence >= min_confidence]

    def get_manual_matches(self) -> List[MatchInfo]:
        """
        Get manually confirmed matches.

        Returns:
            List of manually confirmed MatchInfo objects
        """
        return [m for m in self.matches if m.is_manual]

    def get_automatic_matches(self) -> List[MatchInfo]:
        """
        Get automatically detected matches.

        Returns:
            List of automatically detected MatchInfo objects
        """
        return [m for m in self.matches if not m.is_manual]

    def print_summary(self):
        """Print a summary of the diff results."""
        stats = self.statistics

        print("BinDiff Results Summary")
        print("=" * 60)
        print(f"Database: {self.database_path}")
        print()

        print("Functions:")
        print(f"  Primary:   {stats.primary_function_count:6}")
        print(f"  Secondary: {stats.secondary_function_count:6}")
        print(f"  Matched:   {stats.matched_function_count:6} ({stats.function_similarity:5.1%})")
        print()

        print("Basic Blocks:")
        print(f"  Primary:   {stats.primary_basic_block_count:6}")
        print(f"  Secondary: {stats.secondary_basic_block_count:6}")
        print(f"  Matched:   {stats.matched_basic_block_count:6} ({stats.basic_block_similarity:5.1%})")
        print()

        print("Instructions:")
        print(f"  Primary:   {stats.primary_instruction_count:6}")
        print(f"  Secondary: {stats.secondary_instruction_count:6}")
        print(f"  Matched:   {stats.matched_instruction_count:6} ({stats.instruction_similarity:5.1%})")
        print()

        manual = len(self.get_manual_matches())
        automatic = len(self.get_automatic_matches())
        print(f"Matches: {self.num_matches} total ({automatic} automatic, {manual} manual)")

    def __repr__(self):
        return f"Results(database='{self.database_path}', matches={self.num_matches})"


# Re-export for convenience
__all__ = ['Results', 'MatchInfo', 'StatisticsInfo']
