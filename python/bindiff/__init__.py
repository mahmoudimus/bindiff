"""
BinDiff Python Interface
=========================

A Cython-based Python interface for BinDiff binary diffing engine.

This package provides Python bindings to BinDiff's C++ core, enabling:
- Binary diffing and comparison
- Loading and analyzing BinExport files
- Managing diff results and databases
- Accessing match information and statistics

Example:
    Basic usage for diffing two binaries:

    >>> import bindiff
    >>> # Diff two BinExport files
    >>> bindiff.diff('primary.BinExport', 'secondary.BinExport', 'results.db')
    >>>
    >>> # Load and analyze results
    >>> results = bindiff.Results.load('results.db')
    >>> print(f"Matched functions: {results.num_matches}")
    >>> for match in results.matches:
    ...     print(f"  {match.primary_name} -> {match.secondary_name}")
"""

__version__ = "8.0.0"

from .core import (
    diff,
    load_matches,
    load_statistics,
    get_config,
    get_default_config,
    set_config,
    reset_config,
    CallGraph,
    FlowGraph,
    FixedPoint,
    MatchInfo,
    StatisticsInfo,
)

from .results import (
    Results,
)

from .database import (
    BinDiffDatabase,
    FunctionMatch,
    FileInfo,
    MANUAL_ALGORITHM,
)

__all__ = [
    # Main API
    "diff",
    "Results",

    # Reading and editing a .BinDiff file
    "BinDiffDatabase",
    "FunctionMatch",
    "FileInfo",
    "MANUAL_ALGORITHM",

    # Loading functions
    "load_matches",
    "load_statistics",

    # Configuration
    "get_config",
    "get_default_config",
    "set_config",
    "reset_config",

    # Core types
    "CallGraph",
    "FlowGraph",
    "FixedPoint",

    # Data types
    "MatchInfo",
    "StatisticsInfo",
]
