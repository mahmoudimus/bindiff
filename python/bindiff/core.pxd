# distutils: language = c++
# cython: language_level = 3

"""
Cython declarations for BinDiff core types.
"""

from libcpp cimport bool
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.pair cimport pair

cdef extern from "python/bindiff/wrappers.h" namespace "security::bindiff":
    # C++ structs (using different names to avoid conflicts with Python classes)
    ctypedef struct CMatchInfo "security::bindiff::MatchInfo":
        unsigned long long primary_address
        unsigned long long secondary_address
        string primary_name
        string secondary_name
        double similarity
        double confidence
        int algorithm_id
        string algorithm_name
        bool is_manual
        int flags

    ctypedef struct CStatisticsInfo "security::bindiff::StatisticsInfo":
        int primary_function_count
        int secondary_function_count
        int matched_function_count
        int primary_basic_block_count
        int secondary_basic_block_count
        int matched_basic_block_count
        int primary_instruction_count
        int secondary_instruction_count
        int matched_instruction_count
        int primary_edge_count
        int secondary_edge_count
        int matched_edge_count

    # High-level functions
    # Declared nogil so callers can release the GIL around them. DiffBinaries
    # reads both inputs, runs the full matching pipeline and writes the result
    # database -- seconds to minutes of native work. Holding the GIL across it
    # freezes every other Python thread in the host process, which inside IDA
    # means the UI stops responding for the whole diff.
    #
    # `except +` still works without the GIL: Cython reacquires it to raise.
    int DiffBinaries(const string& primary_path,
                    const string& secondary_path,
                    const string& output_database) except + nogil

    vector[CMatchInfo] LoadMatches(const string& database_path) except + nogil
    CStatisticsInfo LoadStatistics(const string& database_path) except + nogil

    # Config accessors. Kept with the GIL: these are cheap, and they touch a
    # process-wide global that a running diff reads.
    string GetConfigJson() except +
    string GetDefaultConfigJson() except +
    void SetConfigJson(const string& json) except +
