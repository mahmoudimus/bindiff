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
    int DiffBinaries(const string& primary_path,
                    const string& secondary_path,
                    const string& output_database) except +

    vector[CMatchInfo] LoadMatches(const string& database_path) except +
    CStatisticsInfo LoadStatistics(const string& database_path) except +
