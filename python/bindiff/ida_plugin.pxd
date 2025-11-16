# distutils: language = c++
# cython: language_level = 3

"""
Cython declarations for BinDiff IDA plugin types.
"""

from libcpp cimport bool
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.memory cimport unique_ptr

cdef extern from "python/bindiff/results_wrapper.h" namespace "security::bindiff":
    # Data structures matching ida/results.h
    cdef cppclass MatchDescription:
        double similarity
        double confidence
        int change_type
        unsigned long long address_primary
        string name_primary
        unsigned long long address_secondary
        string name_secondary
        bool comments_ported
        string algorithm_name
        int basic_block_count
        int basic_block_count_primary
        int basic_block_count_secondary
        int edge_count
        int edge_count_primary
        int edge_count_secondary
        int instruction_count
        int instruction_count_primary
        int instruction_count_secondary
        bool manual

    cdef cppclass UnmatchedDescription:
        unsigned long long address
        string name
        int basic_block_count
        int instruction_count
        int edge_count

    cdef cppclass StatisticDescription:
        string name
        bool is_count
        size_t count
        double value

    # Results wrapper providing complete IDA plugin API
    cdef cppclass ResultsWrapper:
        @staticmethod
        unique_ptr[ResultsWrapper] Create()

        # Matched functions
        size_t GetNumMatches()
        MatchDescription GetMatchDescription(size_t index)
        unsigned long long GetPrimaryAddress(size_t index)
        unsigned long long GetSecondaryAddress(size_t index)
        unsigned long long GetMatchPrimaryAddress(size_t index)
        unsigned long long GetMatchSecondaryAddress(size_t index)

        # Unmatched functions
        size_t GetNumUnmatchedPrimary()
        UnmatchedDescription GetUnmatchedDescriptionPrimary(size_t index)
        size_t GetNumUnmatchedSecondary()
        UnmatchedDescription GetUnmatchedDescriptionSecondary(size_t index)

        # Statistics
        size_t GetNumStatistics()
        StatisticDescription GetStatisticDescription(size_t index)

        # Match manipulation
        int DeleteMatches(const vector[size_t]& indices)
        int AddMatch(unsigned long long primary, unsigned long long secondary)
        int ConfirmMatches(const vector[size_t]& indices)

        # Comment/symbol porting
        int PortComments(const vector[size_t]& indices, int how)
        int PortCommentsByAddress(unsigned long long start_address_source,
                                 unsigned long long end_address_source,
                                 unsigned long long start_address_target,
                                 unsigned long long end_address_target,
                                 double min_confidence,
                                 double min_similarity)

        # Diff operations
        int IncrementalDiff()
        void MarkPortedCommentsInDatabase()

        # Visual diff preparation
        bool PrepareVisualDiff(size_t index, string* message)
        bool PrepareVisualCallGraphDiff(size_t index, string* message)

        # File I/O
        int ReadFromFile(const string& filename)
        int WriteToFile(const string& filename)

        # State management
        bool is_incomplete()
        bool is_modified()
        void set_modified()
        bool should_reset_selection()
        void set_should_reset_selection(bool value)
