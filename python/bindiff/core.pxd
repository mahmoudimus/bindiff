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
    # Data structures
    cdef cppclass FunctionInfo:
        unsigned long long address
        string name
        string demangled_name
        int basic_block_count
        int edge_count
        int instruction_count
        double md_index

    cdef cppclass BasicBlockInfo:
        unsigned long long address
        int instruction_count
        double md_index

    cdef cppclass MatchInfo:
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

    cdef cppclass StatisticsInfo:
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

    # Wrapper classes (declarations only - actual classes are in C++)
    cdef cppclass CallGraphWrapper:
        CallGraphWrapper(...)
        string GetFilePath()
        string GetExeFilename()
        string GetExeHash()
        int GetNumFunctions()
        vector[unsigned long long] GetFunctionAddresses()
        FunctionInfo GetFunctionInfo(unsigned long long address)
        bool HasFunction(unsigned long long address)
        int GetNumBasicBlocks()
        int GetNumEdges()
        int GetNumInstructions()

    cdef cppclass FlowGraphWrapper:
        FlowGraphWrapper(...)
        unsigned long long GetAddress()
        int GetNumBasicBlocks()
        int GetNumEdges()
        int GetNumInstructions()
        vector[unsigned long long] GetBasicBlockAddresses()
        BasicBlockInfo GetBasicBlockInfo(unsigned long long address)
        bool HasBasicBlock(unsigned long long address)
        unsigned long long GetEntryPointAddress()

    cdef cppclass FixedPointWrapper:
        FixedPointWrapper(...)
        unsigned long long GetPrimaryAddress()
        unsigned long long GetSecondaryAddress()
        double GetSimilarity()
        double GetConfidence()
        int GetAlgorithm()
        int GetFlags()
        int GetNumBasicBlockMatches()
        vector[pair[unsigned long long, unsigned long long]] GetBasicBlockMatches()

    # High-level functions
    int DiffBinaries(const string& primary_path,
                    const string& secondary_path,
                    const string& output_database) except +

    vector[MatchInfo] LoadMatches(const string& database_path) except +
    StatisticsInfo LoadStatistics(const string& database_path) except +
