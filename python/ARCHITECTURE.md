# BinDiff Python Interface Architecture

This document describes the architecture of the BinDiff Python interface built with Cython 3.0+.

## Overview

The Python interface provides a high-performance, Pythonic API for BinDiff's C++ core, enabling usage with PySide6 instead of IDA's native forms. The interface is designed in layers to provide both ease of use and direct access to low-level functionality when needed.

## Architecture Layers

### Layer 1: C++ Wrapper Layer

**Location**: `python/bindiff/wrappers.h` and `python/bindiff/wrappers.cc`

**Purpose**: Provides simplified C++ interfaces that are easier to wrap with Cython.

**Key Components**:

- **Wrapper Classes**: Simplify access to Boost graph types
  - `CallGraphWrapper` - Function-level control flow graph access
  - `FlowGraphWrapper` - Basic block-level control flow graph access
  - `FixedPointWrapper` - Match information access

- **Data Structures**: Plain C++ structs for passing data to Python
  - `FunctionInfo` - Function metadata
  - `BasicBlockInfo` - Basic block metadata
  - `MatchInfo` - Function match information
  - `StatisticsInfo` - Diff statistics

- **High-Level Functions**: Simplified APIs for common operations
  - `DiffBinaries()` - Perform a diff operation
  - `LoadMatches()` - Load matches from database
  - `LoadStatistics()` - Load statistics from database

**Why This Layer?**

Cython has limited support for complex C++ types like Boost Graph Library. The wrapper layer:
- Converts Boost graph structures to simple vectors and primitives
- Provides RAII and memory management
- Handles C++ exceptions and error codes
- Simplifies the Cython interface

### Layer 2: Cython Declaration Layer

**Location**: `python/bindiff/core.pxd`

**Purpose**: Declares C++ types and functions for Cython.

**Key Components**:

- External C++ declarations (`cdef extern`)
- Type mappings (C++ ↔ Cython)
- Function signatures with exception handling

**Example**:

```cython
cdef extern from "python/bindiff/wrappers.h" namespace "security::bindiff":
    cdef cppclass MatchInfo:
        unsigned long long primary_address
        unsigned long long secondary_address
        string primary_name
        string secondary_name
        double similarity
        double confidence

    vector[MatchInfo] LoadMatches(const string& database_path) except +
```

### Layer 3: Cython Implementation Layer

**Location**: `python/bindiff/core.pyx`

**Purpose**: Implements Python-accessible wrappers for C++ functionality.

**Key Components**:

- **Python Classes**: Pythonic wrappers for C++ data structures
  - `FunctionInfo`, `BasicBlockInfo`, `MatchInfo`, `StatisticsInfo`
  - Type conversions (C++ ↔ Python)
  - Memory management

- **Python Functions**: High-level API functions
  - `diff()` - Main diff function
  - `load_matches()` - Load matches from database
  - `load_statistics()` - Load statistics

**Example**:

```python
def diff(primary_path: str, secondary_path: str, output_path: str) -> int:
    cdef string c_primary = primary_path.encode('utf-8')
    cdef string c_secondary = secondary_path.encode('utf-8')
    cdef string c_output = output_path.encode('utf-8')

    return core_types.DiffBinaries(c_primary, c_secondary, c_output)
```

### Layer 4: Pure Python Layer

**Location**: `python/bindiff/results.py` and `python/bindiff/__init__.py`

**Purpose**: Provides high-level, user-friendly Python API.

**Key Components**:

- **`Results` Class**: High-level interface for diff results
  - Lazy loading of matches and statistics
  - Filtering and search capabilities
  - Summary and export functions

- **Module Interface**: Clean, documented API
  - Type hints
  - Docstrings
  - Examples

**Example**:

```python
results = Results.load('diff.db')
results.print_summary()

high_similarity = results.get_matches_by_similarity(0.9, 1.0)
for match in high_similarity:
    print(f"{match.primary_name} -> {match.secondary_name}")
```

## Data Flow

### Diffing Workflow

```
Python: bindiff.diff(primary, secondary, output)
  ↓
Cython: core.pyx::diff()
  ↓ (type conversion: str → std::string)
Cython: core.pxd declares DiffBinaries()
  ↓
C++: wrappers.cc::DiffBinaries()
  ↓ (calls BinDiff core)
C++: differ.cc::Diff()
  ↓
BinDiff Core Engine
  ↓
SQLite Database (results)
```

### Results Loading Workflow

```
Python: Results.load('diff.db')
  ↓
Python: results.matches (property access)
  ↓
Cython: load_matches('diff.db')
  ↓
C++: wrappers.cc::LoadMatches()
  ↓ (SQLite queries)
SQLite Database
  ↓
C++: vector<MatchInfo>
  ↓ (type conversion)
Cython: Python list of MatchInfo
  ↓
Python: List[MatchInfo]
```

## Memory Management

### C++ Side

- **Ownership**: Wrapper classes use non-owning pointers to BinDiff objects
- **Lifetime**: C++ objects are managed by BinDiff's existing mechanisms
- **Exceptions**: Converted to Python exceptions via `except +`

### Cython Side

- **Automatic Conversion**: Cython handles string/vector conversions
- **Reference Counting**: Python objects use normal reference counting
- **Cleanup**: No manual memory management needed

### Best Practices

1. **String Encoding**: Always encode Python strings to UTF-8 for C++
2. **Vector Copying**: C++ vectors are copied to Python lists (no shared memory)
3. **Exception Handling**: C++ exceptions become Python exceptions automatically

## Build System Integration

### CMake Build

The Python bindings integrate with BinDiff's existing CMake build:

```cmake
# python/CMakeLists.txt
add_library(bindiff_python_wrappers STATIC
  bindiff/wrappers.cc
  bindiff/wrappers.h
)

target_link_libraries(bindiff_python_wrappers
  bindiff_shared
  # ... other dependencies
)
```

### Python Build (setup.py)

For standalone Python installation:

```python
extensions = [
    Extension(
        "bindiff.core",
        sources=["bindiff/core.pyx", "bindiff/wrappers.cc"],
        include_dirs=[...],
        libraries=["bindiff_shared", ...],
        language="c++",
        extra_compile_args=["-std=c++17"],
    ),
]

setup(ext_modules=cythonize(extensions))
```

## Performance Considerations

### Optimizations

1. **Lazy Loading**: Statistics and matches loaded on first access
2. **Cython Compilation**: Compiled to native code, not interpreted
3. **Direct C++ Calls**: Minimal overhead between Python and C++
4. **Efficient Data Structures**: Vector copying happens once

### Bottlenecks

1. **String Encoding**: UTF-8 encoding/decoding for each string
2. **Vector Copying**: Large result sets copied from C++ to Python
3. **Database I/O**: SQLite queries dominate for large databases

### Recommendations

- Use filtering in C++ when possible (future enhancement)
- Batch operations instead of per-item processing
- Cache results in Python when repeatedly accessed

## Extension Points

### Adding New Functionality

To add new C++ functionality to Python:

1. **Add C++ wrapper** in `wrappers.h/cc`
   ```cpp
   std::vector<FlowGraphInfo> GetFlowGraphs(const std::string& path);
   ```

2. **Declare in Cython** in `core.pxd`
   ```cython
   vector[FlowGraphInfo] GetFlowGraphs(const string& path) except +
   ```

3. **Wrap in Cython** in `core.pyx`
   ```python
   def get_flow_graphs(path: str) -> List[FlowGraphInfo]:
       cdef string c_path = path.encode('utf-8')
       cdef vector[core_types.FlowGraphInfo] c_graphs = core_types.GetFlowGraphs(c_path)
       return [FlowGraphInfo(...) for g in c_graphs]
   ```

4. **Export from Python** in `__init__.py`
   ```python
   from .core import get_flow_graphs
   __all__ = [..., 'get_flow_graphs']
   ```

## Testing Strategy

### Unit Tests

Test each layer independently:

1. **C++ Layer**: Use existing BinDiff C++ tests
2. **Cython Layer**: Test type conversions and error handling
3. **Python Layer**: Test high-level API and edge cases

### Integration Tests

Test end-to-end workflows:

1. Diff two binaries
2. Load and verify results
3. Export to various formats

### Example Test

```python
def test_diff_and_load():
    # Perform diff
    result = bindiff.diff('test1.BinExport', 'test2.BinExport', 'test.db')
    assert result == 0

    # Load results
    results = bindiff.Results.load('test.db')
    assert results.num_matches > 0

    # Verify statistics
    stats = results.statistics
    assert stats.matched_function_count > 0
```

## Future Enhancements

### Planned Features

1. **Direct Graph Access**: Expose CallGraph and FlowGraph objects
2. **Manual Matching**: Add/remove matches programmatically
3. **Incremental Diff**: Re-run diff with updated matches
4. **Configuration**: Expose matching algorithm configuration
5. **Parallel Processing**: Multi-threaded diff operations
6. **Streaming Results**: Iterator-based result access for large databases

### PySide6 Integration

The interface is designed for PySide6 GUI development:

1. **Qt Models**: Create custom models from Results data
2. **Async Loading**: Load results in background threads
3. **Filtering/Sorting**: Implement in Python for UI responsiveness
4. **Visualization**: Export graph data for rendering

## References

- [Cython Documentation](https://cython.readthedocs.io/)
- [Cython 3.0 Release Notes](https://cython.readthedocs.io/en/latest/src/changes.html#release-3-0-0)
- [BinDiff Documentation](https://github.com/google/bindiff)
- [PySide6 Documentation](https://doc.qt.io/qtforpython/)
