# BinDiff Python Interface

A Cython 3.0+ based Python interface for the BinDiff binary diffing engine.

## Overview

This package provides **two main components**:

1. **Standalone Python API** - Use BinDiff from Python scripts without IDA
2. **IDA Pro Plugin (Python)** - Complete IDA plugin written in Python/Cython

## Features

### Standalone API
- **High-Performance**: Direct Cython bindings to BinDiff's C++ core
- **Pythonic API**: Clean, intuitive Python interface
- **PySide6 Ready**: Designed for use with PySide6 or custom UIs
- **Complete Access**: Diff results, statistics, and match information

### IDA Plugin (Python Implementation)
- **Full C++ Plugin Replacement**: All functionality from C++ version
- **Pure Python UI**: Choosers for matched/unmatched functions, statistics
- **Interactive Operations**: Add/delete matches, port comments, incremental diff
- **Easy Customization**: Modify behavior without recompiling
- **Visual Diff Integration**: Prepare flow graph and call graph diffs

## Requirements

- Python 3.8 or higher
- Cython 3.0 or higher
- BinDiff (built from source)
- BinExport (sibling directory to BinDiff)

## Installation

### 1. Build BinDiff

First, build BinDiff using CMake:

```bash
cd /path/to/bindiff
mkdir -p build && cd build
cmake .. -DBINDIFF_BUILD_TESTING=OFF
cmake --build .
```

### 2. Install Python Package

From the `python/` directory:

```bash
cd python
pip install -e .
```

For development with UI support:

```bash
pip install -e ".[dev,ui]"
```

## Quick Start

### Standalone Usage

#### Basic Diffing

```python
import bindiff

# Diff two BinExport files
result = bindiff.diff('binary1.BinExport', 'binary2.BinExport', 'results.db')

if result == 0:
    print("Diff completed successfully!")
```

### Analyzing Results

```python
import bindiff

# Load diff results
results = bindiff.Results.load('results.db')

# Print summary
results.print_summary()

# Access matches
for match in results.matches[:10]:
    print(f"{match.primary_name} -> {match.secondary_name}")
    print(f"  Similarity: {match.similarity:.2%}")
    print(f"  Confidence: {match.confidence:.2%}")

# Filter matches
high_confidence = results.get_matches_by_confidence(min_confidence=0.9)
print(f"High confidence matches: {len(high_confidence)}")
```

### Statistics

```python
import bindiff

results = bindiff.Results.load('results.db')
stats = results.statistics

print(f"Function similarity: {stats.function_similarity:.2%}")
print(f"Basic block similarity: {stats.basic_block_similarity:.2%}")
print(f"Instruction similarity: {stats.instruction_similarity:.2%}")
```

### IDA Plugin Usage

The complete IDA plugin is implemented in Python. See `ida_plugin/README.md` for detailed documentation.

#### Installation

```bash
# 1. Build BinDiff with IDA support
cmake .. -DIdaSdk_ROOT_DIR=/path/to/idasdk
cmake --build .

# 2. Build Python bindings
cd python
python setup.py build_ext --inplace
pip install -e .

# 3. Install to IDA
cp ida_plugin/bindiff_plugin.py ~/.idapro/plugins/
cp -r bindiff ~/.idapro/python/
```

#### Quick Usage

1. Press **Ctrl+6** in IDA to launch the plugin
2. Load a `.BinDiff` file
3. Browse matched/unmatched functions
4. Add manual matches, port comments, perform incremental diff

#### Programmatic Usage

```python
# In IDA's Python console
from bindiff.ida_plugin import BindiffResults, PortCommentsKind

# Load results
results = BindiffResults.create()
results.read_from_file('diff.BinDiff')

# Add manual match
results.add_match(0x401000, 0x402000)

# Port comments from high-confidence matches
indices = [i for i in range(results.num_matches)
           if results.get_match(i).confidence >= 0.9]
results.port_comments(indices, PortCommentsKind.NORMAL)

# Re-run diff
results.incremental_diff()

# Save
results.write_to_file('diff.BinDiff')
```

For complete IDA plugin documentation, see **[ida_plugin/README.md](ida_plugin/README.md)**.

## API Reference

### Main Functions

- `bindiff.diff(primary, secondary, output)` - Diff two binaries
- `bindiff.Results.load(database)` - Load diff results

### Results Class

- `results.matches` - List of all matches
- `results.statistics` - Diff statistics
- `results.get_matches_by_similarity(min, max)` - Filter by similarity
- `results.get_matches_by_confidence(min)` - Filter by confidence
- `results.print_summary()` - Print summary

### Data Classes

- `MatchInfo` - Function match information
- `StatisticsInfo` - Diff statistics
- `FunctionInfo` - Function information
- `Config` - Configuration options

## Examples

See the `examples/` directory for complete examples:

- `basic_diff.py` - Basic diffing workflow
- `analyze_results.py` - Result analysis
- `pyside6_viewer.py` - PySide6 GUI viewer (requires PySide6)

## Building from Source

### Prerequisites

1. **BinDiff and BinExport**:
   ```bash
   git clone https://github.com/google/binexport.git
   git clone https://github.com/google/bindiff.git
   cd bindiff
   mkdir build && cd build
   cmake .. -DBINDIFF_BUILD_TESTING=OFF
   cmake --build .
   ```

2. **Python Dependencies**:
   ```bash
   pip install Cython>=3.0 setuptools wheel
   ```

### Build Steps

```bash
cd python
python setup.py build_ext --inplace
pip install -e .
```

## Architecture

The Python interface consists of three layers:

1. **C++ Wrapper Layer** (`wrappers.h/cc`) - Simplifies Boost graph access
2. **Cython Declarations** (`*.pxd`) - Declare C++ types
3. **Cython Implementation** (`*.pyx`) - Python-friendly wrappers

This architecture provides:
- Type safety
- Memory management
- Pythonic interface
- High performance

## License

Apache License 2.0 - See LICENSE file for details

## Contributing

Contributions are welcome! Please see the main BinDiff repository for contribution guidelines.
