# BinDiff Python Interface

A Cython 3.0+ based Python interface for the BinDiff binary diffing engine.

## Features

- **High-Performance**: Direct Cython bindings to BinDiff's C++ core
- **Pythonic API**: Clean, intuitive Python interface
- **PySide6 Ready**: Designed for use with PySide6 instead of IDA's native forms
- **Complete Access**: Access to diff results, statistics, and match information

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

### Basic Diffing

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
