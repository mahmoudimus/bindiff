# BinDiff Python Interface - Installation Guide

Complete installation guide for the BinDiff Python interface.

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Python**: 3.8 or higher
- **C++ Compiler**:
  - Linux: GCC 9+ or Clang 10+
  - macOS: Xcode 12+ or Command Line Tools
  - Windows: MSVC 2019+ or MinGW
- **CMake**: 3.20 or higher

### Python Dependencies

- **Cython**: 3.0.0 or higher (required)
- **setuptools**: 65.0 or higher (required)
- **wheel**: Latest version (required)
- **PySide6**: 6.0 or higher (optional, for GUI)
- **pytest**: 7.0 or higher (optional, for testing)

## Installation Methods

### Method 1: Install from BinDiff Build (Recommended)

This method builds BinDiff and then installs the Python package.

#### Step 1: Clone Repositories

```bash
# Clone BinExport
git clone https://github.com/google/binexport.git

# Clone BinDiff
git clone https://github.com/google/bindiff.git

cd bindiff
```

#### Step 2: Build BinDiff

```bash
# Create build directory
mkdir -p build && cd build

# Configure with CMake
cmake .. -DBINDIFF_BUILD_TESTING=OFF

# Build (this will take a few minutes)
cmake --build . -j$(nproc)

cd ..
```

#### Step 3: Install Python Package

```bash
# Install Python dependencies
pip install Cython>=3.0 setuptools wheel

# Install BinDiff Python package
cd python
pip install -e .

# Or for development with all optional dependencies:
pip install -e ".[dev,ui]"
```

#### Step 4: Verify Installation

```bash
python -c "import bindiff; print(bindiff.__version__)"
```

### Method 2: Development Installation

For active development on the Python interface.

#### Step 1: Build BinDiff (as above)

```bash
cd bindiff
mkdir -p build && cd build
cmake .. -DBINDIFF_BUILD_TESTING=OFF
cmake --build .
cd ..
```

#### Step 2: Install in Editable Mode

```bash
cd python

# Install development dependencies
pip install -e ".[dev,ui]"

# Run in-place build
python setup.py build_ext --inplace
```

Now you can edit Python files and see changes immediately without reinstalling.

### Method 3: CMake-Based Build (Advanced)

Build Python extension directly with CMake.

```bash
cd bindiff
mkdir -p build && cd build

# Enable Python extension build
cmake .. \
  -DBINDIFF_BUILD_TESTING=OFF \
  -DBINDIFF_BUILD_PYTHON_EXTENSION=ON

cmake --build .
```

The extension will be built in `build/python/bindiff/core.so`.

To use it:

```bash
# Add to PYTHONPATH
export PYTHONPATH=/path/to/bindiff/build/python:$PYTHONPATH

python -c "import bindiff; print('Success!')"
```

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cmake \
  python3-dev \
  python3-pip

# Install Python dependencies
pip3 install Cython>=3.0 setuptools wheel

# Follow Method 1 above
```

### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake python@3.11

# Install Python dependencies
pip3 install Cython>=3.0 setuptools wheel

# Follow Method 1 above
```

### Windows

```powershell
# Install Visual Studio 2019 or later with C++ development tools
# Install CMake from https://cmake.org/download/
# Install Python 3.8+ from https://www.python.org/downloads/

# Install Python dependencies
pip install Cython>=3.0 setuptools wheel

# Clone and build (use Git Bash or PowerShell)
git clone https://github.com/google/binexport.git
git clone https://github.com/google/bindiff.git

cd bindiff
mkdir build
cd build

# Configure
cmake .. -DBINDIFF_BUILD_TESTING=OFF -G "Visual Studio 16 2019"

# Build
cmake --build . --config Release

# Install Python package
cd ..\python
pip install -e .
```

## Troubleshooting

### Problem: CMake can't find BinExport

**Solution**: Ensure BinExport is in a sibling directory to BinDiff:

```bash
ls -la ..
# Should show both 'binexport' and 'bindiff' directories

# If not, clone BinExport:
cd ..
git clone https://github.com/google/binexport.git
cd bindiff
```

### Problem: Cython version too old

**Error**: `Cython version 2.x.x is too old`

**Solution**:

```bash
pip install --upgrade "Cython>=3.0"
```

### Problem: Can't find bindiff_shared library

**Error**: `NameError: ... bindiff_shared ...`

**Solution**: Make sure BinDiff is fully built first:

```bash
cd build
cmake --build . --target bindiff_shared
```

### Problem: Import error on macOS

**Error**: `ImportError: dlopen(...): image not found`

**Solution**: Set library path:

```bash
export DYLD_LIBRARY_PATH=/path/to/bindiff/build:$DYLD_LIBRARY_PATH
```

Or use `install_name_tool` to fix the library paths:

```bash
install_name_tool -change @rpath/libbindiff_shared.dylib \
  /path/to/bindiff/build/libbindiff_shared.dylib \
  /path/to/bindiff/python/build/lib.*/bindiff/core*.so
```

### Problem: Boost not found

**Error**: `fatal error: boost/graph/compressed_sparse_row_graph.hpp: No such file`

**Solution**: CMake should download Boost automatically. If not:

```bash
# Set Boost include directory
export BOOST_INCLUDE_DIR=/path/to/boost

# Or on Ubuntu/Debian:
sudo apt-get install libboost-dev

export BOOST_INCLUDE_DIR=/usr/include
```

### Problem: Python development headers missing

**Error**: `fatal error: Python.h: No such file or directory`

**Solution**:

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev

# macOS (usually included with Python)
# If needed:
brew install python@3.11

# Windows
# Reinstall Python with "Development headers" option checked
```

## Verifying Installation

### Quick Test

```bash
python3 << 'EOF'
import bindiff
print(f"BinDiff Python version: {bindiff.__version__}")
print(f"Available functions: {dir(bindiff)}")
EOF
```

### Run Examples

```bash
cd python/examples

# Check if examples are present
ls -la

# Run basic example (requires BinExport files)
python basic_diff.py --help
```

### Run Tests (if installed with dev dependencies)

```bash
cd python
pytest tests/
```

## Next Steps

After successful installation:

1. **Read the README**: `python/README.md`
2. **Explore examples**: `python/examples/`
3. **Check architecture**: `python/ARCHITECTURE.md`
4. **Try the GUI**: `python examples/pyside6_viewer.py` (requires PySide6)

## Updating

To update the Python package after modifying code:

```bash
cd python

# Rebuild Cython extensions
python setup.py build_ext --inplace

# Or reinstall
pip install -e . --force-reinstall --no-deps
```

## Uninstalling

```bash
pip uninstall bindiff
```

## Getting Help

If you encounter issues:

1. Check the [troubleshooting section](#troubleshooting)
2. Review the [BinDiff documentation](https://github.com/google/bindiff)
3. File an issue at [BinDiff Issues](https://github.com/google/bindiff/issues)

## Development Setup

For contributing to the Python interface:

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install code formatters
pip install black isort mypy

# Format code
black bindiff/
isort bindiff/

# Type checking
mypy bindiff/

# Run tests
pytest tests/ -v
```
