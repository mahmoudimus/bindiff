# BinDiff IDA Plugin (Python Implementation)

This is a **complete Python implementation** of the BinDiff IDA plugin, replacing the C++ version. The plugin uses Cython bindings to call BinDiff's C++ core while providing all UI and interaction logic in Python.

## Features

### Complete Functionality
- ✅ **Matched Functions Viewer** - Browse all function matches with similarity/confidence
- ✅ **Unmatched Functions Viewers** - View unmatched functions in both binaries
- ✅ **Statistics Viewer** - Display comprehensive diff statistics
- ✅ **Manual Matching** - Add custom matches between functions
- ✅ **Match Deletion** - Remove incorrect matches
- ✅ **Match Confirmation** - Mark matches as manually verified
- ✅ **Comment/Symbol Porting** - Import symbols and comments from matched functions
- ✅ **Incremental Diff** - Re-run diff with manual changes
- ✅ **Visual Diff Preparation** - Prepare for flow graph and call graph visualization

### Advantages Over C++ Plugin
- **Easier Customization** - Modify UI and behavior without recompiling
- **Python Ecosystem** - Use Python libraries for analysis and automation
- **Rapid Development** - Iterate faster with Python
- **Better Integration** - Leverage IDA's Python API features
- **PySide6 Compatible** - Can be extended with modern Qt GUI

## Architecture

```
┌─────────────────────────────────────┐
│   IDA Python Plugin (bindiff_plugin.py)   │
│   - MatchedFunctionsChooser        │
│   - UnmatchedFunctionsChoosers     │
│   - StatisticsChooser              │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Python Bindings (ida_plugin.pyx)  │
│  - BindiffResults class            │
│  - Match, UnmatchedFunction        │
│  - Statistic classes               │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  C++ Wrappers (results_wrapper.cc)  │
│  - ResultsWrapper                   │
│  - Simplified API for Cython        │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│    BinDiff C++ Core (ida/results.cc)    │
│    - Results class                  │
│    - Diff engine integration        │
└─────────────────────────────────────┘
```

## Installation

### Prerequisites

1. **IDA Pro 8.2+** with Python 3 support
2. **BinDiff** built from source
3. **Python 3.8+**
4. **Cython 3.0+**

### Build Steps

#### 1. Build BinDiff with IDA Plugin Support

```bash
cd bindiff
mkdir build && cd build

# Configure with IDA SDK path
cmake .. \
  -DIdaSdk_ROOT_DIR=/path/to/idasdk \
  -DBINDIFF_BUILD_TESTING=OFF

# Build everything
cmake --build .
```

#### 2. Build Python Bindings

```bash
cd ../python

# Install Python dependencies
pip install Cython>=3.0 setuptools wheel

# Build bindings (requires IDA plugin to be built)
python setup.py build_ext --inplace
pip install -e .
```

#### 3. Install Plugin to IDA

```bash
# Copy plugin file
cp ida_plugin/bindiff_plugin.py ~/.idapro/plugins/

# Copy Python module (or ensure it's in PYTHONPATH)
cp -r build/lib.*/bindiff ~/.idapro/python/
```

#### Alternative: Manual Installation

```bash
# Symlink for easier development
ln -s /path/to/bindiff/python/ida_plugin/bindiff_plugin.py ~/.idapro/plugins/
ln -s /path/to/bindiff/python/bindiff ~/.idapro/python/
```

### Verify Installation

1. Start IDA Pro
2. Check the Output window for:
   ```
   BinDiff-NG 8.1.0 initialized
   ```
3. Press `Ctrl+6` or go to `Edit` → `Plugins` → `BinDiff`

## Usage

### Basic Workflow

1. **Load BinDiff Results**
   - Press `Ctrl+6`
   - Select "YES" to load results
   - Choose a `.BinDiff` file

2. **View Matched Functions**
   - Automatically shown after loading
   - Double-click to jump to function
   - Select multiple rows for batch operations

3. **View Unmatched Functions**
   - Shown if you answer "YES" to the prompt
   - Separate windows for primary and secondary binaries

4. **View Statistics**
   - Shows comprehensive diff statistics
   - Function/basic block/instruction counts
   - Similarity metrics

### Advanced Features

#### Manual Matching

```python
# In IDA's Python console
from bindiff.ida_plugin import BindiffResults

results = BindiffResults.create()
results.read_from_file('path/to/diff.BinDiff')

# Add manual match
results.add_match(0x401000, 0x402000)  # primary_addr, secondary_addr

# Save updated results
results.write_to_file('path/to/diff.BinDiff')
```

#### Port Comments/Symbols

```python
# Port comments from selected matches
indices = [0, 1, 2, 3]  # Match indices
results.port_comments(indices, PortCommentsKind.NORMAL)

# Or port as external library
results.port_comments(indices, PortCommentsKind.AS_EXTERNAL_LIB)
```

#### Incremental Diff

```python
# After adding manual matches
results.incremental_diff()
```

### Automation Example

```python
# Script to auto-process diff results
import ida_auto
import ida_kernwin
from bindiff.ida_plugin import BindiffResults, PortCommentsKind

def auto_process_diff(diff_file):
    """Automatically load diff and port high-confidence matches."""
    # Wait for auto-analysis
    ida_auto.auto_wait()

    # Load results
    results = BindiffResults.create()
    if results.read_from_file(diff_file) != 0:
        print(f"Failed to load {diff_file}")
        return

    # Find high-confidence matches
    high_conf_indices = []
    for i in range(results.num_matches):
        match = results.get_match(i)
        if match.confidence >= 0.9 and match.similarity >= 0.95:
            high_conf_indices.append(i)

    print(f"Found {len(high_conf_indices)} high-confidence matches")

    # Port comments
    if high_conf_indices:
        results.port_comments(high_conf_indices, PortCommentsKind.NORMAL)
        print(f"Ported comments from {len(high_conf_indices)} functions")

    # Save
    results.write_to_file(diff_file)
    print("Results saved")

# Usage
auto_process_diff("/path/to/diff.BinDiff")
```

## Customization

### Extending the Plugin

The Python implementation makes it easy to customize:

```python
class CustomMatchedChooser(MatchedFunctionsChooser):
    """Custom chooser with additional filtering."""

    def __init__(self, results, min_similarity=0.8):
        super().__init__(results)
        self.min_similarity = min_similarity

    def refresh_items(self):
        """Only show matches above threshold."""
        super().refresh_items()
        # Filter by similarity
        self.items = [
            item for i, item in enumerate(self.items)
            if self.results.get_match(i).similarity >= self.min_similarity
        ]
```

### Adding Context Menu Actions

```python
import ida_kernwin

class ImportSymbolsAction(ida_kernwin.action_handler_t):
    """Action to import symbols from selected matches."""

    def __init__(self, results):
        super().__init__()
        self.results = results

    def activate(self, ctx):
        # Get selected indices from chooser
        # (implementation depends on chooser context)
        indices = [...]
        self.results.port_comments(indices, PortCommentsKind.NORMAL)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# Register action
ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        "bindiff:import_symbols",
        "Import symbols/comments",
        ImportSymbolsAction(results)
    )
)
```

## Troubleshooting

### Plugin Not Loading

**Problem**: Plugin doesn't appear in IDA

**Solutions**:
1. Check IDA output window for errors
2. Verify Python module is importable:
   ```python
   import bindiff.ida_plugin
   ```
3. Check file permissions on plugin file
4. Ensure Cython extensions are built for correct Python version

### Import Errors

**Problem**: `ImportError: No module named 'bindiff'`

**Solutions**:
1. Add to PYTHONPATH:
   ```bash
   export PYTHONPATH=/path/to/bindiff/python:$PYTHONPATH
   ```
2. Or copy `bindiff` module to IDA's Python directory:
   ```bash
   cp -r bindiff ~/.idapro/python/
   ```

### Results Not Loading

**Problem**: Results file fails to load

**Solutions**:
1. Verify file is a valid BinDiff database (`.BinDiff` extension)
2. Check file was created with compatible BinDiff version
3. Ensure file permissions allow reading
4. Try loading in IDA console:
   ```python
   from bindiff.ida_plugin import BindiffResults
   r = BindiffResults.create()
   print(r.read_from_file('/path/to/file.BinDiff'))
   ```

### Crashes or Segfaults

**Problem**: IDA crashes when using plugin

**Solutions**:
1. Ensure BinDiff and bindings built with same compiler
2. Check for ABI compatibility between Python versions
3. Verify IDA SDK version matches build configuration
4. Run with debug logging:
   ```bash
   export IDAPYTHON_DEBUG=1
   ```

## Development

### Building for Development

```bash
# Build in debug mode
python setup.py build_ext --inplace --debug

# Enable verbose output
python setup.py build_ext --inplace -v
```

### Running Tests

```bash
# Unit tests for Python code
pytest python/tests/

# Test in IDA (manual)
ida64 -A -S"test_script.py" test_binary.idb
```

### Code Structure

- `bindiff_plugin.py` - Main plugin file (IDA entry point)
- `ida_plugin.pyx` - Cython bindings for Results API
- `ida_plugin.pxd` - Cython declarations
- `results_wrapper.h/cc` - C++ wrapper layer

## Performance

The Python plugin has comparable performance to the C++ version:

- **Loading**: ~same speed (I/O bound)
- **UI Updates**: Slightly slower for very large result sets (10,000+ matches)
- **Match Operations**: ~same speed (C++ backend)

For better performance with large datasets:
- Use filtering to reduce displayed items
- Implement lazy loading for choosers
- Cache frequently accessed data

## Contributing

To contribute improvements:

1. Modify `bindiff_plugin.py` for UI changes
2. Modify `ida_plugin.pyx` for API bindings
3. Modify `results_wrapper.h/cc` for C++ interface
4. Test thoroughly with various diff files
5. Submit pull request

## License

Apache License 2.0 - See LICENSE file

## Support

- **Issues**: https://github.com/google/bindiff/issues
- **Documentation**: https://github.com/google/bindiff
- **IDA SDK Docs**: https://hex-rays.com/products/ida/support/sdkdoc/

## Credits

- Original C++ plugin by Google BinDiff team
- Python port maintains full compatibility
- Uses Cython for high-performance bindings
