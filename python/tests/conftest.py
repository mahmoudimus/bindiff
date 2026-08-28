"""Shared configuration for the BinDiff Python tests.

These run inside an IDA Pro Docker image (see docker-compose.yml and
tools/scripts/run_tests_docker.sh). The Cython extension is loaded by IDA's own
interpreter, so it must have been compiled against that interpreter -- an
extension built elsewhere will not import.
"""

import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON_DIR = REPO_ROOT / "python"
FIXTURES_DIR = REPO_ROOT / "fixtures"

# The compiled package lives in python/bindiff, next to the sources.
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

# Mirrors how IDA loads the plugin, so the plugin's own imports resolve the same
# way under test as they do in a real session.
IDA_PLUGIN_DIR = "/root/.idapro/plugins"
if os.path.isdir(IDA_PLUGIN_DIR) and IDA_PLUGIN_DIR not in sys.path:
    sys.path.insert(0, IDA_PLUGIN_DIR)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "requires_extension: needs the compiled bindiff extension"
    )
    config.addinivalue_line(
        "markers", "requires_ida: needs a running IDA Pro interpreter"
    )
    config.addinivalue_line("markers", "e2e: diffs real fixtures end to end")


@pytest.fixture(scope="session")
def fixtures_dir() -> pathlib.Path:
    """The .BinExport corpus shared with the C++ groundtruth tests."""
    if not FIXTURES_DIR.is_dir():
        pytest.skip(f"fixtures directory not found at {FIXTURES_DIR}")
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def insider_pair(fixtures_dir):
    """The smallest fixture pair: two builds of the same program."""
    primary = fixtures_dir / "insider" / "insider_gcc.BinExport"
    secondary = fixtures_dir / "insider" / "insider_lcc.BinExport"
    for path in (primary, secondary):
        if not path.is_file():
            pytest.skip(f"fixture missing: {path}")
    return primary, secondary


@pytest.fixture(scope="session")
def bindiff_module():
    """The compiled extension, or a skip explaining how to build it."""
    try:
        import bindiff
    except ImportError as exc:
        pytest.skip(
            f"bindiff extension not importable ({exc}). Build it with:\n"
            "  ./tools/scripts/run_tests_docker.sh build"
        )
    if not hasattr(bindiff, "diff"):
        pytest.skip("bindiff imported but has no diff(); extension not built")
    return bindiff
