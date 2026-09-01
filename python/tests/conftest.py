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

# Last, so it ends up first. The harness builds the extension outside the
# checkout: /work is a bind mount, a Python extension has the same filename on
# every platform, and an in-place build there replaced whatever the host had
# built -- leaving the plugin unable to import in a real IDA, with nothing to
# say so. BINDIFF_PACKAGE_DIR holds the extension plus links to these same
# sources. It has to beat both of the entries above, which are two views of
# the checkout and so carry the host's extension, not this platform's.
PACKAGE_DIR = os.environ.get("BINDIFF_PACKAGE_DIR")
if PACKAGE_DIR and os.path.isdir(PACKAGE_DIR):
    if PACKAGE_DIR in sys.path:
        sys.path.remove(PACKAGE_DIR)
    sys.path.insert(0, PACKAGE_DIR)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "requires_extension: needs the compiled bindiff extension"
    )
    config.addinivalue_line(
        "markers", "requires_ida: needs a running IDA Pro interpreter"
    )
    config.addinivalue_line("markers", "e2e: diffs real fixtures end to end")
    config.addinivalue_line(
        "markers", "slow: takes seconds -- opens a database with idalib")
    config.addinivalue_line(
        "markers",
        "requires_binexport: needs BinExport's IDA plugin installed; run the "
        "harness with --with-binexport")


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


@pytest.fixture(scope="session")
def libssl_pair(fixtures_dir):
    """Two gcc builds of the same library, four years of compiler apart.

    The pair with real ground truth to measure against: 737 known pairs, and
    the one where the import feature has room to help, because both sides link
    against the same runtime.
    """
    directory = fixtures_dir / "libssl"
    primary = directory / "libssl.0.9.8g.x86.gcc.4.3.3.a.BinExport"
    secondary = directory / "libssl.0.9.8g.x86.gcc.3.4.6.a.BinExport"
    truth = (directory /
             "libssl.0.9.8g.x86.gcc.4.3.3.a_vs_libssl.0.9g.x86.gcc.3.4.6.a.truth")
    for path in (primary, secondary, truth):
        if not path.is_file():
            pytest.skip(f"fixture missing: {path}")
    return primary, secondary, truth


@pytest.fixture
def ground_truth():
    """Parses a .truth file into {primary address: secondary address}."""
    def parse(path):
        pairs = {}
        for line in pathlib.Path(path).read_text().splitlines():
            fields = line.split()
            if len(fields) >= 2:
                pairs[int(fields[0], 16)] = int(fields[1], 16)
        return pairs
    return parse


@pytest.fixture(scope="session")
def generated_pair(tmp_path_factory):
    """Two builds of one generated program, exported, with ground truth.

    Session-scoped because building it means two compiles and two full IDA
    analyses; the pair is immutable once made, so sharing it is safe.

    Skips unless gcc, idalib and BinExport's IDA plugin are all present. That
    last one is opt-in:

        ./tools/scripts/run_tests_docker.sh python --with-binexport
    """
    import importlib.util

    if importlib.util.find_spec("idapro") is None:
        pytest.skip("idalib not available")

    from fixture_builder import FixtureUnavailable, build_pair

    directory = tmp_path_factory.mktemp("generated")
    try:
        pair = build_pair(directory)
    except FixtureUnavailable as exc:
        pytest.skip(
            f"could not generate a fixture pair: {exc}. Needs gcc and "
            f"BinExport's IDA plugin (run the harness with --with-binexport)")
    if len(pair.truth) < 20:
        pytest.skip(
            f"generated pair has only {len(pair.truth)} known pairs, too few "
            f"to measure against")
    return pair
