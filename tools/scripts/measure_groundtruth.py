#!/usr/bin/env python3
"""Measures the differ against the checked-in ground truth.

The four fixtures under fixtures/ ship .truth files listing the function pairs
a human confirmed. The C++ suite uses them as a regression check -- results must
not get worse -- but it does not report *how good* they are, which is the number
that decides whether a new matching signal is worth building.

    tools/scripts/measure_groundtruth.py --bindiff build/out/bindiff
    tools/scripts/measure_groundtruth.py --sidecars      # build them first
    tools/scripts/measure_groundtruth.py --compare       # with vs. without

Name matching is disabled by default. Every fixture carries full symbols, so
with the shipped configuration almost everything matches by name and the
measurement says nothing about the algorithms; the case that matters is the
stripped one, where name matching has nothing to work with. Pass
--keep-name-matching to measure the configuration as shipped instead.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FEATURE_STEP = "function: feature imports/v1"

# name, primary, secondary, truth -- the same four pairs differ_test.cc uses.
FIXTURES = [
    ("insider",
     "insider/insider_gcc.BinExport",
     "insider/insider_lcc.BinExport",
     "insider/insider_gcc_vs_insider_lcc.truth"),
    ("libssl",
     "libssl/libssl.0.9.8g.x86.gcc.4.3.3.a.BinExport",
     "libssl/libssl.0.9.8g.x86.gcc.3.4.6.a.BinExport",
     "libssl/libssl.0.9.8g.x86.gcc.4.3.3.a_vs_libssl.0.9g.x86.gcc.3.4.6.a.truth"),
    ("minievil",
     "minievil/0d0d06e42bb39a4a8fd1a3da8a9be8d2abaacd4c7373d4cd36cd6fac6f4d1650.BinExport",
     "minievil/70726a39fda45d1e0bb167a2bf3825db0960529368a5814c4f43d59b4d585e79.BinExport",
     "minievil/minievil.truth"),
    ("mydoom",
     "mydoom/Mydoom-vc_orig.BinExport",
     "mydoom/Mydoom-vc_optz.BinExport",
     "mydoom/Mydoom-vc_orig_vs_Mydoom-vc_optz.truth"),
]


def to_unsigned(value: int) -> int:
    """Addresses are stored as signed BIGINTs in a .BinDiff."""
    return value + (1 << 64) if value < 0 else value


def read_truth(path: Path) -> dict:
    pairs = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2:
            pairs[int(fields[0], 16)] = int(fields[1], 16)
    return pairs


def read_matches(database: Path) -> dict:
    connection = sqlite3.connect(str(database))
    try:
        rows = connection.execute(
            "SELECT address1, address2 FROM function").fetchall()
    finally:
        connection.close()
    return {to_unsigned(a): to_unsigned(b) for a, b in rows}


def read_attributed(database: Path, algorithm: str) -> dict:
    """The matches one named algorithm is responsible for."""
    connection = sqlite3.connect(str(database))
    try:
        rows = connection.execute(
            "SELECT f.address1, f.address2 FROM function AS f "
            "JOIN functionalgorithm AS a ON f.algorithm = a.id "
            "WHERE a.name = ?", (algorithm,)).fetchall()
    finally:
        connection.close()
    return {to_unsigned(a): to_unsigned(b) for a, b in rows}


def write_config(destination: Path, bindiff: Path, keep_name_matching: bool,
                 with_feature: bool) -> Path:
    """Starts from the binary's own effective configuration.

    Taken from --print_config rather than from bindiff.json so that the
    measurement reflects what this build actually does, including any per-user
    configuration that would otherwise silently change the result.
    """
    printed = subprocess.run(
        [str(bindiff), "--print_config", "--nologo"],
        capture_output=True, text=True, check=True).stdout
    config = json.loads(printed)

    steps = config["function_matching"]
    if not keep_name_matching:
        steps = [s for s in steps if "name hash" not in s["name"]]
    present = any(s["name"] == FEATURE_STEP for s in steps)
    if with_feature and not present:
        # Straight after byte-hash matching, which is where bindiff.json puts
        # it: measured best there, both for recall and for the number of
        # previously correct matches it displaces.
        at = next((i for i, s in enumerate(steps)
                   if s["name"] == "function: hash matching"), 0) + 1
        steps.insert(at, {"name": FEATURE_STEP, "confidence": 0.9})
    elif not with_feature:
        steps = [s for s in steps if s["name"] != FEATURE_STEP]
    config["function_matching"] = steps

    destination.write_text(json.dumps(config, indent=1))
    return destination


def _load_producer():
    """Loads the sidecar producer without importing the bindiff package.

    Importing `bindiff` pulls in the Cython extension, which is built against
    IDA's interpreter inside the container -- so on a normal host it will not
    load, and this script has no need of it. The producer and the metadata
    module are pure Python; only protobuf is required.
    """
    import importlib.util
    import types

    package_dir = REPO / "python" / "bindiff"
    # A stub package, so the modules' own "from bindiff._pb import ..." finds
    # the generated bindings without executing bindiff/__init__.py.
    if "bindiff" not in sys.modules:
        stub = types.ModuleType("bindiff")
        stub.__path__ = [str(package_dir)]
        sys.modules["bindiff"] = stub

    loaded = {}
    for name in ("metadata", "metadata_binexport"):
        spec = importlib.util.spec_from_file_location(
            f"bindiff.{name}", package_dir / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        # Registered before execution so metadata_binexport's own
        # "from bindiff.metadata import ..." resolves to the copy just loaded.
        sys.modules[f"bindiff.{name}"] = module
        spec.loader.exec_module(module)
        loaded[name] = module
    return loaded["metadata"], loaded["metadata_binexport"]


def build_sidecars(directory: Path) -> None:
    if str(REPO / "python") not in sys.path:
        sys.path.insert(0, str(REPO / "python"))
    metadata, producer = _load_producer()

    for export in sorted(directory.glob("*.BinExport")):
        metadata.write_sidecar(str(export), producer.build_sidecar(str(export)))


def run_one(bindiff: Path, config: Path, primary: Path, secondary: Path,
            output_dir: Path) -> Path:
    subprocess.run(
        [str(bindiff), "--nologo", "--config", str(config),
         "--primary", str(primary), "--secondary", str(secondary),
         "--output_dir", str(output_dir), "--output_format=bin"],
        capture_output=True, check=True)
    # The engine truncates the output name to a maximum length, so it cannot be
    # predicted from the inputs alone.
    produced = sorted(output_dir.glob("*.BinDiff"))
    if len(produced) != 1:
        raise RuntimeError(f"expected one .BinDiff in {output_dir}, "
                           f"got {[p.name for p in produced]}")
    return produced[0]


def score(truth: dict, matches: dict) -> tuple:
    correct = sum(1 for a, b in truth.items() if matches.get(a) == b)
    wrong = sum(1 for a, b in truth.items() if a in matches and matches[a] != b)
    return correct, wrong, len(truth) - correct - wrong


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bindiff", default=str(REPO / "build/out/bindiff"),
                        help="path to the bindiff CLI (default: build/out/bindiff)")
    parser.add_argument("--sidecars", action="store_true",
                        help="build metadata sidecars before diffing")
    parser.add_argument("--compare", action="store_true",
                        help="run with and without the import feature and "
                             "report the difference; implies --sidecars")
    parser.add_argument("--keep-name-matching", action="store_true",
                        help="measure the shipped configuration instead of "
                             "the stripped-binary case")
    args = parser.parse_args(argv)

    bindiff = Path(args.bindiff)
    if not bindiff.is_file():
        parser.error(f"no bindiff binary at {bindiff}; build it first")
    sidecars = args.sidecars or args.compare

    fixtures_root = REPO / "fixtures"
    totals = {}
    with tempfile.TemporaryDirectory() as scratch_name:
        scratch = Path(scratch_name)
        variants = [("without", False), ("with", True)] if args.compare \
            else [("result", sidecars)]

        results = {}
        for label, use_feature in variants:
            configuration = write_config(
                scratch / f"config-{label}.json", bindiff,
                args.keep_name_matching, use_feature and sidecars)
            per_pair = {}
            for name, primary_rel, secondary_rel, truth_rel in FIXTURES:
                work = scratch / f"{label}-{name}"
                work.mkdir(parents=True)
                local = []
                for relative in (primary_rel, secondary_rel):
                    source = fixtures_root / relative
                    if not source.is_file():
                        break
                    destination = work / source.name
                    # Symlinked so a sidecar lands here rather than in the
                    # checked-in fixtures, without copying the export.
                    destination.symlink_to(source)
                    local.append(destination)
                if len(local) != 2:
                    print(f"  skipping {name}: fixture missing", file=sys.stderr)
                    continue
                if sidecars and use_feature:
                    build_sidecars(work)
                database = run_one(bindiff, configuration, local[0], local[1],
                                   work)
                per_pair[name] = (read_truth(fixtures_root / truth_rel),
                                  read_matches(database),
                                  read_attributed(database, FEATURE_STEP))
            results[label] = per_pair

        if args.compare:
            print(f"{'pair':<10} {'truth':>6} | {'base':>6} {'wrong':>6} | "
                  f"{'feat':>6} {'wrong':>6} | {'delta':>6} {'displaced':>10}")
            grand = [0, 0, 0, 0, 0, 0]
            for name, _, _, _ in FIXTURES:
                if name not in results["with"]:
                    continue
                truth, base_m, _ = results["without"][name]
                _, feat_m, _ = results["with"][name]
                bc, bw, _ = score(truth, base_m)
                fc, fw, _ = score(truth, feat_m)
                displaced = sum(1 for a, b in truth.items()
                                if base_m.get(a) == b and feat_m.get(a) != b)
                grand = [g + v for g, v in zip(
                    grand, [len(truth), bc, bw, fc, fw, displaced])]
                print(f"{name:<10} {len(truth):>6} | {bc:>6} {bw:>6} | "
                      f"{fc:>6} {fw:>6} | {fc - bc:>+6} {displaced:>10}")
            total, bc, bw, fc, fw, displaced = grand
            print("-" * 76)
            print(f"{'TOTAL':<10} {total:>6} | {bc:>6} {bw:>6} | {fc:>6} "
                  f"{fw:>6} | {fc - bc:>+6} {displaced:>10}")
            print(f"\nrecall {bc / total:.1%} -> {fc / total:.1%}"
                  f"   ({fc - bc:+d} correct, {fw - bw:+d} wrong, "
                  f"{displaced} displaced)")

            # The feature's own precision, separate from its knock-on effects.
            proposed = agreed = 0
            for name in results["with"]:
                truth, _, attributed = results["with"][name]
                covered = {a: b for a, b in attributed.items() if a in truth}
                proposed += len(covered)
                agreed += sum(1 for a, b in covered.items() if truth[a] == b)
            if proposed:
                print(f"\n{FEATURE_STEP}: {agreed}/{proposed} of its own "
                      f"matches agree with ground truth "
                      f"({agreed / proposed:.1%})")
        else:
            print(f"{'pair':<10} {'truth':>6} {'correct':>8} {'wrong':>6} "
                  f"{'missed':>7} {'recall':>8}")
            total = correct = wrong = missed = 0
            for name, _, _, _ in FIXTURES:
                if name not in results["result"]:
                    continue
                truth, matches, _ = results["result"][name]
                c, w, m = score(truth, matches)
                total += len(truth); correct += c; wrong += w; missed += m
                print(f"{name:<10} {len(truth):>6} {c:>8} {w:>6} {m:>7} "
                      f"{c / len(truth):>7.1%}")
            print("-" * 50)
            print(f"{'TOTAL':<10} {total:>6} {correct:>8} {wrong:>6} "
                  f"{missed:>7} {correct / total:>7.1%}")
            print(f"\nheadroom: {total - correct} of {total} truth pairs are "
                  f"wrong or missed ({(total - correct) / total:.1%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
