#!/usr/bin/env python3
"""Measures sidecar features against real programs, not a generated corpus.

`python/tests/fixture_builder.py` generates C with 48 deliberately distinct
signatures, which makes a prototype feature look good by construction: it was
built to prove the plumbing works, and it cannot say whether the feature earns
its place on code somebody actually wrote. This runs the same measurement over
pairs of real binaries.

Ground truth comes from symbol names, so both sides must be unstripped builds
of the same program -- two optimisation levels, or two versions. Library,
imported and thunk functions are excluded: they are shared code whose matching
says nothing about the algorithms under test.

    tools/scripts/measure_real_corpus.py --pairs pairs.json --work build/corpus

`pairs.json` is a list of {"name", "primary", "secondary"} with paths to the
binaries. Everything else -- exporting, sidecars, configuration, scoring --
happens here.

Must run where idalib and BinExport's IDA plugin are both available, because
prototype/v1 and frame/v1 come from IDA's type and frame information rather
than from the BinExport proto:

    ./tools/scripts/run_tests_docker.sh exec --with-binexport -- \
        /app/ida/.venv/bin/python3 /work/tools/scripts/measure_real_corpus.py ...
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

REPO = Path(__file__).resolve().parents[2]

# Every feature is named the same way in the config: the step is created on
# demand from its name, so measuring a new one needs no engine change.
STEP_PREFIX = "function: feature "

# Where a feature step goes in the order, named by the step it follows.
# Straight after byte-hash matching is where bindiff.json puts imports/v1, and
# where it measured best -- both for recall and for how many previously correct
# matches it displaced.
AFTER_STEP = "function: hash matching"
STEP_CONFIDENCE = 0.9


@dataclass
class Pair:
    name: str
    primary: Path
    secondary: Path
    # The unstripped originals, when `primary`/`secondary` are stripped copies.
    # Exported only to read the symbol table; never diffed. Stripping removes
    # non-allocated sections, so addresses are identical in both.
    primary_symbols: Optional[Path] = None
    secondary_symbols: Optional[Path] = None
    primary_export: Optional[Path] = None
    secondary_export: Optional[Path] = None
    primary_ida: object = None
    secondary_ida: object = None
    truth: Dict[int, int] = field(default_factory=dict)
    dropped: int = 0
    informative: Dict[str, int] = field(default_factory=dict)


class Unavailable(Exception):
    """Something the measurement needs is not installed."""


# -- exporting -------------------------------------------------------------

def export_with_metadata(binary: Path, output: Path):
    """Exports `binary` and captures IDA's view of it in the same session.

    One session for both, because the export is the only moment the database is
    open and analysed. Re-opening it to collect types would double the cost of
    the slowest step, and on a corpus of this size that is the whole runtime.

    Both halves are cached beside the export. Analysing this corpus takes
    minutes per run, and a measurement nobody can afford to repeat is a
    measurement that stops being checked.
    """
    from bindiff.metadata import _load_pb2, from_proto, to_proto

    cache = Path(str(output) + ".idameta")
    if output.is_file() and cache.is_file():
        proto = _load_pb2().BinaryMetadata()
        proto.ParseFromString(cache.read_bytes())
        return output, from_proto(proto)

    from bindiff.headless import _invoke_binexport, export
    from bindiff.metadata_ida import IdaSource, build_metadata

    captured = {}

    def exporter(path: str) -> None:
        _invoke_binexport(path)
        captured["metadata"] = build_metadata(IdaSource())

    result = export(str(binary), str(output), exporter=exporter)
    if not result.ok:
        raise Unavailable(f"exporting {binary.name} failed: {result.message}")
    metadata = captured.get("metadata")
    if metadata is not None:
        cache.write_bytes(to_proto(metadata).SerializeToString())
    return output, metadata


def _stripped_copy_is_current(source: Path, destination: Path) -> bool:
    return (destination.is_file()
            and destination.stat().st_mtime >= source.stat().st_mtime)


# GNU strip only handles the targets its binutils was built for, and the test
# image is aarch64 while this corpus is x86-64 -- so the native tool refuses
# the file outright. The cross-targeted one is tried first for that reason.
_STRIP_TOOLS = ("x86_64-linux-gnu-strip", "llvm-strip", "strip")


def find_strip_tool() -> str:
    import shutil

    for tool in _STRIP_TOOLS:
        if shutil.which(tool):
            return tool
    raise Unavailable(
        f"none of {', '.join(_STRIP_TOOLS)} is installed; install "
        f"binutils-x86-64-linux-gnu to measure the stripped case")


def _strip(tool: str, binary: Path, destination: Path) -> Path:
    """A copy with the symbol table and debug sections removed.

    Which is the whole point of the exercise: an unstripped build hands IDA
    exact prototypes out of DWARF, and a feature measured against those is
    measuring the debug info rather than the matcher.
    """
    if _stripped_copy_is_current(binary, destination):
        return destination
    result = subprocess.run([tool, "--strip-all", "-o", str(destination),
                             str(binary)], capture_output=True, text=True)
    if result.returncode != 0:
        raise Unavailable(
            f"{tool} could not strip {binary.name}: {result.stderr.strip()}")
    return destination


def named_functions(binexport: Path) -> Dict[str, int]:
    """Real-named, non-library functions in an export, keyed by name.

    Library, imported and thunk functions are dropped: they are the same code
    on both sides regardless of how the program was built, so matching them
    measures nothing. A name appearing twice is dropped as well -- it would
    make the pairing ambiguous, and an ambiguous truth entry is worse than a
    missing one because it scores a correct match as wrong.
    """
    from bindiff.binexport import read_functions

    by_name: Dict[str, int] = {}
    for function in read_functions(str(binexport)):
        if function.is_library or not function.has_real_name:
            continue
        name = function.best_name
        by_name[name] = -1 if name in by_name else function.address
    return {name: address for name, address in by_name.items() if address >= 0}


def function_addresses(binexport: Path) -> set:
    from bindiff.binexport import read_functions

    return {f.address for f in read_functions(str(binexport))}


def informative_prototypes(metadata) -> int:
    """How many functions carry a prototype worth matching on.

    Reported because it is the number that decides whether a prototype feature
    is measuring the matcher or measuring DWARF: an unstripped build hands IDA
    exact signatures, and a feature that looks strong only there is a feature
    that will not help on the binaries anybody actually needs to diff.
    """
    if metadata is None:
        return 0
    return sum(1 for function in metadata.functions
               for feature in function.features
               if feature.name == "prototype/v1")


def prepare(pair: Pair, work: Path) -> Pair:
    work.mkdir(parents=True, exist_ok=True)
    pair.primary_export, pair.primary_ida = export_with_metadata(
        pair.primary, work / f"{pair.name}.primary.BinExport")
    pair.secondary_export, pair.secondary_ida = export_with_metadata(
        pair.secondary, work / f"{pair.name}.secondary.BinExport")
    pair.informative = {
        "primary": informative_prototypes(pair.primary_ida),
        "secondary": informative_prototypes(pair.secondary_ida),
    }

    if pair.primary_symbols is None:
        truth_primary, truth_secondary = pair.primary_export, pair.secondary_export
    else:
        # Exported only for its symbol table. The same file with .symtab and
        # .debug_* removed keeps every allocated section at the same address,
        # so a truth pair read here is valid against the stripped exports.
        truth_primary, _ = export_with_metadata(
            pair.primary_symbols, work / f"{pair.name}.primary.symbols.BinExport")
        truth_secondary, _ = export_with_metadata(
            pair.secondary_symbols,
            work / f"{pair.name}.secondary.symbols.BinExport")

    primary_names = named_functions(truth_primary)
    secondary_names = named_functions(truth_secondary)
    shared = sorted(set(primary_names) & set(secondary_names))
    if not shared:
        raise Unavailable(
            f"{pair.name}: no name is present in both exports "
            f"({len(primary_names)} and {len(secondary_names)} named); the "
            f"builds are stripped or are not the same program")
    truth = {primary_names[n]: secondary_names[n] for n in shared}

    # A truth pair whose function the disassembler did not find in the stripped
    # build is not a matching failure -- nothing can match a function that is
    # not there. Counted and dropped, so the recall reported is the matcher's.
    present_primary = function_addresses(pair.primary_export)
    present_secondary = function_addresses(pair.secondary_export)
    pair.truth = {a: b for a, b in truth.items()
                  if a in present_primary and b in present_secondary}
    pair.dropped = len(truth) - len(pair.truth)
    if not pair.truth:
        raise Unavailable(
            f"{pair.name}: none of the {len(truth)} truth pairs survive in the "
            f"exports actually being diffed")
    return pair


# -- sidecars --------------------------------------------------------------

def write_sidecars(pair: Pair, features: List[str], model=None) -> None:
    """Writes each side's sidecar holding exactly `features`.

    Rewritten per configuration rather than written once and filtered by the
    config, so a feature that is not being measured is not merely unused but
    absent -- otherwise a step disabled in the config could still be reached
    through some other path and quietly join the result.
    """
    import copy

    from bindiff.metadata import sidecar_path_for, write_sidecar
    from bindiff.metadata_binexport import build_sidecar
    from bindiff.asm2vec import FEATURE_ASM2VEC
    from bindiff.metadata_embedding import (FEATURE_MNEMONIC_HISTOGRAM,
                                            build_sidecar as build_embedding)
    from bindiff.metadata_ida import merge

    for export, ida_metadata in ((pair.primary_export, pair.primary_ida),
                                 (pair.secondary_export, pair.secondary_ida)):
        if not features:
            Path(sidecar_path_for(str(export))).unlink(missing_ok=True)
            continue

        # Always built, even when imports/v1 is not being measured, because it
        # is what carries executable_id -- the engine refuses a sidecar whose
        # id disagrees with the export, and the IDA producer does not set one.
        # Its features are then dropped if they were not asked for.
        metadata = build_sidecar(str(export))
        if "imports/v1" not in features:
            metadata.functions = []

        if FEATURE_MNEMONIC_HISTOGRAM in features:
            # Produced from the .BinExport like the import sets, but a separate
            # producer: it walks the whole instruction table, which the import
            # producer has no reason to pay for.
            merge(metadata, build_embedding(str(export)))

        if FEATURE_ASM2VEC in features:
            if model is None:
                raise Unavailable(
                    f"{FEATURE_ASM2VEC} needs a trained model; pass "
                    f"--asm2vec-model. Training per binary would put the two "
                    f"sides in unrelated spaces")
            from bindiff.asm2vec import build_sidecar as build_learned

            merge(metadata, build_learned(str(export), model))

        wanted = [f for f in features
                  if f not in ("imports/v1", FEATURE_MNEMONIC_HISTOGRAM,
                               FEATURE_ASM2VEC)]
        if wanted and ida_metadata is not None:
            # Deep-copied because merge() appends by reference and the captured
            # metadata is reused for every configuration in the run.
            extra = copy.deepcopy(ida_metadata)
            for function in extra.functions:
                function.features = [feature for feature in function.features
                                     if feature.name in wanted]
            extra.functions = [f for f in extra.functions if f.features]
            merge(metadata, extra)
        write_sidecar(str(export), metadata)


# -- running ---------------------------------------------------------------

def write_config(destination: Path, bindiff: Path, features: List[str],
                 keep_name_matching: bool, drop_steps=()) -> Path:
    """The binary's own effective configuration, with the steps under test.

    Read from --print_config rather than bindiff.json so the measurement
    reflects what this build actually does, including any per-user
    configuration that would otherwise change the result without saying so.
    """
    printed = subprocess.run([str(bindiff), "--print_config", "--nologo"],
                             capture_output=True, text=True,
                             check=True).stdout
    config = json.loads(printed)

    steps = config["function_matching"]
    if not keep_name_matching:
        # Both sides carry full symbols -- that is what makes the ground truth
        # possible -- so with name matching on, almost everything matches by
        # name and the measurement says nothing about the algorithms.
        steps = [s for s in steps if "name hash" not in s["name"]]
    steps = [s for s in steps if not s["name"].startswith(STEP_PREFIX)]
    if drop_steps:
        # Removed rather than set to zero confidence: a confidence of zero
        # still runs the step and still commits its matches, which is exactly
        # how the weakest steps came to produce most of the wrong ones.
        steps = [s for s in steps if s["name"] not in drop_steps]

    at = next((i for i, s in enumerate(steps) if s["name"] == AFTER_STEP),
              0) + 1
    for offset, feature in enumerate(features):
        steps.insert(at + offset, {"name": STEP_PREFIX + feature,
                                   "confidence": STEP_CONFIDENCE})
    config["function_matching"] = steps

    destination.write_text(json.dumps(config, indent=1))
    return destination


def to_unsigned(value: int) -> int:
    """Addresses are stored as signed BIGINTs in a .BinDiff."""
    return value + (1 << 64) if value < 0 else value


def read_matches(database: Path) -> Dict[int, int]:
    import sqlite3

    with sqlite3.connect(str(database)) as connection:
        rows = connection.execute("SELECT address1, address2 FROM function")
        return {to_unsigned(a): to_unsigned(b) for a, b in rows}


def read_attributed(database: Path, step: str) -> Dict[int, int]:
    """The matches one step is credited with, so its own precision is visible
    separately from what it changed downstream."""
    import sqlite3

    with sqlite3.connect(str(database)) as connection:
        row = connection.execute(
            "SELECT id FROM functionalgorithm WHERE name = ?",
            (step,)).fetchone()
        if row is None:
            return {}
        rows = connection.execute(
            "SELECT address1, address2 FROM function WHERE algorithm = ?",
            (row[0],))
        return {to_unsigned(a): to_unsigned(b) for a, b in rows}


def run_one(bindiff: Path, config: Path, pair: Pair, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in output_dir.glob("*.BinDiff"):
        stale.unlink()
    subprocess.run(
        [str(bindiff), "--nologo", "--config", str(config),
         "--primary", str(pair.primary_export),
         "--secondary", str(pair.secondary_export),
         "--output_dir", str(output_dir), "--output_format=bin"],
        capture_output=True, check=True)
    produced = sorted(output_dir.glob("*.BinDiff"))
    if len(produced) != 1:
        raise RuntimeError(f"expected one .BinDiff in {output_dir}, "
                           f"got {[p.name for p in produced]}")
    return produced[0]


def score(truth: Dict[int, int], matches: Dict[int, int]):
    correct = sum(1 for a, b in truth.items() if matches.get(a) == b)
    wrong = sum(1 for a, b in truth.items() if a in matches and matches[a] != b)
    return correct, wrong, len(truth) - correct - wrong


# -- reporting -------------------------------------------------------------

def percentage(part: int, whole: int) -> float:
    return 100.0 * part / whole if whole else 0.0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pairs", required=True,
                        help="JSON list of {name, primary, secondary}")
    parser.add_argument("--work", default=str(REPO / "build/corpus"),
                        help="where exports and results are written")
    parser.add_argument("--bindiff", default=str(REPO / "build/out/bindiff"))
    parser.add_argument("--features", default="imports/v1,prototype/v1,frame/v1",
                        help="comma-separated features to measure, each on its "
                             "own and then all together")
    parser.add_argument("--base-features", default="",
                        help="features present in every configuration, "
                             "including the baseline. Use the shipped set to "
                             "ask what a candidate adds to what is already "
                             "enabled, which is a different question from what "
                             "it adds to nothing")
    parser.add_argument("--keep-name-matching", action="store_true")
    parser.add_argument("--drop-steps", default="",
                        help="comma-separated step names to remove from the "
                             "configuration entirely")
    parser.add_argument("--asm2vec-model",
                        help="frozen model for the asm2vec/v1 feature. It has "
                             "to be one model for both sides: two separately "
                             "trained ones put the binaries in unrelated "
                             "spaces and every cosine between them is "
                             "meaningless while still looking like a number")
    parser.add_argument("--strip", action="store_true",
                        help="diff stripped copies, taking ground truth from "
                             "the originals. This is the case that decides "
                             "whether a feature is enabled by default: an "
                             "unstripped build hands IDA exact prototypes from "
                             "DWARF, which no real target provides")
    parser.add_argument("--json", help="write the raw numbers here")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(REPO / "python"))

    work = Path(args.work)
    bindiff = Path(args.bindiff)
    if not bindiff.is_file():
        print(f"no bindiff CLI at {bindiff}", file=sys.stderr)
        return 2

    features = [f.strip() for f in args.features.split(",") if f.strip()]
    drop_steps = {s.strip() for s in args.drop_steps.split(",") if s.strip()}
    if drop_steps:
        print(f"[dropped] {len(drop_steps)} steps: "
              f"{', '.join(sorted(drop_steps))}")

    model = None
    if args.asm2vec_model:
        from bindiff.asm2vec import Asm2VecModel

        model = Asm2VecModel.load(args.asm2vec_model)
        print(f"[model] {args.asm2vec_model}: {len(model.tokens)} tokens x "
              f"{model.dimension} dimensions, trained on "
              f"{len(model.trained_on)} binaries", flush=True)
    # Baseline first so every later number is a delta against it, then one
    # configuration per feature, then all of them -- a feature can be worth
    # something alone and nothing beside another that already found the same
    # functions.
    base = [f.strip() for f in args.base_features.split(",") if f.strip()]
    if base:
        print(f"[base] every configuration also carries: {', '.join(base)}")
    configurations = [("baseline", list(base))]
    configurations += [(f, base + [f]) for f in features if f not in base]
    if len(features) > 1:
        configurations.append(("all", base + [f for f in features
                                              if f not in base]))

    strip_tool = find_strip_tool() if args.strip else ""
    pairs = []
    for entry in json.loads(Path(args.pairs).read_text()):
        primary, secondary = Path(entry["primary"]), Path(entry["secondary"])
        pair = Pair(name=entry["name"], primary=primary, secondary=secondary)
        if args.strip:
            stripped = work / entry["name"]
            stripped.mkdir(parents=True, exist_ok=True)
            pair.primary_symbols, pair.secondary_symbols = primary, secondary
            pair.primary = _strip(strip_tool, primary,
                                  stripped / "primary.stripped")
            pair.secondary = _strip(strip_tool, secondary,
                                    stripped / "secondary.stripped")
        try:
            pairs.append(prepare(pair, work / pair.name))
            print(f"[prepared] {pair.name}: {len(pair.truth)} truth pairs "
                  f"({pair.dropped} not found by the disassembler), "
                  f"prototypes {pair.informative['primary']}/"
                  f"{pair.informative['secondary']}", flush=True)
        except Unavailable as exc:
            print(f"[skipped] {exc}", file=sys.stderr, flush=True)
    if not pairs:
        print("no usable pairs", file=sys.stderr)
        return 1

    results = {}
    for label, wanted in configurations:
        totals = {"correct": 0, "wrong": 0, "missing": 0, "truth": 0,
                  "own_correct": 0, "own_total": 0}
        per_pair = {}
        for pair in pairs:
            write_sidecars(pair, wanted, model)
            config = write_config(work / f"config-{pair.name}.json", bindiff,
                                  wanted, args.keep_name_matching,
                                  drop_steps=drop_steps)
            database = run_one(bindiff, config, pair,
                               work / pair.name / label)
            matches = read_matches(database)
            correct, wrong, missing = score(pair.truth, matches)

            own_correct = own_total = 0
            for feature in [f for f in wanted if f not in base] or wanted:
                attributed = read_attributed(database, STEP_PREFIX + feature)
                own_total += len(attributed)
                own_correct += sum(1 for a, b in attributed.items()
                                   if pair.truth.get(a) == b)

            per_pair[pair.name] = {
                "correct": correct, "wrong": wrong, "missing": missing,
                "truth": len(pair.truth), "own_correct": own_correct,
                "own_total": own_total, "matches": len(matches)}
            totals["correct"] += correct
            totals["wrong"] += wrong
            totals["missing"] += missing
            totals["truth"] += len(pair.truth)
            totals["own_correct"] += own_correct
            totals["own_total"] += own_total
        results[label] = {"totals": totals, "pairs": per_pair}
        print(f"[measured] {label}: {totals['correct']}/{totals['truth']}",
              flush=True)

    base = results["baseline"]["totals"]
    print(f"\n{len(pairs)} pairs, {base['truth']} ground-truth function pairs")
    print(f"{'configuration':<18} {'recall':>16} {'delta':>8} "
          f"{'wrong':>7} {'own precision':>16}")
    for label, _ in configurations:
        totals = results[label]["totals"]
        recall = percentage(totals["correct"], totals["truth"])
        delta = totals["correct"] - base["correct"]
        own = (f"{totals['own_correct']}/{totals['own_total']} "
               f"{percentage(totals['own_correct'], totals['own_total']):.0f}%"
               if totals["own_total"] else "-")
        print(f"{label:<18} {totals['correct']:>6}/{totals['truth']:<5} "
              f"{recall:5.1f}% {delta:+8d} {totals['wrong']:>7} {own:>16}")

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
        print(f"\nraw numbers written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
