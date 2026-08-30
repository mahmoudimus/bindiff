#!/usr/bin/env python3
"""Precision and recall of an embedding feature, by cosine threshold.

The engine's threshold is a compile-time constant, so finding the right value
by rebuilding and re-diffing costs a full measurement per candidate. This
applies the same rule the engine applies -- mutual best match above a threshold
-- directly to the vectors, which takes seconds and predicts the engine's own
numbers closely enough to choose with.

    tools/scripts/sweep_embedding_threshold.py --pairs pairs.json \\
        --work build/corpus-stripped --producer histogram

**A threshold is not transferable between features.** A set feature scores
unrelated functions at zero because they share no keys; a dense embedding
returns a number for every pair, and a non-negative one cannot score below 0.5
after the [-1, 1] mapping. Reusing the Jaccard threshold for the first
embedding put it at 70% precision and made the combined result worse. Sweep
every new feature.

The separation line is the one to read first: the gap between what true pairs
score and what random pairs score. A feature with a small gap cannot be fixed
by choosing a threshold well.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List

REPO = Path(__file__).resolve().parents[2]

DEFAULT_THRESHOLDS = (0.60, 0.70, 0.80, 0.85, 0.90, 0.95, 0.98, 0.995)


def named_functions(binexport: Path) -> Dict[str, int]:
    from bindiff.binexport import read_functions

    by_name: Dict[str, int] = {}
    for function in read_functions(str(binexport)):
        if function.is_library or not function.has_real_name:
            continue
        by_name[function.best_name] = (
            -1 if function.best_name in by_name else function.address)
    return {n: a for n, a in by_name.items() if a >= 0}


def embed_histogram(export: Path, model) -> Dict[int, List[float]]:
    from bindiff.metadata_embedding import embed, function_mnemonics

    return embed(function_mnemonics(str(export)))


def embed_asm2vec(export: Path, model) -> Dict[int, List[float]]:
    from bindiff.asm2vec import infer, read_functions

    if model is None:
        raise SystemExit("--producer asm2vec needs --model")
    return infer(model, read_functions(str(export)))


PRODUCERS = {"histogram": embed_histogram, "asm2vec": embed_asm2vec}


def mutual_best(left, right, threshold, cosine):
    """The engine's rule: best on both sides, strictly, above the threshold."""
    taken = []
    forward = {}
    for a, vector in left.items():
        scored = sorted(((cosine(vector, other), b)
                         for b, other in right.items()), reverse=True)
        forward[a] = scored[:2]
    backward = {}
    for b, vector in right.items():
        scored = sorted(((cosine(vector, other), a)
                         for a, other in left.items()), reverse=True)
        backward[b] = scored[:2]

    for a, scored in forward.items():
        if not scored or scored[0][0] < threshold:
            continue
        if len(scored) > 1 and scored[1][0] >= scored[0][0]:
            continue  # tied: the engine takes nothing from an ambiguous best
        b = scored[0][1]
        back = backward[b]
        if not back or back[0][0] < threshold or back[0][1] != a:
            continue
        if len(back) > 1 and back[1][0] >= back[0][0]:
            continue
        taken.append((a, b))
    return taken


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pairs", required=True)
    parser.add_argument("--work", default=str(REPO / "build/corpus-stripped"))
    parser.add_argument("--producer", choices=sorted(PRODUCERS),
                        default="histogram")
    parser.add_argument("--model", help="model file, for a learned producer")
    parser.add_argument("--thresholds", default=None,
                        help="comma separated; defaults to a spread")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(REPO / "python"))
    from bindiff.metadata_embedding import cosine

    model = None
    if args.model:
        from bindiff.asm2vec import Asm2VecModel

        model = Asm2VecModel.load(args.model)
        print(f"[model] {len(model.tokens)} tokens x {model.dimension} "
              f"dimensions, trained on {len(model.trained_on)} binaries")

    thresholds = ([float(t) for t in args.thresholds.split(",")]
                  if args.thresholds else list(DEFAULT_THRESHOLDS))
    produce = PRODUCERS[args.producer]
    work = Path(args.work)

    totals = {t: [0, 0] for t in thresholds}
    truth_total = 0
    true_scores: List[float] = []
    random_scores: List[float] = []
    rng = random.Random(20260829)

    for entry in json.loads(Path(args.pairs).read_text()):
        name = entry["name"]
        base = work / name
        started = time.monotonic()
        left = produce(base / f"{name}.primary.BinExport", model)
        right = produce(base / f"{name}.secondary.BinExport", model)

        symbols_left = base / f"{name}.primary.symbols.BinExport"
        symbols_right = base / f"{name}.secondary.symbols.BinExport"
        if not symbols_left.is_file():
            symbols_left = base / f"{name}.primary.BinExport"
            symbols_right = base / f"{name}.secondary.BinExport"
        by_name_left = named_functions(symbols_left)
        by_name_right = named_functions(symbols_right)
        truth = {by_name_left[n]: by_name_right[n]
                 for n in set(by_name_left) & set(by_name_right)
                 if by_name_left[n] in left and by_name_right[n] in right}
        truth_total += len(truth)

        for a, b in truth.items():
            true_scores.append(cosine(left[a], right[b]))
        candidates = list(right)
        for a in list(left)[:300]:
            random_scores.append(
                cosine(left[a], right[rng.choice(candidates)]))

        for threshold in thresholds:
            for a, b in mutual_best(left, right, threshold, cosine):
                totals[threshold][0] += 1
                if truth.get(a) == b:
                    totals[threshold][1] += 1
        print(f"  {name}: {len(left)}+{len(right)} embedded, "
              f"{len(truth)} truth pairs, {time.monotonic() - started:.0f}s",
              flush=True)

    if not truth_total:
        print("no truth pairs", file=sys.stderr)
        return 1

    true_median = statistics.median(true_scores)
    random_median = statistics.median(random_scores)
    print(f"\n{truth_total} truth pairs where both sides carry a vector")
    print(f"  true pairs   median {true_median:.3f}")
    print(f"  random pairs median {random_median:.3f}")
    print(f"  separation          {true_median - random_median:.3f}"
          "   <- a small gap is not a threshold problem")

    print(f"\n{'threshold':>10}{'taken':>8}{'correct':>9}{'precision':>11}"
          f"{'recall':>9}")
    for threshold in thresholds:
        taken, correct = totals[threshold]
        precision = 100.0 * correct / taken if taken else 0.0
        print(f"{threshold:>10.3f}{taken:>8}{correct:>9}{precision:>10.1f}%"
              f"{100.0 * correct / truth_total:>8.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
