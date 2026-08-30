#!/usr/bin/env python3
"""Where the recall that is still missing has gone, and what could recover it.

`measure_real_corpus.py` says how much a configuration matches. This says what
is left: for every ground-truth pair the differ did not match, whether the
information needed to match it was available and merely unused.

The question it exists to answer is whether a *global* graph alignment -- what
IsoRank does, and what BinSlayer's Hungarian pass does over BinDiff's leftovers
-- has anything to work with here, or whether the misses are isolated functions
no graph method can reach.

    tools/scripts/analyze_residual.py --pairs pairs.json --work build/corpus \\
        --configuration all

Two conditions have to hold together for a later pass to recover a miss:

  evidence   at least one of the function's call-graph neighbours is already
             matched to a neighbour of its counterpart. This is what IsoRank
             propagates and what a Hungarian pass scores; without it no graph
             method reaches the function at all.
  free       the correct counterpart is still unclaimed. If the differ already
             spent it on some other function, a pass that only fills gaps
             cannot have it back without undoing that match.

**Report the cross-tabulation, never the two margins.** Reading them
separately is what made this tool mislead its first user: on the nine-pair
corpus 129 misses had evidence and 104 had a free counterpart, which looks
like well over a hundred recoverable pairs -- and the overlap is *exactly
zero*. Where there is evidence, greedy propagation already used it and took
the counterpart; where the counterpart is free, the function is isolated and
there is nothing to reason from. A leftovers-only global assignment therefore
has a ceiling of zero here, and measuring one confirmed it: 8 pairs taken
across nine binaries, none correct.

The implication is not that global assignment is useless but that it cannot be
a *last* step. To help it would have to revise matches other steps committed,
which is what BinSlayer does -- it scores everything rather than accepting the
greedy result as fixed.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Set, Tuple

REPO = Path(__file__).resolve().parents[2]


def to_unsigned(value: int) -> int:
    return value + (1 << 64) if value < 0 else value


def read_call_graph(binexport: Path) -> Tuple[Dict[int, Set[int]], Set[int]]:
    """Undirected call-graph neighbours by address, and every function address.

    Undirected on purpose: a caller is as much evidence for a function's
    identity as a callee, and IsoRank's propagation is symmetric.
    """
    sys.path.insert(0, str(REPO / "python"))
    from bindiff._pb import binexport2_pb2

    proto = binexport2_pb2.BinExport2()
    proto.ParseFromString(binexport.read_bytes())

    addresses = [vertex.address for vertex in proto.call_graph.vertex]
    neighbours: Dict[int, Set[int]] = defaultdict(set)
    for edge in proto.call_graph.edge:
        source = addresses[edge.source_vertex_index]
        target = addresses[edge.target_vertex_index]
        neighbours[source].add(target)
        neighbours[target].add(source)
    return neighbours, set(addresses)


def read_matches(database: Path) -> Dict[int, int]:
    with sqlite3.connect(str(database)) as connection:
        return {to_unsigned(a): to_unsigned(b) for a, b in
                connection.execute("SELECT address1, address2 FROM function")}


def named_functions(binexport: Path) -> Dict[str, int]:
    sys.path.insert(0, str(REPO / "python"))
    from bindiff.binexport import read_functions

    by_name: Dict[str, int] = {}
    for function in read_functions(str(binexport)):
        if function.is_library or not function.has_real_name:
            continue
        name = function.best_name
        by_name[name] = -1 if name in by_name else function.address
    return {n: a for n, a in by_name.items() if a >= 0}


def analyse(name: str, work: Path, configuration: str) -> dict:
    primary = work / name / f"{name}.primary.BinExport"
    secondary = work / name / f"{name}.secondary.BinExport"
    symbols_primary = work / name / f"{name}.primary.symbols.BinExport"
    symbols_secondary = work / name / f"{name}.secondary.symbols.BinExport"
    if not symbols_primary.is_file():
        symbols_primary, symbols_secondary = primary, secondary

    results = sorted((work / name / configuration).glob("*.BinDiff"))
    if len(results) != 1:
        raise FileNotFoundError(
            f"expected one .BinDiff in {work / name / configuration}")

    matches = read_matches(results[0])
    primary_neighbours, primary_addresses = read_call_graph(primary)
    secondary_neighbours, secondary_addresses = read_call_graph(secondary)

    left = named_functions(symbols_primary)
    right = named_functions(symbols_secondary)
    truth = {left[n]: right[n] for n in sorted(set(left) & set(right))
             if left[n] in primary_addresses and right[n] in secondary_addresses}

    # Addresses the differ has already spent. A later pass cannot use one
    # without taking it away from the match that holds it.
    claimed_secondary = set(matches.values())

    correct = {a for a, b in truth.items() if matches.get(a) == b}
    wrong = {a for a, b in truth.items()
             if a in matches and matches[a] != b}
    missed = [a for a in truth if a not in matches]

    # The evidence IsoRank would propagate: a neighbour pair already agreed on.
    def supporting(a: int, b: int) -> int:
        partners = {matches[n] for n in primary_neighbours.get(a, ())
                    if n in matches}
        return len(partners & secondary_neighbours.get(b, set()))

    unmatched_secondary = [b for b in secondary_addresses
                           if b not in claimed_secondary]
    # Precomputed once: for each unmatched candidate, which already-agreed
    # partners it neighbours. Comparing that set is what a global assignment
    # would be scoring.
    candidate_support = {}
    for b in unmatched_secondary:
        candidate_support[b] = secondary_neighbours.get(b, set())

    buckets = {"no evidence": 0, "unique": 0, "contested": 0}
    # The cross-tabulation, which is the number that decides anything. Keyed
    # "evidence,free" so the margins can still be summed but never reported on
    # their own.
    cross = {"yes,yes": 0, "yes,no": 0, "no,yes": 0, "no,no": 0}
    reachable = 0
    support_histogram = defaultdict(int)
    for a in missed:
        b = truth[a]
        free = b not in claimed_secondary
        if free:
            reachable += 1
        support = supporting(a, b)
        support_histogram[min(support, 5)] += 1
        cross[f"{'yes' if support else 'no'},{'yes' if free else 'no'}"] += 1
        if support == 0:
            buckets["no evidence"] += 1
            continue
        partners = {matches[n] for n in primary_neighbours.get(a, ())
                    if n in matches}
        rivals = sum(1 for candidate, adjacency in candidate_support.items()
                     if len(partners & adjacency) >= support)
        buckets["unique" if rivals <= 1 else "contested"] += 1

    return {
        "truth": len(truth), "correct": len(correct), "wrong": len(wrong),
        "missed": len(missed), "reachable": reachable,
        "buckets": buckets, "cross": cross,
        "support": {str(k): v for k, v in sorted(support_histogram.items())},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pairs", required=True)
    parser.add_argument("--work", default=str(REPO / "build/corpus-stripped"))
    parser.add_argument("--configuration", default="all")
    parser.add_argument("--json")
    args = parser.parse_args(argv)

    work = Path(args.work)
    per_pair = {}
    for entry in json.loads(Path(args.pairs).read_text()):
        try:
            per_pair[entry["name"]] = analyse(entry["name"], work,
                                              args.configuration)
        except FileNotFoundError as exc:
            print(f"[skipped] {entry['name']}: {exc}", file=sys.stderr)

    if not per_pair:
        print("nothing to analyse", file=sys.stderr)
        return 1

    total = defaultdict(int)
    buckets = defaultdict(int)
    support = defaultdict(int)
    cross = defaultdict(int)
    for row in per_pair.values():
        for key in ("truth", "correct", "wrong", "missed", "reachable"):
            total[key] += row[key]
        for key, value in row["buckets"].items():
            buckets[key] += value
        for key, value in row["support"].items():
            support[key] += value
        for key, value in row["cross"].items():
            cross[key] += value

    print(f"{len(per_pair)} pairs, configuration {args.configuration!r}\n")
    print(f"  ground truth        {total['truth']}")
    print(f"  matched correctly   {total['correct']} "
          f"({100.0 * total['correct'] / total['truth']:.1f}%)")
    print(f"  matched wrongly     {total['wrong']}")
    print(f"  not matched at all  {total['missed']}")
    print(f"\nof the {total['missed']} unmatched truth pairs, both conditions "
          f"a later pass needs:\n")
    print(f"  {'':<22}{'counterpart free':>18}{'counterpart taken':>19}")
    for evidence, label in (("yes", "neighbour evidence"),
                            ("no", "no evidence")):
        print(f"  {label:<22}{cross[f'{evidence},yes']:>18}"
              f"{cross[f'{evidence},no']:>19}")
    recoverable = cross["yes,yes"]
    print(f"\n  recoverable by a pass that only fills gaps: {recoverable}")
    if recoverable == 0 and total["missed"]:
        print("  -- the two conditions do not co-occur. Where there is "
              "evidence the\n     counterpart is already spent; where it is "
              "free there is no evidence.\n     Such a pass cannot help; it "
              "would have to revise existing matches.")
    for label in ("no evidence", "unique", "contested"):
        count = buckets[label]
        print(f"  {label:<24} {count:>5} "
              f"({100.0 * count / total['missed']:.1f}%)")
    print("\ncorrectly-matched call-graph neighbours shared with the "
          "counterpart:")
    for key in sorted(support, key=int):
        print(f"  {key}{'+' if key == '5' else ' '} neighbours  "
              f"{support[key]:>5}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"pairs": per_pair, "totals": dict(total),
             "buckets": dict(buckets), "cross": dict(cross),
             "support": dict(support)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
