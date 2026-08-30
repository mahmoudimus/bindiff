#!/usr/bin/env python3
"""Trains the frozen asm2vec model the sidecar producer needs.

A learned embedding is only useful across two binaries if both were embedded
against the *same* fixed token vectors. Training per binary would put each side
in its own space and give every pair a confident cosine that means nothing --
the numbers still land in [0, 1], which is what makes it a trap rather than an
error. So the model is trained once, here, and shipped or cached; inference
then fits only the new binary's function vectors.

    tools/scripts/train_asm2vec.py --out model.a2v build/corpus/*.BinExport

Needs PyTorch, which nothing else in this repository does. That is the point of
keeping it here: the producer is the only thing that learns, the differ only
compares floats.

Training on the same binaries a measurement then diffs would be cheating -- the
model would have seen the answer. Train on a corpus held out from whatever is
being measured, and record what went in, which the model file does.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exports", nargs="+",
                        help=".BinExport files to learn the vocabulary from")
    parser.add_argument("--out", required=True, help="model file to write")
    parser.add_argument("--dimension", type=int, default=None)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--walks", type=int, default=None,
                        help="random walks per function")
    parser.add_argument("--walk-length", type=int, default=None)
    parser.add_argument("--min-count", type=int, default=None,
                        help="drop tokens seen fewer times than this")
    parser.add_argument("--seed", type=int, default=20260829)
    args = parser.parse_args(argv)

    sys.path.insert(0, str(REPO / "python"))
    from bindiff import asm2vec

    corpus = []
    sources = []
    for pattern in args.exports:
        path = Path(pattern)
        if not path.is_file():
            print(f"[skipped] {path}: not a file", file=sys.stderr)
            continue
        functions = asm2vec.read_functions(str(path))
        corpus.extend(functions.values())
        sources.append(path.name)
        print(f"[read] {path.name}: {len(functions)} functions", flush=True)

    if not corpus:
        print("no functions to train on", file=sys.stderr)
        return 1

    options = {"seed": args.seed}
    for name, value in (("dimension", args.dimension),
                        ("epochs", args.epochs),
                        ("walks", args.walks),
                        ("length", args.walk_length),
                        ("min_count", args.min_count)):
        if value is not None:
            options[name] = value

    started = time.monotonic()

    def report(state):
        print(f"[epoch {state['epoch']}/{state['epochs']}] "
              f"loss {state['loss']:.4f} over {state['sequences']} sequences "
              f"({time.monotonic() - started:.0f}s)", flush=True)

    model = asm2vec.train(corpus, progress=report, **options)
    model.trained_on = sources
    model.save(args.out)

    print(f"\nwrote {args.out}: {len(model.tokens)} tokens x "
          f"{model.dimension} dimensions, {model.epochs} epochs over "
          f"{len(corpus)} functions from {len(sources)} binaries")
    print(f"took {time.monotonic() - started:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
