"""Measuring the IDA-derived features against a pair built at test time.

The checked-in fixtures cannot exercise these: their .idb files are 32-bit
databases IDA 9.x will not open, so there was no way to run an extractor over
anything with ground truth. fixture_builder compiles one source twice, exports
both through the real BinExport plugin, and derives ground truth from the symbol
names -- which is stronger than the hand-curated .truth files, because a pair is
correct exactly when the names agree.

What is asserted and what is only reported is deliberate. Precision is an
invariant: a matching step that contradicts ground truth is broken, whatever it
does to the totals. Recall is measured and printed, and only guarded against
regression -- claiming a specific improvement for a feature on one generated
corpus would be over-reading a single measurement.

Needs BinExport's IDA plugin:

    ./tools/scripts/run_tests_docker.sh python --with-binexport -- -k generated
"""

from __future__ import annotations

import sqlite3

import pytest

pytestmark = [pytest.mark.requires_extension, pytest.mark.requires_binexport,
              pytest.mark.slow]

IMPORTS_STEP = "function: feature imports/v1"
PROTOTYPE_STEP = "function: feature prototype/v1"
FRAME_STEP = "function: feature frame/v1"


def _to_unsigned(value):
    return value + (1 << 64) if value < 0 else value


def _matches(database):
    connection = sqlite3.connect(str(database))
    try:
        rows = connection.execute(
            "SELECT address1, address2 FROM function").fetchall()
    finally:
        connection.close()
    return {_to_unsigned(a): _to_unsigned(b) for a, b in rows}


def _attributed(database, algorithm):
    """The matches one named algorithm is responsible for."""
    connection = sqlite3.connect(str(database))
    try:
        rows = connection.execute(
            "SELECT f.address1, f.address2 FROM function AS f "
            "JOIN functionalgorithm AS a ON f.algorithm = a.id "
            "WHERE a.name = ?", (algorithm,)).fetchall()
    finally:
        connection.close()
    return {_to_unsigned(a): _to_unsigned(b) for a, b in rows}


def _steps(bindiff_module, extra=()):
    """The default ladder with name matching removed, plus `extra`.

    Name matching is dropped for the same reason the C++ suite drops it: both
    builds carry full symbols, so with it enabled everything matches by name
    and the measurement says nothing about the algorithms.
    """
    steps = [s for s in bindiff_module.get_default_config()["function_matching"]
             if "name hash" not in s["name"]]
    known = {s["name"] for s in steps}
    at = next((i for i, s in enumerate(steps)
               if s["name"] == "function: hash matching"), 0) + 1
    for offset, name in enumerate(extra):
        if name not in known:
            steps.insert(at + offset, {"name": name, "confidence": 0.9})
    return steps


def _score(truth, matches):
    correct = sum(1 for a, b in truth.items() if matches.get(a) == b)
    wrong = sum(1 for a, b in truth.items() if a in matches and matches[a] != b)
    return correct, wrong


class TestTheGeneratedPair:
    def test_ground_truth_is_usable(self, generated_pair):
        assert len(generated_pair.truth) >= 20
        # Derived from names, so every pair is distinct on both sides.
        assert len(set(generated_pair.truth.values())) == len(
            generated_pair.truth)
        assert all(address > 0 for address in generated_pair.truth)

    def test_ida_features_were_captured(self, generated_pair):
        """The point of capturing during export: one IDA session, both
        artefacts. If this is empty the extractors ran but found nothing, which
        is a different failure from not running at all."""
        for metadata in (generated_pair.primary_ida,
                         generated_pair.secondary_ida):
            assert metadata is not None, "no IDA metadata captured at export"
            names = {d["name"] for d in metadata.descriptors()}
            assert names, f"no features at all; warnings: {metadata.warnings}"


@pytest.fixture
def restore_config(bindiff_module):
    yield
    bindiff_module.reset_config()


@pytest.mark.usefixtures("restore_config")
class TestFeatureContribution:
    """Each feature set measured against the same pair, in the same process."""

    @staticmethod
    def _run(bindiff_module, pair, tmp_path, label, steps, *,
             imports, ida_features):
        from fixture_builder import write_sidecars

        write_sidecars(pair, imports=imports, ida_features=ida_features)
        bindiff_module.set_config({"function_matching": steps})
        database = tmp_path / f"{label}.BinDiff"
        assert bindiff_module.diff(str(pair.primary), str(pair.secondary),
                                   str(database)) == 0
        return database

    def test_no_feature_step_ever_contradicts_ground_truth(
            self, bindiff_module, generated_pair, tmp_path, capsys):
        """The invariant. A step that pairs functions the symbols say are
        different is broken, whatever it does to the totals."""
        baseline_db = self._run(
            bindiff_module, generated_pair, tmp_path, "baseline",
            _steps(bindiff_module), imports=False, ida_features=False)
        baseline_correct, baseline_wrong = _score(
            generated_pair.truth, _matches(baseline_db))

        all_db = self._run(
            bindiff_module, generated_pair, tmp_path, "all",
            _steps(bindiff_module, (PROTOTYPE_STEP, FRAME_STEP)),
            imports=True, ida_features=True)
        correct, wrong = _score(generated_pair.truth, _matches(all_db))

        total = len(generated_pair.truth)
        report = [f"\nground truth pairs: {total}",
                  f"baseline:      {baseline_correct} correct, "
                  f"{baseline_wrong} wrong",
                  f"all features:  {correct} correct, {wrong} wrong"]

        attributed_total = 0
        for step in (IMPORTS_STEP, PROTOTYPE_STEP, FRAME_STEP):
            attributed = _attributed(all_db, step)
            attributed_total += len(attributed)
            covered = {a: b for a, b in attributed.items()
                       if a in generated_pair.truth}
            contradicting = {a: b for a, b in covered.items()
                             if generated_pair.truth[a] != b}
            report.append(
                f"  {step}: {len(attributed)} matches, {len(covered)} covered "
                f"by truth, {len(contradicting)} contradicting")
            assert not contradicting, (
                f"{step} made {len(contradicting)} matches that contradict "
                f"ground truth, out of {len(covered)} covered")

        with capsys.disabled():
            print("\n".join(report))

        # Guards against the test passing while measuring nothing. Every
        # assertion below about contradictions is vacuous at zero matches, and
        # an earlier version of this file did exactly that: the steps were
        # credited with no matches at all -- because the engine was writing
        # them against an algorithm id that did not exist -- and the test was
        # perfectly happy. At least one feature step has to be visible in the
        # attribution for the rest of this to mean anything.
        assert attributed_total > 0, (
            "no match in the result file is attributed to any feature step; "
            "either the steps ran and matched nothing, or their matches are "
            "not being recorded against the right algorithm")

        # Guarded, not asserted upward: a feature that actively costs matches
        # is a regression, but claiming a specific gain from one generated
        # corpus would be over-reading a single measurement.
        assert correct >= baseline_correct, (
            f"enabling the sidecar features lost matches: {correct} vs "
            f"{baseline_correct} of {total}")
