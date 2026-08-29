"""Tests for the engine configuration.

The point of these is that a toggle has to actually change what the differ
does. Before this existed, `Config` was a Python object with three invented
attributes wired to nothing, and the engine cached its algorithm selection in a
process-wide static on first use -- so even a real setter would have been
ignored from the second diff onwards.
"""

import sqlite3

import pytest

pytestmark = pytest.mark.requires_extension


@pytest.fixture(autouse=True)
def restore_config(bindiff_module):
    """The config is process-wide state; put it back after every test."""
    yield
    bindiff_module.reset_config()


def test_config_reports_real_matching_steps(bindiff_module):
    config = bindiff_module.get_config()

    assert "function_matching" in config
    assert "basic_block_matching" in config

    names = [step["name"] for step in config["function_matching"]]
    # These are the engine's own step names, not an invented schema.
    assert "function: name hash matching" in names
    assert "function: hash matching" in names
    assert len(names) == len(set(names)), "duplicate step names in config"


def test_the_shipped_sidecar_features_are_enabled(bindiff_module):
    """Both features that measured their keep are in the default config.

    A step absent from the config is silently skipped -- it gets confidence
    -1.0 and never runs -- so a feature can be fully built, tested and
    producing sidecars while contributing nothing, with no error anywhere to
    say so. That is the failure this pins down.
    """
    names = [step["name"]
             for step in bindiff_module.get_default_config()["function_matching"]]

    assert "function: feature imports/v1" in names
    assert "function: feature prototype/v1" in names
    # Measured on stripped real programs at 80% precision and improving only
    # 2 of 9 pairs, hurting 2 others. See tools/scripts/measure_real_corpus.py.
    assert "function: feature frame/v1" not in names, (
        "frame/v1 did not earn a default slot; see the measurement")

    # Order is not cosmetic: the steps run strongest first and an earlier one
    # claims a pair the later cannot. Measured, imports before prototype is
    # worth 923 correct matches against 907 the other way round.
    assert names.index("function: feature imports/v1") < names.index(
        "function: feature prototype/v1")


def test_defaults_are_stable(bindiff_module):
    """get_default_config is the compiled-in baseline, not the live config."""
    defaults = bindiff_module.get_default_config()
    assert defaults["function_matching"]

    bindiff_module.set_config(
        {"function_matching": [{"name": "function: hash matching",
                                "confidence": 1.0}]}
    )
    assert len(bindiff_module.get_config()["function_matching"]) == 1
    # Mutating the live config must not disturb the defaults.
    assert bindiff_module.get_default_config() == defaults


def test_set_config_round_trips(bindiff_module):
    bindiff_module.set_config(
        {"function_matching": [
            {"name": "function: name hash matching", "confidence": 1.0},
            {"name": "function: hash matching", "confidence": 1.0},
        ]}
    )
    names = [s["name"] for s in bindiff_module.get_config()["function_matching"]]
    assert names == ["function: name hash matching", "function: hash matching"]


def test_omitted_lists_keep_defaults(bindiff_module):
    """A patch that says nothing about matching keeps the default steps."""
    default_count = len(bindiff_module.get_default_config()["function_matching"])
    bindiff_module.set_config({"log": {"to_stderr": False}})
    assert len(bindiff_module.get_config()["function_matching"]) == default_count


def test_reset_config_restores_defaults(bindiff_module):
    bindiff_module.set_config(
        {"function_matching": [{"name": "function: hash matching",
                                "confidence": 1.0}]}
    )
    assert len(bindiff_module.get_config()["function_matching"]) == 1
    bindiff_module.reset_config()
    assert (bindiff_module.get_config()["function_matching"]
            == bindiff_module.get_default_config()["function_matching"])


def test_set_config_rejects_garbage(bindiff_module):
    with pytest.raises(TypeError):
        bindiff_module.set_config("not a dict")
    with pytest.raises(Exception):
        bindiff_module.set_config({"function_matching": "not a list"})


@pytest.mark.e2e
def test_disabling_steps_changes_the_diff(bindiff_module, insider_pair, tmp_path):
    """The one that matters: a toggle has to reach the engine.

    Runs the same fixture pair twice -- once with the default seventeen function
    matching steps, once with a single one -- and requires the results to
    differ. If the selection were still cached in a static, or if set_config
    merged instead of replacing, both runs would return identical counts.
    """
    primary, secondary = insider_pair

    baseline_db = tmp_path / "baseline.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(baseline_db)) == 0
    baseline = len(bindiff_module.load_matches(str(baseline_db)))
    assert baseline > 0

    # One step only. Name matching alone can pair far fewer functions than the
    # full ladder of structural algorithms.
    bindiff_module.set_config(
        {"function_matching": [{"name": "function: name hash matching",
                                "confidence": 1.0}]}
    )
    assert len(bindiff_module.get_config()["function_matching"]) == 1

    reduced_db = tmp_path / "reduced.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(reduced_db)) == 0
    reduced = len(bindiff_module.load_matches(str(reduced_db)))

    assert reduced < baseline, (
        f"disabling sixteen of seventeen matching steps changed nothing "
        f"({reduced} vs {baseline}) -- the config is not reaching the engine"
    )

    # And it is reversible within the same process, which is the case the
    # cached static used to break.
    bindiff_module.reset_config()
    restored_db = tmp_path / "restored.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(restored_db)) == 0
    assert len(bindiff_module.load_matches(str(restored_db))) == baseline


class TestConfidenceIsLive:
    """Confidence used to be read once per process.

    The engine cached it in a member set when each algorithm object was
    constructed, so a configuration change never reached a running differ: the
    dialog could edit the value and the edit silently did nothing. It is now
    read from a snapshot that set_config rebuilds.
    """

    def test_confidence_round_trips(self, bindiff_module):
        config = bindiff_module.get_config()
        original = config["function_matching"][0]["confidence"]
        changed = 0.25 if original != 0.25 else 0.75

        config["function_matching"][0]["confidence"] = changed
        bindiff_module.set_config(config)

        assert bindiff_module.get_config()["function_matching"][0][
            "confidence"] == changed

    @pytest.mark.e2e
    def test_confidence_changes_reported_confidence(
            self, bindiff_module, insider_pair, tmp_path):
        """The value has to reach the engine, not just the config.

        Confidence weights how much each algorithm's matches are trusted, and
        feeds the confidence recorded against every match. Dropping every
        algorithm to a low weight must move those numbers; if the engine were
        still reading its construction-time copy, the two runs would be
        identical.
        """
        primary, secondary = insider_pair

        baseline_db = tmp_path / "baseline.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary),
                                   str(baseline_db)) == 0
        baseline = [m.confidence
                    for m in bindiff_module.load_matches(str(baseline_db))]
        assert baseline

        config = bindiff_module.get_config()
        for step in config["function_matching"]:
            step["confidence"] = 0.05
        for step in config["basic_block_matching"]:
            step["confidence"] = 0.05
        bindiff_module.set_config(config)

        lowered_db = tmp_path / "lowered.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary),
                                   str(lowered_db)) == 0
        lowered = [m.confidence
                   for m in bindiff_module.load_matches(str(lowered_db))]

        assert len(lowered) == len(baseline), "the match set should not change"
        assert lowered != baseline, (
            "lowering every algorithm's confidence changed nothing -- the "
            "engine is not reading the configured value")
        assert max(lowered) < max(baseline)


@pytest.mark.e2e
def test_a_step_enabled_after_the_first_diff_is_attributed(
        bindiff_module, insider_pair, tmp_path):
    """Every match must name an algorithm that exists in the result file.

    The engine interns matching step names in a process-wide pool. That pool
    used to be built once, from whatever steps were registered the first time a
    fixed point was created, and a name that was not in it silently became the
    empty string -- so the writer looked up "" in its step table, got the
    default 0, and wrote matches referencing an algorithm id that does not
    exist. Nothing failed and no count changed; the results file was simply
    wrong about which algorithm found what.

    It takes two diffs in one process to show up, with the second enabling a
    step the first did not have -- which is every diff after the first in a
    long-lived host like IDA, where the point of the algorithm dialog is to
    change the selection between runs.
    """
    primary, secondary = insider_pair
    full = bindiff_module.get_default_config()["function_matching"]
    reduced = [step for step in full
               if step["name"] in ("function: hash matching",
                                   "function: name hash matching")]
    assert len(reduced) < len(full), "expected the reduced list to be smaller"

    # First diff: a deliberately small selection.
    bindiff_module.set_config({"function_matching": reduced})
    first = tmp_path / "first.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(first)) == 0

    # Second diff: everything, including steps the first run never registered.
    bindiff_module.set_config({"function_matching": full})
    second = tmp_path / "second.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(second)) == 0

    connection = sqlite3.connect(str(second))
    try:
        known = {row[0] for row in
                 connection.execute("SELECT id FROM functionalgorithm")}
        used = dict(connection.execute(
            "SELECT algorithm, COUNT(*) FROM function GROUP BY algorithm"))
    finally:
        connection.close()

    assert used, "the second diff matched nothing"
    dangling = {identifier: count for identifier, count in used.items()
                if identifier not in known}
    assert not dangling, (
        f"{sum(dangling.values())} matches reference algorithm ids that are "
        f"not in functionalgorithm: {sorted(dangling)}")
