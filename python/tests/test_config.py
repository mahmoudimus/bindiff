"""Tests for the engine configuration.

The point of these is that a toggle has to actually change what the differ
does. Before this existed, `Config` was a Python object with three invented
attributes wired to nothing, and the engine cached its algorithm selection in a
process-wide static on first use -- so even a real setter would have been
ignored from the second diff onwards.
"""

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
