"""Tests for the ida-plugin.json dependency generator.

This fork is not on PyPI, so `bindiff-ng==8.1.0` resolves nowhere. hcli hands
`pythonDependencies` to pip and offers no way to name an index, so each wheel
is listed as a PEP 508 direct reference guarded by an environment marker.

The property that has to hold: on any machine, **exactly one** of them applies.
Too few and the install fails; too many and pip silently takes whichever was
listed first.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_MODULE = (Path(__file__).resolve().parents[2] / "tools" / "scripts"
           / "plugin_dependencies.py")
_spec = importlib.util.spec_from_file_location("plugin_dependencies", _MODULE)
plugin_dependencies = importlib.util.module_from_spec(_spec)
sys.modules["plugin_dependencies"] = plugin_dependencies
_spec.loader.exec_module(plugin_dependencies)

Unsupported = plugin_dependencies.Unsupported
dependencies_for = plugin_dependencies.dependencies_for
check_unambiguous = plugin_dependencies.check_unambiguous
marker_for = plugin_dependencies.marker_for
parse_wheel = plugin_dependencies.parse_wheel

REPO = "mahmoudimus/bindiff-ng"
TAG = "v8.1.0"

# One release's worth. The platform tags are copied from what the workflow
# actually produced in run 33352286800 rather than from what seemed likely;
# the distribution is bindiff-ng, so a wheel filename spells it bindiff_ng. Two of these
# differ from the obvious guess: macOS builds a single universal2 wheel rather
# than one per architecture, and auditwheel tags the Linux wheels for the
# glibc of the runner that built them.
WHEELS = [
    "bindiff_ng-8.1.0-cp313-cp313-manylinux_2_39_x86_64.whl",
    "bindiff_ng-8.1.0-cp313-cp313-manylinux_2_39_aarch64.whl",
    "bindiff_ng-8.1.0-cp313-cp313-macosx_10_15_universal2.whl",
    "bindiff_ng-8.1.0-cp313-cp313-win_amd64.whl",
]


def applies(spec: str, environment: dict) -> bool:
    from packaging.requirements import Requirement

    requirement = Requirement(spec)
    return requirement.marker is None or requirement.marker.evaluate(environment)


def environment(sys_platform, machine, python="3.13") -> dict:
    from packaging.markers import default_environment

    env = dict(default_environment())
    env.update(sys_platform=sys_platform, platform_machine=machine,
               python_version=python)
    return env


class TestWheelParsing:
    def test_reads_the_tags(self):
        parsed = parse_wheel("bindiff_ng-8.1.0-cp313-cp313-win_amd64.whl")
        assert parsed["name"] == "bindiff_ng"
        assert parsed["version"] == "8.1.0"
        assert parsed["python"] == "cp313"
        assert parsed["platform"] == "win_amd64"

    def test_a_platform_tag_may_contain_dashes_worth_of_detail(self):
        """manylinux tags carry several underscore-separated parts and, when a
        wheel is multiply tagged, dots. The platform is everything after the
        abi, not the next field."""
        parsed = parse_wheel(
            "d810_ng-0.6.6-cp313-cp313-"
            "manylinux_2_24_x86_64.manylinux_2_28_x86_64.whl")
        assert parsed["platform"] == (
            "manylinux_2_24_x86_64.manylinux_2_28_x86_64")

    def test_rejects_something_that_is_not_a_wheel(self):
        with pytest.raises(Unsupported):
            parse_wheel("bindiff_ng-8.1.0.tar.gz")


class TestMarkers:
    def test_linux_carries_platform_and_machine(self):
        marker = marker_for("manylinux_2_28_x86_64", "cp313")
        assert "sys_platform == 'linux'" in marker
        assert "platform_machine == 'x86_64'" in marker
        assert "python_version == '3.13'" in marker

    def test_windows_needs_no_machine_clause(self):
        """Windows reports AMD64 rather than x86_64, and there is only one
        64-bit wheel, so adding a clause would only be a chance to get the
        spelling wrong."""
        marker = marker_for("win_amd64", "cp313")
        assert "sys_platform == 'win32'" in marker
        assert "platform_machine" not in marker

    def test_a_universal_macos_wheel_needs_no_machine_clause(self):
        assert "platform_machine" not in marker_for(
            "macosx_11_0_universal2", "cp313")

    def test_only_cpython_version_tags_are_accepted(self):
        """py3 and abi3 would need a range rather than an equality, and this
        package ships neither -- a Cython extension is per interpreter."""
        with pytest.raises(Unsupported, match="CPython"):
            marker_for("manylinux_2_28_x86_64", "py3")
        with pytest.raises(Unsupported, match="CPython"):
            marker_for("manylinux_2_28_x86_64", "abi3")

    def test_an_unknown_platform_is_refused_not_guessed(self):
        with pytest.raises(Unsupported, match="platform tag"):
            marker_for("solaris_11_sparc", "cp313")


class TestDependencies:
    def test_each_wheel_becomes_a_direct_reference(self):
        specs = dependencies_for(WHEELS, REPO, TAG)
        assert len(specs) == len(WHEELS)
        for spec in specs:
            assert spec.startswith("bindiff-ng @ https://github.com/"), spec
            assert f"/releases/download/{TAG}/" in spec

    @pytest.mark.parametrize("platform,machine,expected", [
        ("linux", "x86_64", "manylinux_2_39_x86_64"),
        ("linux", "aarch64", "manylinux_2_39_aarch64"),
        # Both Macs take the one universal2 wheel.
        ("darwin", "arm64", "macosx_10_15_universal2"),
        ("darwin", "x86_64", "macosx_10_15_universal2"),
        ("win32", "AMD64", "win_amd64"),
    ])
    def test_exactly_one_applies_per_machine(self, platform, machine, expected):
        """The property the whole approach rests on. Too few and the install
        fails; too many and pip takes whichever came first."""
        specs = dependencies_for(WHEELS, REPO, TAG)
        env = environment(platform, machine)
        matching = [s for s in specs if applies(s, env)]

        assert len(matching) == 1, (
            f"{platform}/{machine} matched {len(matching)}: {matching}")
        assert expected in matching[0]

    def test_nothing_applies_to_a_python_version_with_no_wheel(self):
        """Better a clear "no matching distribution" than a wheel built for a
        different interpreter."""
        specs = dependencies_for(WHEELS, REPO, TAG)
        env = environment("linux", "x86_64", python="3.11")
        assert [s for s in specs if applies(s, env)] == []

    def test_the_output_is_stable_for_the_same_wheels(self):
        """A release regenerated from the same inputs must produce a
        byte-identical field, or every release shows a spurious diff."""
        first = dependencies_for(WHEELS, REPO, TAG)
        second = dependencies_for(list(reversed(WHEELS)), REPO, TAG)
        assert first == second

    def test_two_wheels_for_one_environment_are_refused(self):
        """pip would silently take the first. On a matrix that grew a
        duplicate, that is not the one anybody chose."""
        duplicated = WHEELS + [
            "bindiff_ng-8.1.0-cp313-cp313-manylinux_2_34_x86_64.whl"]
        with pytest.raises(Unsupported, match="same environment"):
            check_unambiguous(dependencies_for(duplicated, REPO, TAG))

    def test_an_overlap_is_caught_even_when_the_markers_differ(self):
        """The case that will actually happen. macOS ships one universal2
        wheel, whose marker names no architecture; add a dedicated arm64 wheel
        beside it and the markers differ as text while both apply on an arm64
        Mac. An earlier version of this check compared marker strings and let
        that through."""
        overlapping = WHEELS + [
            "bindiff_ng-8.1.0-cp313-cp313-macosx_11_0_arm64.whl"]
        specs = dependencies_for(overlapping, REPO, TAG)
        markers = {str(__import__("packaging.requirements", fromlist=["x"])
                       .Requirement(s).marker) for s in specs}
        assert len(markers) == len(specs), "markers must differ as text"
        with pytest.raises(Unsupported, match="same environment"):
            check_unambiguous(specs)

    def test_every_shipped_machine_is_covered_by_some_wheel(self):
        """A platform the workflow builds for that no marker selects would
        install nothing, and pip's message names the package, not the gap."""
        specs = dependencies_for(WHEELS, REPO, TAG)
        for platform, machine in [("linux", "x86_64"), ("linux", "aarch64"),
                                  ("darwin", "arm64"), ("darwin", "x86_64"),
                                  ("win32", "AMD64")]:
            env = environment(platform, machine)
            assert [s for s in specs if applies(s, env)], (
                f"nothing installs on {platform}/{machine}")

    def test_a_clean_set_passes_the_ambiguity_check(self):
        check_unambiguous(dependencies_for(WHEELS, REPO, TAG))


def test_it_rewrites_only_the_dependency_field(tmp_path):
    """ida-plugin.json is hand-maintained apart from this one field."""
    import json

    source = Path(__file__).resolve().parents[2] / "ida-plugin.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))
    target = tmp_path / "ida-plugin.json"
    target.write_text(json.dumps(manifest, indent=4) + "\n", encoding="utf-8")

    wheels = tmp_path / "dist"
    wheels.mkdir()
    for name in WHEELS:
        (wheels / name).write_bytes(b"")

    assert plugin_dependencies.main([
        "--wheels", str(wheels), "--repo", REPO, "--tag", TAG,
        "--write", str(target)]) == 0

    written = json.loads(target.read_text(encoding="utf-8"))
    assert len(written["plugin"]["pythonDependencies"]) == len(WHEELS)
    # Everything else survives untouched.
    for key, value in manifest["plugin"].items():
        if key != "pythonDependencies":
            assert written["plugin"][key] == value
