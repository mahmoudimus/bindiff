#!/usr/bin/env python3
"""Turns a directory of wheels into `pythonDependencies` for ida-plugin.json.

hcli installs a plugin's Python dependencies with pip, and the field it reads
takes pip-compatible specifications with no way to name an index. This fork is
not on PyPI, so `bindiff-ng==8.1.1` would not resolve for anyone.

PEP 508 direct references solve it: a specification may carry a URL *and* an
environment marker, so one entry per wheel, each guarded by the platform and
Python version it was built for, resolves to exactly one candidate on any
machine. pip evaluates the markers and downloads that one.

    tools/scripts/plugin_dependencies.py --wheels dist/ --tag v8.1.1 \\
        --repo mahmoudimus/bindiff-ng --write ida-plugin.json

Without --write it prints the list, which is what the tests use.

The alternative was a PEP 503 index on GitHub Pages. It reads better for a
human running pip by hand, and it is published alongside this -- but it needs
--extra-index-url, and `pythonDependencies` has nowhere to put one, so hcli
could not use it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

# PEP 427: name-version(-build)?-python-abi-platform.whl
_WHEEL = re.compile(
    r"^(?P<name>[^-]+)-(?P<version>[^-]+)"
    r"(?:-(?P<build>\d[^-]*))?"
    r"-(?P<python>[^-]+)-(?P<abi>[^-]+)-(?P<platform>.+)\.whl$")

# Marker fragments per wheel platform tag. Keyed on what the tag starts with,
# because the rest carries a glibc or macOS version this does not need to
# reproduce -- pip already refuses a wheel too new for the host.
_PLATFORM_MARKERS = {
    "manylinux": "sys_platform == 'linux'",
    "musllinux": "sys_platform == 'linux'",
    "linux": "sys_platform == 'linux'",
    "macosx": "sys_platform == 'darwin'",
    "win": "sys_platform == 'win32'",
}

_MACHINE = {
    "x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64",
    "arm64": "arm64", "universal2": None, "intel": None, "any": None,
}


class Unsupported(Exception):
    """A wheel whose tags this cannot turn into a marker."""


def parse_wheel(filename: str) -> Dict[str, str]:
    match = _WHEEL.match(filename)
    if not match:
        raise Unsupported(f"not a wheel filename: {filename}")
    return match.groupdict()


def _python_version(python_tag: str) -> str:
    """cp313 -> '3.13'.

    Only CPython tags are handled. `py3` and the abi3 tags would need a range
    rather than an equality, and this package ships neither -- a Cython
    extension is built per interpreter version.
    """
    match = re.fullmatch(r"cp(\d)(\d+)", python_tag)
    if not match:
        raise Unsupported(
            f"only CPython version tags are supported, got {python_tag!r}")
    return f"{match.group(1)}.{match.group(2)}"


def _python_marker(python_tag: str, abi_tag: str = "") -> str:
    """An equality for a version-locked wheel, a floor for a stable-ABI one.

    A cp313 wheel is built against one interpreter's ABI and loads on nothing
    else, so its marker pins the version exactly. An abi3 wheel is built
    against the limited API and loads on the version it names and every later
    one -- pinning it to that version would refuse the interpreters it exists
    to serve, which is the entire reason for building it.
    """
    version = _python_version(python_tag)
    if abi_tag == "abi3":
        return f"python_version >= '{version}'"
    return f"python_version == '{version}'"


def _machine_marker(platform_tag: str) -> Optional[str]:
    """The architecture clause, or None when the wheel covers every machine.

    macOS universal2 and Windows' single 64-bit tag need no clause: there is
    nothing to disambiguate them from.
    """
    for machine, canonical in _MACHINE.items():
        if platform_tag.endswith("_" + machine) or platform_tag == machine:
            if canonical is None:
                return None
            # Windows reports AMD64; Linux and macOS report x86_64.
            if canonical == "x86_64" and platform_tag.startswith("win"):
                return None
            return f"platform_machine == '{canonical}'"
    return None


def marker_for(platform_tag: str, python_tag: str, abi_tag: str = "") -> str:
    for prefix, clause in _PLATFORM_MARKERS.items():
        if platform_tag.startswith(prefix):
            clauses = [clause, _python_marker(python_tag, abi_tag)]
            machine = _machine_marker(platform_tag)
            if machine:
                clauses.insert(1, machine)
            return " and ".join(clauses)
    raise Unsupported(f"unrecognised platform tag: {platform_tag}")


def asset_url(repo: str, tag: str, filename: str) -> str:
    return f"https://github.com/{repo}/releases/download/{tag}/{filename}"


def dependencies_for(wheels: List[str], repo: str, tag: str) -> List[str]:
    """One specification per wheel, sorted so the output is reproducible.

    A release regenerated from the same wheels must produce a byte-identical
    field, or every release shows a spurious diff in ida-plugin.json.
    """
    specs = []
    for filename in sorted(wheels):
        parsed = parse_wheel(filename)
        marker = marker_for(parsed["platform"], parsed["python"],
                            parsed["abi"])
        specs.append(f"{parsed['name'].replace('_', '-')} @ "
                     f"{asset_url(repo, tag, filename)} ; {marker}")
    return specs


# The machines a marker gets evaluated against: the ones this project ships
# wheels for. An overlap that shows on no shipped platform is not an overlap
# anybody can hit.
# Probed Python versions. An abi3 marker is a floor, so an overlap between it
# and a version-locked wheel shows up on a version that appears in neither
# filename -- deriving the grid from the tags alone would look past exactly the
# case this has to catch. 3.9 is below every floor this ships and is here to
# check that nothing claims it.
_PROBE_PYTHONS = ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]

_ENVIRONMENTS = [
    ("linux", "x86_64"),
    ("linux", "aarch64"),
    ("darwin", "arm64"),
    ("darwin", "x86_64"),
    ("win32", "AMD64"),
]


def _filename(url: str) -> str:
    """Last segment of a release URL. Not a filesystem path -- a URL always
    uses forward slashes, so pathlib would be wrong on Windows."""
    return url.rsplit("/", 1)[-1]


def check_unambiguous(specs: List[str]) -> None:
    """Refuses two wheels that could both install on one machine.

    pip takes the first satisfied requirement, so an overlap does not fail --
    it silently installs whichever was listed first, which on a matrix that
    grew a duplicate is not the one anybody chose.

    Comparing the marker text is not enough, and the wheels this actually
    builds are why: macOS produces one universal2 wheel, whose marker names no
    architecture because it needs none. Add a dedicated arm64 wheel beside it
    and the two markers differ as strings while both still apply on an arm64
    Mac -- the exact case this exists to catch. So evaluate them, against every
    machine this ships for, and count.
    """
    from packaging.markers import default_environment
    from packaging.requirements import Requirement

    requirements = [Requirement(spec) for spec in specs]
    pythons = sorted(
        set(_PROBE_PYTHONS) | {
            _python_version(parse_wheel(_filename(requirement.url))["python"])
            for requirement in requirements if requirement.url},
        key=lambda v: tuple(int(part) for part in v.split(".")))

    for sys_platform, machine in _ENVIRONMENTS:
        for python in pythons:
            environment = dict(default_environment())
            environment.update(sys_platform=sys_platform,
                               platform_machine=machine,
                               python_version=python)
            applicable = [
                requirement for requirement in requirements
                if requirement.marker is None
                or requirement.marker.evaluate(environment)]
            if len(applicable) > 1:
                listed = "\n  ".join(
                    _filename(r.url or "") for r in applicable)
                raise Unsupported(
                    f"{len(applicable)} wheels claim the same environment "
                    f"({sys_platform}/{machine}, python {python}); pip would "
                    f"install whichever is listed first:\n  {listed}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheels", required=True,
                        help="directory of built wheels")
    parser.add_argument("--repo", required=True, help="owner/name on GitHub")
    parser.add_argument("--tag", required=True, help="release tag")
    parser.add_argument("--write", help="ida-plugin.json to update in place")
    args = parser.parse_args(argv)

    names = [p.name for p in sorted(Path(args.wheels).glob("*.whl"))]
    if not names:
        print(f"no wheels in {args.wheels}", file=sys.stderr)
        return 1

    try:
        specs = dependencies_for(names, args.repo, args.tag)
        check_unambiguous(specs)
    except Unsupported as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.write:
        print(json.dumps(specs, indent=4))
        return 0

    path = Path(args.write)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["plugin"]["pythonDependencies"] = specs
    # Trailing newline and four-space indent to match what is checked in, so
    # the only diff is the field that changed.
    path.write_text(json.dumps(manifest, indent=4) + "\n", encoding="utf-8")
    print(f"wrote {len(specs)} dependencies into {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
