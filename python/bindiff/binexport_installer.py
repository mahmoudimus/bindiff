"""Fetches the BinExport IDA plugin that the export half of a diff needs.

Without it an installation can open an existing .BinDiff and nothing else:
`bindiff.headless.export` calls BinExport's BinExportBinary IDC function, and
that only exists if BinExport is loaded. Upstream publishes nothing usable on
IDA 9.x -- its newest release predates IDA 9.0, ships x86_64-only macOS
binaries and still carries the _ida/_ida64 pair 9.0 abolished -- so the
binaries come from this fork's own release, built by
.github/workflows/binexport-plugin.yml.

This ends with a native binary being loaded into IDA, so the rules are:

  * Nothing is downloaded without the caller asking. There is no implicit
    fetch on plugin load; `plan()` describes what would happen and the caller
    decides.
  * Every byte is checked against a digest from the release manifest before
    anything touches the plugins directory. That is integrity, not provenance:
    it proves the archive is the one the manifest names, and the manifest and
    the archive come from the same server over the same HTTPS connection. It
    catches truncation, a corrupted proxy and an asset replaced after the
    manifest was written. It does not, alone, prove the release was not
    tampered with at source.
  * Exactly one member is extracted, by name. A zip can name ../../anything
    and Python will happily write it, so the archive is treated as untrusted
    input rather than as something this project produced.
  * The install is atomic. A half-written plugin is one IDA will try to load.

Everything here is pure but for `install()`, and the download is injected, so
the whole thing is exercised without a network in
python/tests/test_binexport_installer.py.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import zipfile
from pathlib import Path
from typing import Callable, Dict, NamedTuple, Optional

# Asset base names, as .github/workflows/binexport-plugin.yml publishes them.
_ASSETS = {
    ("darwin", "arm64"): "binexport-macos-arm64",
    ("darwin", "x86_64"): "binexport-macos-x86_64",
    ("linux", "x86_64"): "binexport-linux-x86_64",
    ("linux", "arm64"): "binexport-linux-arm64",
    ("windows", "x86_64"): "binexport-windows-x86_64",
}

# What IDA loads. The name is not cosmetic: IDA finds a plugin by filename, so
# an archive whose member were renamed to carry its platform would have to be
# renamed back before it worked.
_PLUGIN_NAMES = {
    "darwin": "binexport12_ida.dylib",
    "linux": "binexport12_ida.so",
    "windows": "binexport12_ida.dll",
}

MANIFEST_ASSET = "binexport-manifest.json"


class Unsupported(Exception):
    """No BinExport build exists for this platform."""


class Corrupt(Exception):
    """What arrived is not what the manifest describes."""


class Plan(NamedTuple):
    """What an install would do, so a caller can show it before consenting."""

    asset: str
    archive_url: str
    manifest_url: str
    plugin_name: str
    destination: Path


def normalise_platform(system: Optional[str] = None,
                       machine: Optional[str] = None):
    """(system, machine) reduced to the pair the asset names use.

    Taken as arguments rather than read from the interpreter so every branch
    is reachable from a test on any host -- the same reason
    `headless.interpreter_candidates` takes `windows`.
    """
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    if system.startswith("win"):
        system = "windows"
    elif system == "darwin":
        system = "darwin"
    elif system.startswith("linux"):
        system = "linux"
    # Windows reports AMD64, Linux and macOS x86_64; arm is aarch64 or arm64
    # depending on who is asked.
    if machine in ("amd64", "x86_64", "x64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64"
    return system, machine


def asset_for(system: Optional[str] = None,
              machine: Optional[str] = None) -> str:
    key = normalise_platform(system, machine)
    if key not in _ASSETS:
        raise Unsupported(
            f"no BinExport build is published for {key[0]}/{key[1]}; "
            "the workflow builds macOS and Linux on arm64 and x86_64, "
            "and Windows x64")
    return _ASSETS[key]


def plugin_name_for(system: Optional[str] = None) -> str:
    system, _ = normalise_platform(system, "x86_64")
    return _PLUGIN_NAMES[system]


def plan(plugins_dir, version: str, repo: str = "mahmoudimus/bindiff-ng",
         system: Optional[str] = None, machine: Optional[str] = None) -> Plan:
    """Where the archive would come from and where the plugin would land.

    The tag is this package's own version, so an installation fetches the
    BinExport built alongside it rather than whatever is newest. A plugin and
    an exporter that disagree about the .BinExport format produce a confusing
    failure much later.
    """
    asset = asset_for(system, machine)
    tag = f"v{version}"
    base = f"https://github.com/{repo}/releases/download/{tag}"
    return Plan(
        asset=asset,
        archive_url=f"{base}/{asset}.zip",
        manifest_url=f"{base}/{MANIFEST_ASSET}",
        plugin_name=plugin_name_for(system),
        destination=Path(plugins_dir) / plugin_name_for(system),
    )


def find_installed(plugins_dirs, system: Optional[str] = None
                   ) -> Optional[Path]:
    """The installed plugin, or None.

    Checked by filename across every directory IDA loads plugins from rather
    than by asking IDA whether BinExportBinary resolves: the export runs in a
    separate idalib process, so what matters is what is on disk for *that*
    process to find, not what happens to be loaded in this one.
    """
    name = plugin_name_for(system)
    for directory in plugins_dirs:
        if not directory:
            continue
        candidate = Path(directory) / name
        if candidate.is_file():
            return candidate
    return None


def digest_for(manifest: Dict, asset: str) -> str:
    """The recorded SHA-256 for one asset.

    A manifest that does not mention the asset is an error rather than a
    reason to skip the check -- "no digest" must never read as "any bytes
    will do".
    """
    entries = manifest.get("assets") or {}
    digest = entries.get(f"{asset}.zip") or entries.get(asset)
    if not digest:
        raise Corrupt(
            f"the release manifest lists no digest for {asset}.zip; "
            f"it names {sorted(entries)}")
    return digest.lower()


def verify(payload: bytes, expected_sha256: str) -> None:
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected_sha256.lower():
        raise Corrupt(
            f"downloaded archive does not match the manifest:\n"
            f"  expected sha256 {expected_sha256.lower()}\n"
            f"  actual   sha256 {actual}")


def extract_plugin(payload: bytes, plugin_name: str) -> bytes:
    """The one member named `plugin_name`, refusing anything else.

    A zip entry may be an absolute path or contain .., and zipfile.extract
    would write it. Nothing here is extracted to disk at all: the member is
    read into memory by exact name, so a crafted archive has nowhere to
    escape to.
    """
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        matches = [n for n in archive.namelist()
                   if Path(n).name == plugin_name and not n.endswith("/")]
        if not matches:
            raise Corrupt(
                f"the archive contains no {plugin_name}; it holds "
                f"{archive.namelist()}")
        if len(matches) > 1:
            raise Corrupt(
                f"the archive contains {len(matches)} files named "
                f"{plugin_name}: {matches}")
        return archive.read(matches[0])


def install(payload: bytes, manifest: Dict, plan_: Plan) -> Path:
    """Verifies, extracts and writes the plugin. Returns where it landed.

    Written to a temporary name in the destination directory and then moved
    into place, so a failure part way through leaves either the previous
    plugin or none -- never half of one for IDA to load. The temporary file is
    a sibling because os.replace is only atomic within a filesystem.
    """
    verify(payload, digest_for(manifest, plan_.asset))
    binary = extract_plugin(payload, plan_.plugin_name)

    destination = Path(plan_.destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.with_name(destination.name + ".partial")
    staging.write_bytes(binary)
    # IDA has to be able to load it; the archive carries no mode bits worth
    # trusting anyway.
    staging.chmod(0o755)
    os.replace(staging, destination)
    return destination


def fetch_and_install(plan_: Plan,
                      fetch: Callable[[str], bytes],
                      load_manifest: Callable[[bytes], Dict]) -> Path:
    """The whole sequence, with the network injected.

    The manifest is fetched first and on its own: if the release does not
    publish one, this stops before downloading megabytes it has no way to
    check.
    """
    manifest = load_manifest(fetch(plan_.manifest_url))
    # Fetched only after the digest is known, so there is never a window where
    # an unverified archive is the only thing this holds.
    digest_for(manifest, plan_.asset)
    return install(fetch(plan_.archive_url), manifest, plan_)
