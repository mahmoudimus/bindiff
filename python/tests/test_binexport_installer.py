"""Tests for the BinExport plugin installer.

This code ends with a native binary loaded into IDA, so the tests are mostly
about what it refuses. The download is injected, so none of this touches a
network; the archives are built in memory, including the malformed ones.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

# Loaded by path, not as bindiff.binexport_installer: importing the package
# runs bindiff/__init__.py, which pulls in the Cython extension, and this
# module needs nothing but the standard library. That is what lets it run in
# the portable CI leg alongside test_ui_logic and test_diff_runner.
_MODULE = (Path(__file__).resolve().parents[1] / "bindiff"
           / "binexport_installer.py")
_spec = importlib.util.spec_from_file_location("binexport_installer", _MODULE)
bi = importlib.util.module_from_spec(_spec)
sys.modules["binexport_installer"] = bi
_spec.loader.exec_module(bi)


def archive(members):
    """A zip built in memory. `members` maps arcname to bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        for name, payload in members.items():
            handle.writestr(name, payload)
    return buffer.getvalue()


def manifest_for(asset, payload):
    return {"assets": {f"{asset}.zip": hashlib.sha256(payload).hexdigest()}}


class TestPlatformMapping:
    @pytest.mark.parametrize("system,machine,expected", [
        ("Darwin", "arm64", "binexport-macos-arm64"),
        ("Darwin", "x86_64", "binexport-macos-x86_64"),
        ("Linux", "x86_64", "binexport-linux-x86_64"),
        ("Windows", "AMD64", "binexport-windows-x86_64"),
    ])
    def test_each_published_platform_maps_to_its_asset(self, system, machine,
                                                       expected):
        assert bi.asset_for(system, machine) == expected

    def test_architecture_spellings_are_reconciled(self):
        """Windows says AMD64, Linux says x86_64; macOS says arm64 and Linux
        aarch64 for the same silicon."""
        assert bi.asset_for("Linux", "aarch64") == bi.asset_for(
            "Linux", "arm64")
        assert bi.asset_for("Windows", "AMD64") == bi.asset_for(
            "Windows", "x86_64")

    def test_a_platform_with_no_build_is_refused_not_guessed(self):
        with pytest.raises(bi.Unsupported, match="no BinExport build"):
            bi.asset_for("Linux", "aarch64_be")

    @pytest.mark.parametrize("system,name", [
        ("Darwin", "binexport12_ida.dylib"),
        ("Linux", "binexport12_ida.so"),
        ("Windows", "binexport12_ida.dll"),
    ])
    def test_the_plugin_keeps_the_name_ida_looks_for(self, system, name):
        assert bi.plugin_name_for(system) == name


class TestPlan:
    def test_it_points_at_its_own_release(self, tmp_path):
        """A plugin and an exporter that disagree about the .BinExport format
        fail confusingly and much later, so the tag is this package's own
        version rather than whatever is newest."""
        plan = bi.plan(tmp_path, "8.1.3", system="Darwin", machine="arm64")
        assert "/releases/download/v8.1.3/" in plan.archive_url
        assert plan.archive_url.endswith("binexport-macos-arm64.zip")
        assert plan.destination == tmp_path / "binexport12_ida.dylib"

    def test_nothing_is_downloaded_by_planning(self, tmp_path):
        """plan() exists so a caller can show what would happen and ask."""
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        assert not list(tmp_path.iterdir())
        assert plan.manifest_url.endswith(bi.MANIFEST_ASSET)


class TestFindInstalled:
    def test_found_by_filename_in_any_plugins_directory(self, tmp_path):
        first, second = tmp_path / "a", tmp_path / "b"
        first.mkdir(); second.mkdir()
        (second / "binexport12_ida.so").write_bytes(b"x")
        assert bi.find_installed([first, second], "Linux") == (
            second / "binexport12_ida.so")

    def test_absent_reads_as_none(self, tmp_path):
        assert bi.find_installed([tmp_path], "Linux") is None

    def test_empty_entries_are_skipped(self, tmp_path):
        """get_user_idadir() can return nothing; that is not a reason to
        stat the current directory."""
        assert bi.find_installed([None, "", tmp_path], "Linux") is None


class TestVerification:
    def test_matching_bytes_pass(self):
        bi.verify(b"payload", hashlib.sha256(b"payload").hexdigest())

    def test_altered_bytes_are_refused(self):
        with pytest.raises(bi.Corrupt, match="does not match the manifest"):
            bi.verify(b"payload", hashlib.sha256(b"other").hexdigest())

    def test_a_manifest_without_the_asset_is_an_error(self):
        """"No digest" must never read as "any bytes will do"."""
        with pytest.raises(bi.Corrupt, match="no digest"):
            bi.digest_for({"assets": {"something-else.zip": "ab"}},
                          "binexport-linux-x86_64")

    def test_an_empty_manifest_is_an_error(self):
        with pytest.raises(bi.Corrupt, match="no digest"):
            bi.digest_for({}, "binexport-linux-x86_64")


class TestExtraction:
    def test_the_plugin_is_read_out_by_name(self):
        payload = archive({"binexport12_ida.so": b"ELF..."})
        assert bi.extract_plugin(payload, "binexport12_ida.so") == b"ELF..."

    def test_a_nested_path_is_fine_because_only_the_name_matters(self):
        payload = archive({"ida/binexport12_ida.so": b"ELF..."})
        assert bi.extract_plugin(payload, "binexport12_ida.so") == b"ELF..."

    def test_an_archive_without_it_is_refused(self):
        payload = archive({"README": b"hi"})
        with pytest.raises(bi.Corrupt, match="contains no"):
            bi.extract_plugin(payload, "binexport12_ida.so")

    def test_two_candidates_are_refused_rather_than_picked_between(self):
        payload = archive({"a/binexport12_ida.so": b"one",
                           "b/binexport12_ida.so": b"two"})
        with pytest.raises(bi.Corrupt, match="contains 2 files"):
            bi.extract_plugin(payload, "binexport12_ida.so")

    def test_a_traversing_entry_cannot_escape(self, tmp_path):
        """A zip may name ../../ anything and zipfile.extract would write it.
        Nothing is extracted to disk: the member is read by exact name, so
        the hostile entry is simply not the one that matches."""
        payload = archive({"../../../evil.so": b"pwned",
                           "binexport12_ida.so": b"ELF..."})
        assert bi.extract_plugin(payload, "binexport12_ida.so") == b"ELF..."
        assert not (tmp_path.parent / "evil.so").exists()


class TestInstall:
    def test_it_lands_where_the_plan_said(self, tmp_path):
        payload = archive({"binexport12_ida.so": b"ELF..."})
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        written = bi.install(payload, manifest_for(plan.asset, payload), plan)
        assert written == tmp_path / "binexport12_ida.so"
        assert written.read_bytes() == b"ELF..."

    def test_it_is_executable(self, tmp_path):
        payload = archive({"binexport12_ida.so": b"ELF..."})
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        written = bi.install(payload, manifest_for(plan.asset, payload), plan)
        assert written.stat().st_mode & 0o111

    def test_a_bad_digest_writes_nothing_at_all(self, tmp_path):
        """Verification comes before anything touches the plugins directory,
        including the temporary file."""
        payload = archive({"binexport12_ida.so": b"ELF..."})
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        bad = {"assets": {f"{plan.asset}.zip": hashlib.sha256(b"no").hexdigest()}}
        with pytest.raises(bi.Corrupt):
            bi.install(payload, bad, plan)
        assert list(tmp_path.iterdir()) == []

    def test_a_previous_plugin_survives_a_failed_install(self, tmp_path):
        (tmp_path / "binexport12_ida.so").write_bytes(b"the old one")
        payload = archive({"binexport12_ida.so": b"ELF..."})
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        with pytest.raises(bi.Corrupt):
            bi.install(payload, {"assets": {}}, plan)
        assert (tmp_path / "binexport12_ida.so").read_bytes() == b"the old one"

    def test_no_partial_file_is_left_behind(self, tmp_path):
        payload = archive({"binexport12_ida.so": b"ELF..."})
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        bi.install(payload, manifest_for(plan.asset, payload), plan)
        assert [p.name for p in tmp_path.iterdir()] == ["binexport12_ida.so"]


class TestFetchAndInstall:
    def test_the_sequence_with_the_network_injected(self, tmp_path):
        payload = archive({"binexport12_ida.so": b"ELF..."})
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        manifest = manifest_for(plan.asset, payload)
        asked = []

        def fetch(url):
            asked.append(url)
            return (json.dumps(manifest).encode() if url.endswith(".json")
                    else payload)

        written = bi.fetch_and_install(plan, fetch, json.loads)
        assert written.read_bytes() == b"ELF..."
        # Manifest first: there is no point spending megabytes on an archive
        # this has no way to check.
        assert asked[0].endswith(bi.MANIFEST_ASSET)
        assert asked[1].endswith(".zip")

    def test_a_release_without_a_manifest_never_downloads_the_archive(
            self, tmp_path):
        plan = bi.plan(tmp_path, "8.1.3", system="Linux", machine="x86_64")
        asked = []

        def fetch(url):
            asked.append(url)
            return b"{}"

        with pytest.raises(bi.Corrupt, match="no digest"):
            bi.fetch_and_install(plan, fetch, json.loads)
        assert not any(url.endswith(".zip") for url in asked)
        assert list(tmp_path.iterdir()) == []
