"""Copying a database for a worker to open.

An .i64 is only self-contained when IDA packed it. A database that has never
been packed -- which is what "Save" without packing leaves, and what an open
one looks like -- keeps its content in the companions beside it, and copying
the .i64 alone hands the worker a stub.

Three places copy a database for a worker: dump_types, try_import, and the
plugin's snapshot that every diff goes through. The first two always did this;
the third did not.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bindiff.headless import IDA_COMPANION_SUFFIXES, copy_database


@pytest.fixture
def unpacked(tmp_path):
    """A database that has never been packed: a small .i64 and the
    companions that actually hold it."""
    source = tmp_path / "src"
    source.mkdir()
    database = source / "hexx64.dll.i64"
    database.write_bytes(b"stub")
    for suffix, size in ((".id0", 4096), (".id1", 2048), (".id2", 64),
                         (".nam", 128), (".til", 256)):
        (source / f"hexx64.dll{suffix}").write_bytes(b"x" * size)
    return database


def test_the_companions_come_too(unpacked, tmp_path):
    holder = tmp_path / "holder"
    holder.mkdir()
    copy_database(unpacked, holder)
    copied = {p.name for p in holder.iterdir()}
    assert copied == {"hexx64.dll.i64", "hexx64.dll.id0", "hexx64.dll.id1",
                      "hexx64.dll.id2", "hexx64.dll.nam", "hexx64.dll.til"}


def test_the_content_is_carried_not_just_the_names(unpacked, tmp_path):
    holder = tmp_path / "holder"
    holder.mkdir()
    copy_database(unpacked, holder)
    assert (holder / "hexx64.dll.id0").read_bytes() == b"x" * 4096


def test_the_real_filename_is_kept(unpacked, tmp_path):
    """BinExport records the name it was given: a temporary name ends up in
    the .BinExport, in the .BinDiff's file table, and on screen."""
    holder = tmp_path / "holder"
    holder.mkdir()
    assert Path(copy_database(unpacked, holder)).name == "hexx64.dll.i64"


def test_exports_beside_the_database_are_left_alone(unpacked, tmp_path):
    """Globbing the stem also matches hexx64.dll.primary.BinExport and its
    .types.json, so it copied 22 MB of export beside every 12 MB database,
    on every diff."""
    beside = unpacked.parent
    (beside / "hexx64.dll.primary.BinExport").write_bytes(b"y" * 10_000)
    (beside / "hexx64.dll.primary.BinExport.types.json").write_bytes(b"{}")
    (beside / "hexx64.dll.BinDiff").write_bytes(b"z")

    holder = tmp_path / "holder"
    holder.mkdir()
    copy_database(unpacked, holder)
    copied = {p.name for p in holder.iterdir()}
    assert not any("BinExport" in name or "BinDiff" in name for name in copied)


def test_a_packed_database_copies_on_its_own(tmp_path):
    """Nothing beside it, and that is not an error."""
    source = tmp_path / "src"
    source.mkdir()
    database = source / "packed.i64"
    database.write_bytes(b"whole database")
    holder = tmp_path / "holder"
    holder.mkdir()
    copy_database(database, holder)
    assert [p.name for p in holder.iterdir()] == ["packed.i64"]


def test_the_suffix_list_covers_what_ida_writes(tmp_path):
    for suffix in (".id0", ".id1", ".id2", ".nam", ".til"):
        assert suffix in IDA_COMPANION_SUFFIXES


def test_a_directory_named_like_a_companion_is_skipped(tmp_path):
    """is_file(), because shutil.copyfile on a directory raises and would
    fail a diff over something that is not a database file at all."""
    source = tmp_path / "src"
    source.mkdir()
    database = source / "a.i64"
    database.write_bytes(b"db")
    (source / "a.id0").mkdir()
    holder = tmp_path / "holder"
    holder.mkdir()
    copy_database(database, holder)
    assert [p.name for p in holder.iterdir()] == ["a.i64"]
