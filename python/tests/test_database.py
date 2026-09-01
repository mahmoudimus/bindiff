"""Tests for the read/write .BinDiff layer.

Every case runs against a database the engine actually produced, so the schema
assumptions are checked against reality rather than against a fixture someone
wrote by hand.
"""

import sqlite3

import pytest

from bindiff.database import BinDiffDatabase, MANUAL_ALGORITHM, _to_signed, _to_unsigned

pytestmark = pytest.mark.requires_extension


@pytest.fixture(scope="module")
def diffed(bindiff_module, insider_pair, tmp_path_factory):
    """A real .BinDiff produced by the engine."""
    primary, secondary = insider_pair
    out = tmp_path_factory.mktemp("db") / "insider.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(out)) == 0
    return out


@pytest.fixture
def writable(diffed, tmp_path):
    """A private copy, so mutating tests cannot affect each other."""
    copy = tmp_path / "writable.BinDiff"
    copy.write_bytes(diffed.read_bytes())
    with BinDiffDatabase.open(str(copy), read_only=False) as db:
        yield db


def test_address_sign_round_trip():
    """Addresses are signed BIGINTs on disk; high addresses must survive."""
    for address in (0x0, 0x401000, 0x7FFFFFFFFFFFFFFF,
                    0x8000000000000000, 0xFFFFFFFFFFFFFFFF):
        assert _to_unsigned(_to_signed(address)) == address


def test_open_rejects_a_non_bindiff_file(tmp_path):
    path = tmp_path / "empty.sqlite"
    sqlite3.connect(str(path)).close()
    with pytest.raises(ValueError, match="not a .BinDiff database"):
        BinDiffDatabase.open(str(path))


def test_open_refuses_to_create(tmp_path):
    """A typo must not silently produce an empty database."""
    with pytest.raises(FileNotFoundError):
        BinDiffDatabase.open(str(tmp_path / "nope.BinDiff"))


def test_matches_round_trip(diffed):
    with BinDiffDatabase.open(str(diffed)) as db:
        matches = db.matches()
        assert matches
        assert len(matches) == db.num_matches() == len(db)

        similarities = [m.similarity for m in matches]
        assert similarities == sorted(similarities, reverse=True)

        for match in matches:
            assert match.address_primary > 0
            assert match.address_secondary > 0
            assert 0.0 <= match.similarity <= 1.0
            assert match.algorithm, "every match should name its algorithm"


def test_files_report_totals_including_library_code(diffed):
    with BinDiffDatabase.open(str(diffed)) as db:
        files = db.files()
        assert len(files) == 2
        # The engine reports 219/187 total functions for this pair, of which
        # 117/114 are non-library; the totals must be the larger figure.
        assert files[0].functions > db.num_matches()
        for info in files:
            assert info.filename
            assert info.functions > 0


def test_read_only_by_default(diffed):
    with BinDiffDatabase.open(str(diffed)) as db:
        with pytest.raises(PermissionError):
            db.add_manual_match(0xDEAD0000, 0xBEEF0000)


def test_add_manual_match(writable):
    before = writable.num_matches()
    match = writable.add_manual_match(0xDEAD0000, 0xBEEF0000,
                                      name_primary="a", name_secondary="b")

    assert writable.num_matches() == before + 1
    assert match.manual
    assert match.confidence == 1.0
    assert match.algorithm == MANUAL_ALGORITHM
    assert match.address_primary == 0xDEAD0000
    assert match.name_primary == "a"

    # And it is visible through the normal lookup path.
    found = writable.find_match(primary=0xDEAD0000)
    assert found is not None and found.address_secondary == 0xBEEF0000


def test_add_manual_match_rejects_already_matched(writable):
    existing = writable.matches()[0]
    with pytest.raises(ValueError, match="already matched"):
        writable.add_manual_match(existing.address_primary, 0xBEEF0000)
    with pytest.raises(ValueError, match="already matched"):
        writable.add_manual_match(0xDEAD0000, existing.address_secondary)


def test_delete_matches_removes_dependent_rows(writable):
    match = max(writable.matches(), key=lambda m: m.basic_blocks)
    assert match.basic_blocks > 0, "need a match with basic blocks to test this"

    connection = writable._connection
    before_bb = connection.execute(
        "SELECT COUNT(*) FROM basicblock WHERE functionid = ?",
        (match.id,)).fetchone()[0]
    assert before_bb > 0

    assert writable.delete_matches([match.id]) == 1
    assert writable.find_match(primary=match.address_primary) is None
    assert connection.execute(
        "SELECT COUNT(*) FROM basicblock WHERE functionid = ?",
        (match.id,)).fetchone()[0] == 0


def test_confirm_matches(writable):
    match = next(m for m in writable.matches() if not m.manual)
    assert writable.confirm_matches([match.id]) == 1

    updated = writable.find_match(primary=match.address_primary)
    assert updated.manual
    assert updated.confidence == 1.0
    assert updated.algorithm == MANUAL_ALGORITHM


def test_set_comments_ported(writable):
    match = writable.matches()[0]
    assert not match.comments_ported

    assert writable.set_comments_ported([match.id]) == 1
    assert writable.find_match(primary=match.address_primary).comments_ported

    assert writable.set_comments_ported([match.id], ported=False) == 1
    assert not writable.find_match(primary=match.address_primary).comments_ported


def test_rollback_discards_edits(diffed, tmp_path):
    copy = tmp_path / "rollback.BinDiff"
    copy.write_bytes(diffed.read_bytes())

    with BinDiffDatabase.open(str(copy), read_only=False) as db:
        before = db.num_matches()
        db.add_manual_match(0xDEAD0000, 0xBEEF0000)
        assert db.num_matches() == before + 1
        db.rollback()
        assert db.num_matches() == before


def test_commit_persists_edits(diffed, tmp_path):
    copy = tmp_path / "commit.BinDiff"
    copy.write_bytes(diffed.read_bytes())

    with BinDiffDatabase.open(str(copy), read_only=False) as db:
        before = db.num_matches()
        db.add_manual_match(0xDEAD0000, 0xBEEF0000)
        db.commit()

    # Reopened from disk: this is the check that WriteToFile never did.
    with BinDiffDatabase.open(str(copy)) as db:
        assert db.num_matches() == before + 1
        assert db.find_match(primary=0xDEAD0000).manual


def test_edits_are_visible_to_the_engine_reader(bindiff_module, diffed, tmp_path):
    """A database this layer wrote must still read back through the bindings."""
    copy = tmp_path / "interop.BinDiff"
    copy.write_bytes(diffed.read_bytes())

    with BinDiffDatabase.open(str(copy), read_only=False) as db:
        before = db.num_matches()
        db.add_manual_match(0xDEAD0000, 0xBEEF0000)
        db.commit()

    matches = bindiff_module.load_matches(str(copy))
    assert len(matches) == before + 1

    added = [m for m in matches if m.primary_address == 0xDEAD0000]
    assert len(added) == 1
    assert added[0].is_manual, "the C++ reader should agree this match is manual"
    assert added[0].algorithm_name == MANUAL_ALGORITHM


class TestRecordingPortedNames:
    """A .BinDiff stores the names the differ saw. Porting renames the function
    in IDA; without writing it back, the result file describes a function that
    no longer answers to that name -- the matched table goes on showing
    sub_1300B17C0 for something that is now mba_remove_insn."""

    def test_the_primary_name_is_updated(self, writable):
        before = {m.id: m.name_primary for m in writable.matches()}
        target = next(iter(before))
        assert writable.set_primary_names({target: "ported_name"}) == 1
        after = {m.id: m.name_primary for m in writable.matches()}
        assert after[target] == "ported_name"
        # And nothing else moved.
        assert ({k: v for k, v in after.items() if k != target}
                == {k: v for k, v in before.items() if k != target})

    def test_an_empty_name_is_ignored(self, writable):
        """Nothing to record, and blanking a name would lose information."""
        target = next(m.id for m in writable.matches())
        assert writable.set_primary_names({target: ""}) == 0

    def test_nothing_to_do_is_zero(self, writable):
        assert writable.set_primary_names({}) == 0

    def test_it_is_staged_like_every_other_edit(self, writable):
        """Visible on this connection; on disk only after commit."""
        target = next(m.id for m in writable.matches())
        writable.set_primary_names({target: "staged_only"})
        assert any(m.name_primary == "staged_only"
                   for m in writable.matches())
        with BinDiffDatabase.open(writable.path, read_only=True) as fresh:
            assert not any(m.name_primary == "staged_only"
                           for m in fresh.matches())


class TestUnsavedChanges:
    """What auto-save asks before committing.

    sqlite already tracks it, so this reads the transaction state rather than
    keeping a flag -- a flag would go stale the first time a new edit method
    forgot to set it, and the failure would be silent data loss on Revert.
    """

    def test_a_fresh_connection_is_clean(self, writable):
        assert writable.has_unsaved_changes is False

    def test_an_edit_makes_it_dirty(self, writable):
        target = next(m.id for m in writable.matches())
        writable.confirm_matches([target])
        assert writable.has_unsaved_changes is True

    def test_commit_makes_it_clean_again(self, writable):
        target = next(m.id for m in writable.matches())
        writable.confirm_matches([target])
        writable.commit()
        assert writable.has_unsaved_changes is False

    def test_rollback_makes_it_clean_again(self, writable):
        target = next(m.id for m in writable.matches())
        writable.confirm_matches([target])
        writable.rollback()
        assert writable.has_unsaved_changes is False

    def test_it_notices_a_ported_name(self, writable):
        """Every edit method must show up here, including the newest one."""
        target = next(m.id for m in writable.matches())
        writable.set_primary_names({target: "ported"})
        assert writable.has_unsaved_changes is True
