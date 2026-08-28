"""Tests for incremental diffing and comment extraction.

These are the two capabilities that used to be stubs returning success:
ResultsWrapper::IncrementalDiff returned 0 without doing anything, and
PortComments set a flag without touching a comment.
"""

import pytest

pytestmark = [pytest.mark.requires_extension, pytest.mark.e2e]


@pytest.fixture
def restore_config(bindiff_module):
    yield
    bindiff_module.reset_config()


def test_incremental_never_loses_matches_and_converges(
        bindiff_module, insider_pair, tmp_path):
    """Re-running is monotonic and reaches a fixed point.

    It does *not* find nothing. Running incrementally over a finished diff
    picks up one more match on this fixture (116 -> 117): seeding means the
    propagation-based steps start from a fully matched neighbourhood, which the
    original diff's wave ordering never reaches. That is the point of an
    incremental pass, so the invariant to hold is monotonicity plus
    convergence, not "no change".
    """
    primary, secondary = insider_pair
    database = tmp_path / "complete.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(database)) == 0

    totals = [len(bindiff_module.load_matches(str(database)))]
    for _ in range(3):
        new_matches = bindiff_module.incremental_diff(
            str(primary), str(secondary), str(database))
        assert new_matches >= 0
        totals.append(len(bindiff_module.load_matches(str(database))))

    # Never shrinks.
    assert totals == sorted(totals)
    # And settles rather than growing on every pass.
    assert totals[-1] == totals[-2], f"did not converge: {totals}"


def test_incremental_recovers_matches_a_reduced_config_missed(
        bindiff_module, insider_pair, tmp_path, restore_config):
    """The case the feature exists for.

    Diff with a single matching algorithm, so most functions stay unmatched;
    then restore the full set and run incrementally. The new matches are the
    ones the first pass could not make, and the first pass's matches survive.
    """
    primary, secondary = insider_pair

    full_db = tmp_path / "full.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(full_db)) == 0
    full_total = len(bindiff_module.load_matches(str(full_db)))

    bindiff_module.set_config(
        {"function_matching": [{"name": "function: name hash matching",
                                "confidence": 1.0}]})
    partial_db = tmp_path / "partial.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary),
                               str(partial_db)) == 0
    partial = bindiff_module.load_matches(str(partial_db))
    assert 0 < len(partial) < full_total, "need a genuinely partial diff"
    seeded_pairs = {(m.primary_address, m.secondary_address) for m in partial}

    bindiff_module.reset_config()
    new_matches = bindiff_module.incremental_diff(
        str(primary), str(secondary), str(partial_db))

    assert new_matches > 0
    after = bindiff_module.load_matches(str(partial_db))
    assert len(after) == len(partial) + new_matches

    # Nothing from the first pass was dropped or re-paired.
    after_pairs = {(m.primary_address, m.secondary_address) for m in after}
    assert seeded_pairs <= after_pairs


def test_incremental_preserves_a_manual_match(
        bindiff_module, insider_pair, tmp_path, restore_config):
    """A manual match must survive, and must still block both functions.

    This is the property that makes seeding worth doing: the matching steps
    skip any function that already has a fixed point, so a hand-made pairing
    cannot be overwritten by an algorithm on the next pass.
    """
    from bindiff import MANUAL_ALGORITHM, BinDiffDatabase

    primary, secondary = insider_pair

    bindiff_module.set_config(
        {"function_matching": [{"name": "function: name hash matching",
                                "confidence": 1.0}]})
    database = tmp_path / "manual.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary),
                               str(database)) == 0
    bindiff_module.reset_config()

    # Pair two functions that the partial diff left unmatched.
    with BinDiffDatabase.open(str(database)) as db:
        matched_primary = {m.address_primary for m in db.matches()}
        matched_secondary = {m.address_secondary for m in db.matches()}

    full_db = tmp_path / "reference.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(full_db)) == 0
    candidate = next(
        m for m in bindiff_module.load_matches(str(full_db))
        if m.primary_address not in matched_primary
        and m.secondary_address not in matched_secondary)

    with BinDiffDatabase.open(str(database), read_only=False) as db:
        db.add_manual_match(candidate.primary_address,
                            candidate.secondary_address)
        db.commit()

    assert bindiff_module.incremental_diff(
        str(primary), str(secondary), str(database)) >= 0

    with BinDiffDatabase.open(str(database)) as db:
        survivor = db.find_match(primary=candidate.primary_address)
        assert survivor is not None, "the manual match was dropped"
        assert survivor.address_secondary == candidate.secondary_address
        assert survivor.algorithm == MANUAL_ALGORITHM, (
            "an algorithm re-matched a function that was manually paired")


def test_incremental_can_write_to_a_separate_file(
        bindiff_module, insider_pair, tmp_path):
    """Updating in place is the default, not the only option."""
    primary, secondary = insider_pair
    source = tmp_path / "source.BinDiff"
    target = tmp_path / "target.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(source)) == 0

    new_matches = bindiff_module.incremental_diff(
        str(primary), str(secondary), str(source), str(target))
    assert new_matches >= 0
    assert target.is_file()

    # The source is left exactly as it was, and the target holds everything it
    # had plus whatever the pass added.
    source_matches = len(bindiff_module.load_matches(str(source)))
    assert len(bindiff_module.load_matches(str(target))) == (
        source_matches + new_matches)


def test_incremental_reports_unreadable_inputs(bindiff_module, tmp_path,
                                               insider_pair):
    primary, secondary = insider_pair
    database = tmp_path / "x.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(database)) == 0

    assert bindiff_module.incremental_diff(
        str(tmp_path / "missing.BinExport"), str(secondary),
        str(database)) == -1
    assert bindiff_module.incremental_diff(
        str(primary), str(tmp_path / "missing.BinExport"),
        str(database)) == -2


def test_result_file_from_other_binaries_degrades_to_a_plain_diff(
        bindiff_module, fixtures_dir, insider_pair, tmp_path):
    """Seeding must not pair functions by address across unrelated binaries.

    A .BinDiff records addresses, not identities. Fed a result file from a
    different program, the addresses in it either do not exist here or belong
    to unrelated functions; the former are skipped, so the run degrades to a
    normal diff rather than producing nonsense matches.
    """
    mydoom = fixtures_dir / "mydoom"
    other_primary = mydoom / "Mydoom-vc_orig.BinExport"
    other_secondary = mydoom / "Mydoom-vc_optz.BinExport"
    if not other_primary.is_file():
        pytest.skip("mydoom fixture missing")

    foreign = tmp_path / "foreign.BinDiff"
    assert bindiff_module.diff(str(other_primary), str(other_secondary),
                               str(foreign)) == 0

    primary, secondary = insider_pair
    reference = tmp_path / "reference.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary),
                               str(reference)) == 0
    expected = len(bindiff_module.load_matches(str(reference)))

    output = tmp_path / "degraded.BinDiff"
    assert bindiff_module.incremental_diff(
        str(primary), str(secondary), str(foreign), str(output)) >= 0

    # Any address that happened to collide would leave a bogus pair behind, so
    # require the result to be no better-matched than a clean diff.
    assert len(bindiff_module.load_matches(str(output))) <= expected


class TestComments:
    def test_load_comments_returns_a_mapping(self, bindiff_module,
                                             insider_pair):
        """Comments come from the .BinExport; the .BinDiff has none."""
        primary, _secondary = insider_pair
        comments = bindiff_module.load_comments(str(primary))

        assert isinstance(comments, dict)
        for address, text in comments.items():
            assert isinstance(address, int)
            assert isinstance(text, str)
            assert text, "empty comments should be dropped, not returned"

    def test_load_comments_rejects_a_missing_file(self, bindiff_module,
                                                  tmp_path):
        with pytest.raises(Exception):
            bindiff_module.load_comments(str(tmp_path / "nope.BinExport"))
