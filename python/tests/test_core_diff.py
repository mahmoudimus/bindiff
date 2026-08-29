"""End-to-end tests for the Cython bindings.

These drive the full native path -- Read() -> Diff() -> DatabaseWriter -> the
.BinDiff SQLite file -> LoadMatches()/LoadStatistics() -- against the same
fixture corpus the C++ groundtruth tests use. They are the coverage that tells
you the bindings still line up with the engine after an upstream sync; an
import test alone would not have caught the sqlite API change.
"""

import pytest

pytestmark = [pytest.mark.requires_extension, pytest.mark.e2e]


@pytest.fixture(scope="module")
def insider_diff(bindiff_module, insider_pair, tmp_path_factory):
    """Diffs the insider fixture pair once and yields the result database."""
    primary, secondary = insider_pair
    out = tmp_path_factory.mktemp("bindiff") / "insider.BinDiff"

    rc = bindiff_module.diff(str(primary), str(secondary), str(out))

    # DiffBinaries returns 0 on success and a negative code per failure stage:
    # -1/-2 reading the inputs, -3/-4 writing the database, -99 for an
    # unexpected exception.
    assert rc == 0, f"diff() failed with {rc}"
    assert out.is_file(), "diff() reported success but wrote no database"
    return out


def test_diff_produces_matches(bindiff_module, insider_diff):
    matches = bindiff_module.load_matches(str(insider_diff))

    # The two inputs are the same program built by different compilers, so the
    # differ should find a substantial number of matched functions. The exact
    # count is an engine detail; asserting it would make this a change detector.
    assert matches, "no matches found between two builds of the same program"

    for match in matches:
        assert match.primary_address > 0
        assert match.secondary_address > 0
        assert 0.0 <= match.similarity <= 1.0
        assert 0.0 <= match.confidence <= 1.0


def test_matches_are_sorted_by_similarity(bindiff_module, insider_diff):
    """LoadMatches orders by similarity DESC; callers rely on it for ranking."""
    similarities = [
        m.similarity for m in bindiff_module.load_matches(str(insider_diff))
    ]
    assert similarities == sorted(similarities, reverse=True)


def test_statistics_are_self_consistent(bindiff_module, insider_diff):
    stats = bindiff_module.load_statistics(str(insider_diff))

    # You cannot match more functions than either side has.
    assert stats.matched_function_count <= stats.primary_function_count
    assert stats.matched_function_count <= stats.secondary_function_count

    assert stats.primary_function_count > 0
    assert stats.secondary_function_count > 0

    assert 0.0 <= stats.function_similarity <= 1.0


def test_unmatched_counts_are_derived(bindiff_module, insider_diff):
    """A .BinDiff stores only matches, so unmatched counts are totals minus
    matches -- there is no unmatched-function table to read."""
    stats = bindiff_module.load_statistics(str(insider_diff))
    assert stats.primary_unmatched_function_count == (
        stats.primary_function_count - stats.matched_function_count
    )
    assert stats.primary_unmatched_function_count > 0


def test_match_count_agrees_with_statistics(bindiff_module, insider_diff):
    """The match rows and the statistics summary come from separate queries."""
    matches = bindiff_module.load_matches(str(insider_diff))
    stats = bindiff_module.load_statistics(str(insider_diff))
    assert len(matches) == stats.matched_function_count


def test_diff_rejects_missing_input(bindiff_module, tmp_path):
    """A missing input must report failure rather than write a bogus database."""
    out = tmp_path / "nonexistent.BinDiff"
    rc = bindiff_module.diff(
        str(tmp_path / "does_not_exist.BinExport"),
        str(tmp_path / "also_missing.BinExport"),
        str(out),
    )
    assert rc != 0


def test_load_matches_on_missing_database_raises(bindiff_module, tmp_path):
    """Connect() failures surface as exceptions, not as empty results.

    Before the sqlite API rebase the StatusOr from Connect() was dereferenced
    unchecked, which aborted the interpreter on an unreadable file.
    """
    with pytest.raises(Exception):
        bindiff_module.load_matches(str(tmp_path / "no_such.BinDiff"))


def test_concurrent_diffs_do_not_interfere(bindiff_module, insider_pair, tmp_path):
    """Concurrent diffs must produce identical, correct results.

    diff() releases the GIL (core.pyx uses `with nogil`) so a diff can run on a
    worker thread without freezing the host's UI. That also means concurrent
    calls genuinely execute in parallel, which puts the engine's process-wide
    state -- notably the lazily initialised config::Proto() singleton -- under
    real contention. This asserts the results agree; it deliberately makes no
    timing assertion, which would be flaky.
    """
    import threading

    primary, secondary = insider_pair
    results = {}
    errors = []

    def run(index):
        try:
            out = tmp_path / f"concurrent_{index}.BinDiff"
            rc = bindiff_module.diff(str(primary), str(secondary), str(out))
            matches = bindiff_module.load_matches(str(out))
            results[index] = (rc, len(matches))
        except Exception as exc:  # surfaced below, not swallowed
            errors.append((index, exc))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=300)
        assert not thread.is_alive(), "diff thread did not finish"

    assert not errors, f"diff raised on a worker thread: {errors}"
    assert len(results) == 4

    # Same inputs, so every thread must agree -- on the return code and on how
    # many matches it found.
    assert {rc for rc, _ in results.values()} == {0}
    match_counts = {count for _, count in results.values()}
    assert len(match_counts) == 1, f"threads disagreed on match count: {results}"


class TestProgressAndCancellation:
    """A long diff has to be watchable and stoppable.

    The engine reports before each matching step and on each round of
    propagating matches through the call graph -- propagation is where a step
    spends its time, so a callback that only saw step boundaries would go quiet
    for exactly as long as the work takes.

    Cancelling keeps what was matched. That is worth more here than it would be
    for a search: the steps run strongest first, so an interrupted diff has the
    matches worth having and is missing what the weakest heuristics would have
    guessed at.
    """

    def test_progress_is_reported(self, bindiff_module, insider_pair, tmp_path):
        primary, secondary = insider_pair
        seen = []

        assert bindiff_module.diff(
            str(primary), str(secondary), str(tmp_path / "p.BinDiff"),
            progress=seen.append) == 0

        assert seen, "the callback was never invoked"
        for state in seen:
            assert 0 <= state["step_index"] < state["step_count"]
            assert state["step_name"]
            assert state["matches"] >= 0
        # Steps run in configuration order and never go backwards.
        indices = [s["step_index"] for s in seen]
        assert indices == sorted(indices)
        # Matches only accumulate.
        counts = [s["matches"] for s in seen]
        assert counts == sorted(counts)
        assert counts[-1] > 0, "progress never reported a single match"

    def test_returning_none_keeps_going(self, bindiff_module, insider_pair,
                                        tmp_path):
        """Only an explicit False cancels.

        Anyone writing a progress callback for the first time writes one that
        prints and returns None; that must not silently truncate the diff.
        """
        primary, secondary = insider_pair
        calls = []

        def watcher(state):
            calls.append(state)
            return None

        with_callback = tmp_path / "none.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary),
                                   str(with_callback), progress=watcher) == 0
        without = tmp_path / "plain.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary),
                                   str(without)) == 0

        assert calls
        assert (len(bindiff_module.load_matches(str(with_callback)))
                == len(bindiff_module.load_matches(str(without))))

    def test_cancelling_keeps_what_was_matched(self, bindiff_module,
                                               insider_pair, tmp_path):
        primary, secondary = insider_pair

        def stop_once_matching(state):
            # Not a call count: the earliest steps match nothing on this pair
            # (two different compilers, so nothing is byte-identical), and
            # stopping before any work was kept would prove nothing.
            return state["matches"] == 0

        partial_path = tmp_path / "partial.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary),
                                   str(partial_path),
                                   progress=stop_once_matching) == 0
        complete_path = tmp_path / "complete.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary),
                                   str(complete_path)) == 0

        partial = bindiff_module.load_matches(str(partial_path))
        complete = bindiff_module.load_matches(str(complete_path))
        assert partial, "cancelling threw away everything"
        assert len(partial) < len(complete), "cancelling stopped nothing"

    def test_cancelling_immediately_still_writes_a_database(
            self, bindiff_module, insider_pair, tmp_path):
        """An empty result is a result: the caller asked to stop at once."""
        primary, secondary = insider_pair
        output = tmp_path / "empty.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary), str(output),
                                   progress=lambda state: False) == 0
        assert output.is_file()
        assert bindiff_module.load_matches(str(output)) == []

    def test_an_exception_in_the_callback_propagates(self, bindiff_module,
                                                     insider_pair, tmp_path):
        """It cancels the diff, and the caller hears about it.

        Swallowing it would return a success code for a run that was aborted by
        accident, and the exception cannot be let out of the trampoline itself:
        it would unwind through C++ frames that know nothing about it.
        """
        primary, secondary = insider_pair

        class Boom(Exception):
            pass

        def explode(state):
            raise Boom("callback failed")

        with pytest.raises(Boom, match="callback failed"):
            bindiff_module.diff(str(primary), str(secondary),
                                str(tmp_path / "boom.BinDiff"),
                                progress=explode)

    def test_the_callback_is_not_called_again_after_it_raises(
            self, bindiff_module, insider_pair, tmp_path):
        primary, secondary = insider_pair
        calls = []

        def explode(state):
            calls.append(state)
            raise RuntimeError("once")

        with pytest.raises(RuntimeError):
            bindiff_module.diff(str(primary), str(secondary),
                                str(tmp_path / "once.BinDiff"),
                                progress=explode)
        assert len(calls) == 1, f"called {len(calls)} times after raising"

    def test_a_non_callable_is_rejected(self, bindiff_module, insider_pair,
                                        tmp_path):
        primary, secondary = insider_pair
        with pytest.raises(TypeError, match="callable"):
            bindiff_module.diff(str(primary), str(secondary),
                                str(tmp_path / "bad.BinDiff"),
                                progress="not callable")

    def test_no_callback_is_the_old_behaviour(self, bindiff_module,
                                              insider_pair, tmp_path):
        primary, secondary = insider_pair
        a = tmp_path / "a.BinDiff"
        b = tmp_path / "b.BinDiff"
        assert bindiff_module.diff(str(primary), str(secondary), str(a)) == 0
        assert bindiff_module.diff(str(primary), str(secondary), str(b),
                                   progress=None) == 0
        assert (len(bindiff_module.load_matches(str(a)))
                == len(bindiff_module.load_matches(str(b))))
