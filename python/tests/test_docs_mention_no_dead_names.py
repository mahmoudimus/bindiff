"""Docs that name a class which no longer exists send the next reader to
grep for a ghost. Keep the two documents that describe the plugin honest."""

from pathlib import Path

# The six forms the workbench replaced, plus the Cython path the plugin no
# longer uses. Naming any of them as a *current* thing is the bug.
DEAD = ("ControlPanel", "DiffProgressForm", "MatchedFunctionsForm",
        "StatisticsForm", "UnmatchedFunctionsForm", "FilterBar",
        "BindiffResults", "results_wrapper", "ida_plugin.pyx")

# CLAUDE.md records that `results_wrapper.{h,cc}` and `ida_plugin.{pxd,pyx}`
# were deleted, and why. That is history, deliberately kept -- it stops the
# reimplementation being attempted again -- so the three names that only ever
# appear in that sentence are not checked there. The six form names are
# checked in both: nothing should describe them as existing.
DEAD_IN_CLAUDE_MD = tuple(name for name in DEAD
                          if name not in ("BindiffResults", "results_wrapper",
                                          "ida_plugin.pyx"))


def _read(relative: str) -> str:
    root = Path(__file__).resolve().parents[2]
    return (root / relative).read_text(encoding="utf-8")


def test_claude_md_names_no_deleted_class():
    text = _read("CLAUDE.md")
    for name in DEAD_IN_CLAUDE_MD:
        assert name not in text, name


def test_plugin_readme_names_no_deleted_class():
    text = _read("python/ida_plugin/README.md")
    for name in DEAD:
        assert name not in text, name
    assert "workbench" in text.lower()
