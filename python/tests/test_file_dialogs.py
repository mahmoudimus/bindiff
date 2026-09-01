"""Static checks on the IDA file dialogs.

ask_file's second argument is the default *filename*, not a filter list. IDA
hands it to the dialog as a single glob, so "*.BinExport;*.i64;*.idb;*.*"
matches no file at all and the dialog opens with everything greyed out --
which is what happened to the "Diff against" browse button, on the one screen
where picking the right file is the whole task.

Checked by reading the source because the alternative is driving IDA's modal
dialogs, and the mistake is entirely visible in the call.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PLUGIN = Path(__file__).resolve().parents[1] / "ida_plugin"


def ask_file_defaults():
    """Every literal `defval` passed to ask_file, with where it came from."""
    for source in sorted(_PLUGIN.glob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", getattr(node.func, "id", None))
            if name != "ask_file" or len(node.args) < 2:
                continue
            # Every string in the expression, not only a bare literal: the
            # browse button passes `current or "*"`, and a conditional is
            # exactly where a bad mask would hide.
            for inner in ast.walk(node.args[1]):
                if isinstance(inner, ast.Constant) and isinstance(
                        inner.value, str):
                    yield f"{source.name}:{node.lineno}", inner.value


def test_there_are_dialogs_to_check():
    """A rename that moved every call would otherwise make this file pass by
    checking nothing."""
    assert len(list(ask_file_defaults())) >= 4


@pytest.mark.parametrize("where,default", list(ask_file_defaults()),
                         ids=lambda v: v if isinstance(v, str) else "")
def test_a_default_is_one_mask_not_a_list(where, default):
    assert ";" not in default, (
        f"{where}: ask_file takes a default filename, not a filter list; "
        f"{default!r} is one glob and matches nothing")


@pytest.mark.parametrize("where,default", list(ask_file_defaults()),
                         ids=lambda v: v if isinstance(v, str) else "")
def test_nothing_asks_for_a_dot(where, default):
    """"*.*" requires a dot in the name, so a stripped ELF -- or any binary
    without an extension -- is not selectable. "*" is the one that means
    every file."""
    assert default != "*.*", (
        f"{where}: \"*.*\" hides extensionless files; use \"*\"")
