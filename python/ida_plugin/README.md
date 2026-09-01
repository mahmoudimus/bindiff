# BinDiff plugin for IDA Pro

A Python plugin that runs a diff and shows the result inside IDA. The engine
is the same C++ one the `bindiff` CLI uses, reached either through the Cython
bindings or through a worker process; this package is the surface over it.

Comparing runs a worker so IDA stays usable. Reading and editing a result is
`bindiff.database`, plain sqlite3 over the `.BinDiff` file.

## What is on screen

One dock tab, **BinDiff**, and one companion, **Match inspector**.

The tab has a run strip at the top -- the file to compare with, a Compare
button that becomes the progress bar and a Cancel while a diff runs, and the
open result with Save and Close -- then four scopes as tabs: **Matches**,
**Only here**, **Only there**, **Overview**. The status line at the bottom
counts what is shown, what exists and what is selected, and carries the
"follow selection" toggle -- off by default -- that jumps IDA as the
selection moves.

The inspector shows one match: its two sides, the engine's numbers, the step
that found it, what the change flags mean, and the buttons for the actions
that apply to a single match. It is a second dock, so it can sit beside the
table or be closed.

## Lenses

The Matches table is used for three different jobs, so it has three saved
filter-plus-column sets rather than one table with switches:

- **Needs a look** -- anything not Strong, or whose graph changed.
- **Ready to port** -- the other side has a name worth carrying over. This is
  the lens that shows the Outcome column and the port footer.
- **All** -- everything; the search field does the narrowing.

## Search

Free text matches a name or an address. A token of the form `key:value`
becomes a removable chip:

| key | values |
| --- | --- |
| `sim:` | a number 0-1, optionally with `<`, `<=`, `>`, `>=`, `=`; bare means `>=` |
| `coverage:` | same forms as `sim:` |
| `changed:` | `graph`, `instructions`, `operands`, `jumps`, `entry`, `loops`, `calls`, or `any` / `none` |
| `state:` | `unverified`, `verified`, `by-hand`, `imported`, `ported`, `skipped`, `replaced`, `refused` |
| `found-by:` | any substring of the engine step's name, e.g. `hash` |
| `trust:` | `strong`, `check`, `weak` |

A token that looks like a chip but does not parse is searched as text. The
field never refuses to search.

## Porting, and what it records

A port writes into *this* database, where a wrong name reads afterwards like
analysis somebody did. So the footer under the Ready to port lens shows what
a port would do before it does it: a similarity floor (0.50 by default, where
the measured precision was 93.8%), how many names would be written, and
separately how many would replace a name already here -- Review selects those
rows.

What a port did is kept per row in a session-only ledger: the State column
says ported, replaced, skipped or refused for that match, and a ported or
replaced name can be put back one row at a time. The `.BinDiff` schema is not
extended, so the ledger and the by-hand set live only as long as the session.

## Install for development

    tools/scripts/install_dev_plugin.sh

It links the manifest and the `python/` directory individually. Do not symlink
the repository root into `~/.idapro/plugins`: the build tree contains a
symlink back to the repository, IDA's scanner descends it and loads a second
copy of the plugin.

## Tests

Everything that can be tested without IDA is a pure module, and is. From
`python/`:

    python3 -m pytest tests/test_ui_logic.py tests/test_trust.py \
        tests/test_query.py tests/test_lenses.py tests/test_session.py \
        tests/test_inspection.py tests/test_porting.py tests/test_theme.py -q

`ui_logic`, `trust`, `query`, `lenses`, `inspection`, `theme` and `porting`
have no Qt and no IDA import. `panels`, `workbench` and `inspector` are
covered headless too (`test_*_headless.py`), for the parts that do not need a
widget. Anything importing `bindiff.*` needs the Cython extension, which is
why the rest of `tests/` does not run from a bare checkout.

The Qt layer, the action handlers and the graph view cannot be reached that
way, so they run inside a real IDA under Xvfb:

    tools/scripts/run_gui_tests_docker.sh

`tests/gui/gui_driver.py` is that harness. It runs *in* IDA, not in pytest:
it builds a small `.BinDiff` against the functions of the database it opened,
drives the workbench, and writes a JSON report.

## Module map

    ui_logic.py, trust.py, query.py, lenses.py, inspection.py, theme.py
                  pure view logic, no Qt and no IDA -- tested headless
    controller.py the data layer over the .BinDiff and the exports
    session.py    DiffSession: the one owner of every fact the UI shows
    panels.py     the two tables, the flow graph, the algorithm editor
    workbench.py  the dock tab that is the plugin; inspector.py its companion
    porting.py    what a port would do, and what it did
    diff_runner.py the sequence from "two files picked" to "results on screen"
    bindiff_plugin.py  plugin lifecycle, actions, and the IDA-side glue

Nothing in a view reaches into the controller: views read `session` and call
handlers the plugin supplies. `session.can(action)` is asked afresh every
time it matters.
