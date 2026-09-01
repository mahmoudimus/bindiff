"""Tests for the plugin's data layer, against a hand-built .BinDiff.

No IDA and no Qt: the controller opens the result file and the exports and
hands rows to whoever asks. A synthetic database is used because the fixture
result files need the compiled extension to produce.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ida_plugin.controller import BinDiffController


SCHEMA = """
    CREATE TABLE file (id INT, filename TEXT, exefilename TEXT,
        hash CHARACTER(40), functions INT, libfunctions INT, calls INT,
        basicblocks INT, libbasicblocks INT, edges INT, libedges INT,
        instructions INT, libinstructions INT);
    CREATE TABLE metadata (version TEXT, file1 INT, file2 INT,
        description TEXT, created DATE, modified DATE,
        similarity DOUBLE PRECISION, confidence DOUBLE PRECISION);
    CREATE TABLE functionalgorithm (id SMALLINT, name TEXT);
    CREATE TABLE basicblockalgorithm (id SMALLINT, name TEXT);
    CREATE TABLE function (id INT, address1 BIGINT, name1 TEXT,
        address2 BIGINT, name2 TEXT, similarity DOUBLE PRECISION,
        confidence DOUBLE PRECISION, flags INTEGER, algorithm SMALLINT,
        evaluate BOOLEAN, commentsported BOOLEAN, basicblocks INTEGER,
        edges INTEGER, instructions INTEGER);
    CREATE TABLE basicblock (id INT, functionid INT, address1 BIGINT,
        address2 BIGINT, algorithm SMALLINT, evaluate BOOLEAN);
    CREATE TABLE instruction (basicblockid INT, address1 BIGINT,
        address2 BIGINT);
"""


def build_database(path: Path, matches) -> Path:
    """`matches` is a list of (address1, name1, address2, name2, sim, conf,
    flags, algorithm_name). Mirrors DatabaseWriter::PrepareDatabase."""
    connection = sqlite3.connect(str(path))
    connection.executescript(SCHEMA)
    algorithms = {}
    for match in matches:
        algorithms.setdefault(match[7], len(algorithms) + 1)
    algorithms.setdefault("function: manual", len(algorithms) + 1)
    for name, ident in algorithms.items():
        connection.execute("INSERT INTO functionalgorithm VALUES (?, ?)",
                           (ident, name))
    for index, label in ((1, "primary"), (2, "secondary")):
        connection.execute(
            "INSERT INTO file VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (index, f"{label}.BinExport", label, "0" * 40, len(matches) + 2,
             1, 5, 30, 0, 20, 0, 100, 0))
    connection.execute(
        "INSERT INTO metadata VALUES (?,?,?,?,?,?,?,?)",
        ("8", 1, 2, "test", "2026-01-01", "2026-01-01", 0.5, 0.9))
    for index, (a1, n1, a2, n2, sim, conf, flags, algorithm) in enumerate(
            matches, start=1):
        connection.execute(
            "INSERT INTO function VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (index, a1, n1, a2, n2, sim, conf, flags, algorithms[algorithm],
             0, 0, 3, 2, 12))
    connection.commit()
    connection.close()
    return path


MATCHES = [
    (0x401000, "sub_401000", 0x501000, "parse_type", 0.9, 0.95, 0,
     "function: hash matching"),
    (0x402000, "main", 0x502000, "main", 1.0, 1.0, 0,
     "function: name hash matching"),
    (0x403000, "sub_403000", 0x503000, "sub_503000", 0.3, 0.4, 3,
     "function: address sequence"),
]


@pytest.fixture
def result_file(tmp_path):
    return build_database(tmp_path / "a_vs_b.BinDiff", MATCHES)


class TestOpening:
    def test_a_fresh_controller_has_nothing(self):
        controller = BinDiffController()
        assert controller.loaded is False
        assert controller.match_rows() == []
        assert controller.statistic_rows() == []

    def test_opens_and_lists_matches(self, result_file):
        controller = BinDiffController()
        controller.open_database(str(result_file))
        assert controller.loaded
        rows = controller.match_rows()
        assert [row.name_secondary for row in rows] == [
            "main", "parse_type", "sub_503000"]  # similarity descending

    def test_exports_are_not_found_beside_a_bare_result(self, result_file):
        controller = BinDiffController()
        controller.open_database(str(result_file))
        assert controller.export_available(0) is False
        assert controller.export_available(1) is False

    def test_an_export_set_explicitly_is_available(self, result_file, tmp_path):
        export = tmp_path / "secondary.BinExport"
        export.write_bytes(b"")
        controller = BinDiffController()
        controller.open_database(str(result_file))
        controller.set_binexports(None, str(export))
        assert controller.export_available(1) is True
        assert controller.export_available(0) is False


class TestCommentCounts:
    def test_counts_are_empty_without_an_export(self, result_file):
        controller = BinDiffController()
        controller.open_database(str(result_file))
        assert controller.comment_counts() == {}

    def test_counts_come_from_portable_comments_once(self, result_file,
                                                    tmp_path, monkeypatch):
        import ida_plugin.controller as module

        export = tmp_path / "secondary.BinExport"
        export.write_bytes(b"")
        calls = []

        def fake_portable_comments(path, *args, **kwargs):
            calls.append(path)
            return {0x501000: ["a", "b"], 0x502000: ["c"]}

        monkeypatch.setattr(module, "_portable_comments",
                            fake_portable_comments)
        controller = BinDiffController()
        controller.open_database(str(result_file))
        controller.set_binexports(None, str(export))
        assert controller.comment_counts() == {0x501000: 2, 0x502000: 1}
        assert controller.comment_counts() == {0x501000: 2, 0x502000: 1}
        assert len(calls) == 1, "the export was parsed more than once"

    def test_setting_a_new_export_drops_the_cache(self, result_file,
                                                  tmp_path, monkeypatch):
        import ida_plugin.controller as module

        first = tmp_path / "one.BinExport"
        second = tmp_path / "two.BinExport"
        first.write_bytes(b"")
        second.write_bytes(b"")
        monkeypatch.setattr(module, "_portable_comments",
                            lambda path, *a, **k: {0x1: [path]})
        controller = BinDiffController()
        controller.open_database(str(result_file))
        controller.set_binexports(None, str(first))
        controller.comment_counts()
        controller.set_binexports(None, str(second))
        assert controller.portable_comments() == {0x1: [str(second)]}


class TestEdits:
    def test_delete_and_confirm_go_through(self, result_file):
        controller = BinDiffController()
        controller.open_database(str(result_file))
        ids = [row.match_id for row in controller.match_rows()]
        assert controller.confirm_matches(ids[:1]) == 1
        assert controller.delete_matches(ids[1:2]) == 1
        assert len(controller.match_rows()) == 2
        controller.revert()
        assert len(controller.match_rows()) == 3
