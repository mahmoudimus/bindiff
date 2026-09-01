"""The plugin's data layer: the open .BinDiff and the exports beside it.

Deliberately free of Qt and IDA: it opens databases, keeps the current one,
and hands view objects to whoever asks. The session (session.py) owns state
and selection; this owns files and caches. Split out of bindiff_plugin.py so
it can be tested on the host and so the entry module is lifecycle only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

from bindiff.comments import portable_comments as _portable_comments


def _describe_comments(planned, result) -> str:
    """What happened to the comments, in enough detail to act on.

    "wrote 2 comment(s)" cannot answer the only question worth asking when
    one goes missing: was it never planned, or did IDA refuse it? The two
    have different causes -- an instruction that did not match, against an
    address the database will not take a comment on -- and different fixes.
    """
    if not planned:
        return ("nothing to write -- the secondary export has no comment on "
                "the matched instructions of this selection")
    kinds = {}
    for port in planned:
        kinds[port.kind] = kinds.get(port.kind, 0) + 1
    detail = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
    message = f"{result.applied} of {len(planned)} written ({detail})"
    if result.failed:
        where = ", ".join(f"0x{a:X}" for a in result.failed_addresses[:5])
        more = ("..." if len(result.failed_addresses) > 5 else "")
        message += f"; {result.failed} refused by IDA at {where}{more}"
    return message


class BinDiffController:
    """Plugin state and the operations the menu actions invoke.

    Deliberately free of Qt: it opens databases, keeps the current one, and
    hands view objects to the panels. That makes the interesting half testable
    without a display.
    """

    def __init__(self) -> None:
        self._database = None
        self._matched_form = None
        self._unmatched_forms = {}
        self._statistics_form = None
        self._binexports = (None, None)
        self._details = None
        self._functions = {}
        self._comments: Optional[dict] = None
        self._comments_path: Optional[str] = None
        self._stack_names = None

    @property
    def database(self):
        return self._database

    @property
    def loaded(self) -> bool:
        return self._database is not None

    def open_database(self, path: str, read_only: bool = False):
        """Opens a .BinDiff file, replacing whatever was open."""
        from bindiff import BinDiffDatabase

        if self._database is not None:
            self._database.close()
            self._database = None
        self._database = BinDiffDatabase.open(path, read_only=read_only)
        self._binexports = (None, None)
        self._details = None
        self._functions = {}
        self._comments = None
        self._comments_path = None
        self._stack_names = None
        return self._database

    def close(self) -> None:
        if self._database is not None:
            self._database.close()
            self._database = None

    def match_rows(self):
        from ida_plugin.ui_logic import rows_from_database

        if self._database is None:
            return []
        primary, secondary = self._function_details()
        return rows_from_database(self._database, primary, secondary)

    def _function_details(self) -> tuple:
        """Per-side totals for the count columns, loaded once and kept.

        Resolving them means walking the whole instruction table of each
        .BinExport, so this is cached: doing it per refresh would make the
        table unusable on a large binary. Missing exports are not an error --
        the columns read zero and every other column still works.
        """
        from bindiff.binexport import read_function_details

        if self._details is not None:
            return self._details

        loaded = []
        for path in self.resolve_binexports():
            if path is None:
                loaded.append({})
                continue
            try:
                loaded.append(read_function_details(path))
            except Exception:
                loaded.append({})
        self._details = tuple(loaded)
        return self._details

    def function_details(self) -> tuple:
        """Public name for the per-side totals; the session reads them."""
        return self._function_details()

    def statistic_rows(self):
        from ida_plugin.ui_logic import build_statistics

        if self._database is None:
            return []
        return build_statistics(self._database.files(),
                                self._database.num_matches())

    # -- inputs -------------------------------------------------------------

    def resolve_binexports(self) -> tuple:
        """Finds the two .BinExport inputs for the open result file.

        Unmatched views and the per-side counts need them: a .BinDiff records
        matches only. Guessed from the "<primary>_vs_<secondary>.BinDiff"
        naming the engine uses; either may come back None, and the caller is
        expected to ask rather than guess wrongly.
        """
        from bindiff.binexport import find_binexports_for

        if self._database is None:
            return (None, None)
        if self._binexports == (None, None):
            self._binexports = find_binexports_for(self._database.path)
        return self._binexports

    def recorded_input_name(self, side: int) -> Optional[str]:
        """What the result file calls one of its inputs.

        A .BinDiff records the filename it was given for each side, which is
        what Statistics shows. Used to name the file in a prompt rather than
        asking for "the secondary .BinExport" and leaving the user to work out
        which file that is.
        """
        if self._database is None:
            return None
        try:
            files = self._database.files()
        except Exception:
            return None
        if side < len(files):
            name = files[side].filename
            return Path(name).name if name else None
        return None

    def matches_for(self, match_ids=None):
        """The match rows behind a selection, for reporting on them."""
        if self._database is None:
            return []
        matches = self._database.matches()
        if match_ids is None:
            return matches
        wanted = set(match_ids)
        return [m for m in matches if m.id in wanted]

    def set_binexports(self, primary: Optional[str],
                       secondary: Optional[str]) -> None:
        self._binexports = (primary, secondary)
        # Every cache is keyed on the old pair and none would notice.
        self._details = None
        self._functions = {}
        self._comments = None
        self._comments_path = None
        self._stack_names = None

    def _exported_functions(self, path: str):
        """Every function in one .BinExport, parsed once and kept.

        read_functions parses the whole protobuf, which is seconds on a large
        export. The unmatched lists are now refreshed after every edit, so
        without this a delete over a multi-selection would re-parse both
        exports and stall the UI for exactly as long as the diff's inputs are
        big.
        """
        from bindiff.binexport import read_functions

        if path not in self._functions:
            self._functions[path] = read_functions(path)
        return self._functions[path]

    def export_available(self, side: int) -> bool:
        """Whether one side's .BinExport is known and on disk.

        A property of the open result, not an error to raise when a view is
        opened: the scope tab shows it as a state and offers to locate the
        file, so the answer has to be cheap and side-effect free.
        """
        path = self.resolve_binexports()[side]
        return path is not None and Path(path).is_file()

    def portable_comments(self) -> Dict[int, list]:
        """Every portable comment in the secondary export, by address.

        Parsed once per export and kept: read_comments walks the whole
        protobuf, which is seconds on a large binary, and the inspector asks
        for the count on every selection change.
        """
        secondary = self.resolve_binexports()[1]
        if secondary is None:
            raise FileNotFoundError(
                "the secondary .BinExport was not found next to the result "
                "file; comments live there, not in the .BinDiff")
        if self._comments is None or self._comments_path != secondary:
            self._comments = _portable_comments(secondary)
            self._comments_path = secondary
        return self._comments

    def comment_counts(self) -> Dict[int, int]:
        """How many comments each secondary function offers. {} without an
        export -- a count of zero is what the table shows either way."""
        try:
            comments = self.portable_comments()
        except Exception:
            return {}
        return {address: len(found) for address, found in comments.items()}

    def _unmatched(self, side: int):
        from ida_plugin.ui_logic import unmatched_functions

        if self._database is None:
            return []
        path = self.resolve_binexports()[side]
        if path is None:
            raise FileNotFoundError(
                "the .BinExport for this side was not found next to the result "
                "file; set it explicitly to list unmatched functions")

        matches = self._database.matches()
        matched = [m.address_primary if side == 0 else m.address_secondary
                   for m in matches]
        return unmatched_functions(self._exported_functions(path), matched)

    def unmatched_primary(self):
        return self._unmatched(0)

    def unmatched_secondary(self):
        return self._unmatched(1)

    # -- edits --------------------------------------------------------------

    def _require_writable(self):
        if self._database is None:
            raise RuntimeError("no result file is open")
        return self._database

    def delete_matches(self, match_ids) -> int:
        return self._require_writable().delete_matches(match_ids)

    def confirm_matches(self, match_ids) -> int:
        return self._require_writable().confirm_matches(match_ids)

    def add_manual_match(self, primary_address: int, secondary_address: int):
        return self._require_writable().add_manual_match(primary_address,
                                                         secondary_address)

    def record_ported_names(self, ports) -> int:
        """Writes ported names into the result file, so it agrees with IDA."""
        database = self._require_writable()
        return database.set_primary_names(
            {port.match_id: port.new_name for port in ports})

    def mark_imported(self, match_ids) -> int:
        """Records that these matches had something written into IDA.

        The .BinDiff has one flag for this, `commentsported`, and it has
        always meant more than its name: upstream sets it from PortComments(),
        which ports symbols as well. Kept to that meaning rather than given a
        column of our own -- a result file has to stay readable by the C++
        plugin and the Java UI.

        Nothing wrote it before, so the "Comments Ported" column the view has
        always had was permanently empty and its sort did nothing.
        """
        ids = sorted(set(match_ids))
        if not ids:
            return 0
        return self._require_writable().set_comments_ported(ids)

    def save(self) -> None:
        self._require_writable().commit()

    def revert(self) -> None:
        self._require_writable().rollback()

    # -- porting ------------------------------------------------------------

    def plan_symbol_ports(self, match_ids=None, **kwargs):
        from ida_plugin.porting import plan_symbol_ports

        database = self._require_writable()
        matches = database.matches()
        if match_ids is not None:
            wanted = set(match_ids)
            matches = [m for m in matches if m.id in wanted]
        return plan_symbol_ports(matches, **kwargs)

    def types_sidecar(self) -> Optional[str]:
        """The secondary's type sidecar, if one has been produced.

        Beside the secondary .BinExport, or beside the database it came from.
        Types cannot travel in a .BinExport -- BinExport2 has no type table --
        so this is a separate file and its absence is the normal state until
        somebody asks for types.
        """
        from bindiff.typeinfo import types_path_for

        secondary = self.resolve_binexports()[1]
        if secondary is None:
            return None
        for candidate in (types_path_for(secondary),
                          types_path_for(str(Path(secondary).with_suffix("")))):
            if Path(candidate).is_file():
                return candidate
        return None

    def plan_type_ports(self, match_ids=None, *,
                        min_similarity: float = None,
                        min_confidence: float = None):
        """Which prototypes to apply, and which types to define first.

        Returns (plan, ports) where ports is a list of (address, declaration).
        The plan covers only what this database is missing: it asks IDA what
        it already has, so a type both sides define is not redefined.
        """
        import json

        from ida_plugin.porting import (DEFAULT_PORT_MIN_CONFIDENCE,
                                        DEFAULT_PORT_MIN_SIMILARITY)
        from bindiff.typeinfo import FunctionType, from_json, plan_types
        from bindiff.typeinfo_ida import existing_type_names

        if min_similarity is None:
            min_similarity = DEFAULT_PORT_MIN_SIMILARITY
        if min_confidence is None:
            min_confidence = DEFAULT_PORT_MIN_CONFIDENCE

        database = self._require_writable()
        sidecar = self.types_sidecar()
        if sidecar is None:
            raise FileNotFoundError(
                "no type sidecar for the secondary; types are not in a "
                ".BinExport and have to be read out of its database")

        declarations, functions = from_json(
            json.loads(Path(sidecar).read_text(encoding="utf-8")))
        by_address = {f.address: f for f in functions}

        wanted = set(match_ids) if match_ids is not None else None
        needed, ports = [], []
        for match in database.matches():
            if wanted is not None and match.id not in wanted:
                continue
            if (match.similarity < min_similarity
                    or match.confidence < min_confidence):
                continue
            source = by_address.get(match.address_secondary)
            if source is None:
                continue
            needed.append(source)
            ports.append((match.address_primary, source.declaration))

        plan = plan_types(declarations, needed,
                          already_present=existing_type_names())
        return plan, ports

    def plan_pseudocode_ports(self, match_ids=None, *,
                              min_similarity: float = None,
                              min_confidence: float = None):
        """Decompiler comments, moved onto this database's addresses.

        Lives in the type sidecar rather than the .BinExport, for the same
        reason types do: BinExport2's comment table is the disassembly's, and
        a comment written in the pseudocode window is not in it.

        Every address is translated through the match's own instruction
        pairs. One that did not match is dropped: Hex-Rays takes any treeloc
        without complaint and then discards it as an orphan at the next
        decompilation, so a guess here would read as a comment that ported
        and then vanished.
        """
        import json

        from bindiff.pseudocode import by_function, translate
        from bindiff.typeinfo import pseudocode_from_json
        from ida_plugin.porting import (DEFAULT_PORT_MIN_CONFIDENCE,
                                        DEFAULT_PORT_MIN_SIMILARITY)

        if min_similarity is None:
            min_similarity = DEFAULT_PORT_MIN_SIMILARITY
        if min_confidence is None:
            min_confidence = DEFAULT_PORT_MIN_CONFIDENCE

        database = self._require_writable()
        sidecar = self.types_sidecar()
        if sidecar is None:
            raise FileNotFoundError(
                "no sidecar for the secondary; decompiler comments are not "
                "in a .BinExport and have to be read out of its database")
        stored = by_function(pseudocode_from_json(
            json.loads(Path(sidecar).read_text(encoding="utf-8"))))
        if not stored:
            return []

        wanted = set(match_ids) if match_ids is not None else None
        selected = [match for match in database.matches()
                    if (wanted is None or match.id in wanted)
                    and match.similarity >= min_similarity
                    and match.confidence >= min_confidence
                    and stored.get(match.address_secondary)]
        if not selected:
            return []
        # One query, for the same reason plan_comment_ports takes one: asking
        # per match walks an unindexed join once per match. Only the matches
        # that have a comment are asked about, which is usually a handful.
        pairs_by_match = database.instruction_matches_for(
            [match.id for match in selected])

        ports = []
        for match in selected:
            # The entry pair is not always among the instruction matches --
            # a changed prologue starts the pairing a few bytes in -- so it
            # is added explicitly, the same way function comments are.
            address_map = {match.address_secondary: match.address_primary}
            address_map.update(
                {secondary: primary for primary, secondary
                 in pairs_by_match.get(match.id, ())})
            ports.extend(translate(stored[match.address_secondary],
                                   address_map, match.address_primary))
        return ports

    def plan_stack_name_ports(self, match_ids=None, **kwargs):
        """Stack variable names, from the secondary export.

        Upstream issue #13: "Variable names are not being imported anymore".
        BinExport2 has no locals table, which is what makes it look
        impossible -- but a stack operand is an IMMEDIATE_INT expression
        carrying its own name, so the names are there.
        """
        from bindiff.stack_names import stack_names_by_operand
        from ida_plugin.porting import plan_stack_name_ports

        database = self._require_writable()
        secondary = self.resolve_binexports()[1]
        if secondary is None:
            raise FileNotFoundError(
                "the secondary .BinExport was not found next to the result "
                "file; stack variable names live there, not in the .BinDiff")
        if self._stack_names is None:
            self._stack_names = stack_names_by_operand(secondary)
        return plan_stack_name_ports(database, self._stack_names,
                                     match_ids=match_ids, **kwargs)

    def plan_comment_ports(self, match_ids=None, **kwargs):
        """Needs the secondary .BinExport: comments are not in a .BinDiff."""
        from ida_plugin.porting import plan_comment_ports

        database = self._require_writable()
        # portable_comments, not bindiff.load_comments: the engine's
        # reader keys comments by (address, operand) and keeps one per
        # address, which for a documented function was its own name
        # rather than the documentation.
        return plan_comment_ports(database,
                                  self.portable_comments(),
                                  match_ids=match_ids, **kwargs)
