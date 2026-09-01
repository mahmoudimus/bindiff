"""One search field, structured.

Free text matches a name or an address, as the old filter box did. A token
of the form `key:value` becomes a chip: `sim:<0.8`, `changed:instructions`,
`state:unverified`, `found-by:hash`. Chips can be read back and removed one
at a time, which is what two spinners and four unlabelled checkboxes could
not offer. A token that looks like a chip but does not parse is treated as
text rather than rejected -- the field must never refuse to search.

No Qt and no IDA.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ida_plugin.ui_logic import (
    STATE_BY_HAND, STATE_IMPORTED, STATE_NONE, STATE_PORTED, STATE_REFUSED,
    STATE_REPLACED, STATE_SKIPPED, STATE_VERIFIED, ChangeType, MatchRow,
    parse_address_query, text_query_narrows)

KEYS = ("sim", "coverage", "changed", "state", "found-by", "trust")

_ASPECTS = {
    "graph": ChangeType.STRUCTURAL,
    "instr": ChangeType.INSTRUCTIONS,
    "instructions": ChangeType.INSTRUCTIONS,
    "operands": ChangeType.OPERANDS,
    "jumps": ChangeType.BRANCH_INVERSION,
    "entry": ChangeType.ENTRY_POINT,
    "loops": ChangeType.LOOPS,
    "calls": ChangeType.CALLS,
}
_STATES = {
    "unverified": STATE_NONE, "verified": STATE_VERIFIED,
    "by-hand": STATE_BY_HAND, "imported": STATE_IMPORTED,
    "ported": STATE_PORTED, "skipped": STATE_SKIPPED,
    "replaced": STATE_REPLACED, "refused": STATE_REFUSED,
}
_TRUSTS = ("strong", "check", "weak")
_NUMBER = re.compile(r"^(<=|>=|<|>|=)?(\d*\.?\d+)$")


@dataclass(frozen=True)
class Term:
    key: str
    op: str
    value: str
    raw: str


def _parse_term(token: str) -> Optional[Term]:
    key, _, rest = token.partition(":")
    key = key.lower()
    if key not in KEYS or not rest:
        return None
    if key in ("sim", "coverage"):
        found = _NUMBER.match(rest)
        if not found:
            return None
        op, number = found.group(1) or ">=", found.group(2)
        if not 0.0 <= float(number) <= 1.0:
            return None
        return Term(key, op, number, token)
    value = rest.lower()
    if key == "changed" and value not in _ASPECTS and value not in ("any", "none"):
        return None
    if key == "state" and value not in _STATES:
        return None
    if key == "trust" and value not in _TRUSTS:
        return None
    return Term(key, "=", value, token)


def parse_query(source: str) -> "Query":
    words: List[str] = []
    terms: List[Term] = []
    for token in source.split():
        term = _parse_term(token)
        if term is None:
            words.append(token)
        else:
            terms.append(term)
    return Query(text=" ".join(words), terms=tuple(terms))


def _compare(op: str, left: float, right: float) -> bool:
    return {"<": left < right, "<=": left <= right, ">": left > right,
            ">=": left >= right, "=": left == right}[op]


@dataclass(frozen=True)
class Query:
    text: str = ""
    terms: Tuple[Term, ...] = ()

    def chips(self) -> List[str]:
        return [term.raw for term in self.terms]

    def without(self, raw: str) -> "Query":
        return Query(self.text, tuple(t for t in self.terms if t.raw != raw))

    def __str__(self) -> str:
        return " ".join([self.text] + self.chips()).strip()

    def _term_holds(self, term: Term, row: MatchRow) -> bool:
        if term.key == "sim":
            return _compare(term.op, row.similarity, float(term.value))
        if term.key == "coverage":
            return _compare(term.op, row.confidence, float(term.value))
        if term.key == "changed":
            if term.value == "any":
                return row.change_flags != 0
            if term.value == "none":
                return row.change_flags == 0
            return bool(row.change_flags & int(_ASPECTS[term.value]))
        if term.key == "state":
            return row.state == _STATES[term.value]
        if term.key == "found-by":
            return term.value in row.found_by.lower()
        if term.key == "trust":
            return row.trust == term.value
        return True

    def matches(self, row: MatchRow) -> bool:
        if not all(self._term_holds(term, row) for term in self.terms):
            return False
        if not self.text:
            return True
        needle = self.text.lower()
        if needle in row.name_primary.lower() or needle in row.name_secondary.lower():
            return True
        address = parse_address_query(self.text)
        return address is not None and address in (row.address_primary,
                                                   row.address_secondary)

    def narrows(self, previous: "Query") -> bool:
        """True when this query can only accept a subset of `previous`.

        Chips narrow by inclusion: every previous chip must still be present,
        unchanged. A changed bound is not compared numerically -- `sim:<0.9`
        after `sim:<0.8` is wider, and reasoning about that per key is how a
        cache silently hides rows. Text follows the shared rule, including
        its exception for addresses -- except when it did not change at all.
        Unchanged text is the same predicate over the same rows, so only the
        chips can have moved; `text_query_narrows` would still refuse it when
        the text happens to parse as an address ("a" is hex), which would
        throw away the cache on every chip added to an address search.
        """
        if not set(previous.chips()) <= set(self.chips()):
            return False
        if self.text == previous.text:
            return True
        return text_query_narrows(previous.text, self.text)
