"""Trust: a plugin-side verdict on a match, and the words for it.

The engine records three things per match -- similarity, confidence and the
step that found the pair -- and shows all three raw. Trust folds them into
one of three readings so the table can spend colour on the exceptions.

The thresholds come from the measured per-step precision in CLAUDE.md ("What
a match's confidence actually means"): hash and prime signature at 100%, the
feature steps at 98-100%, the MD index steps at ~89%, and address sequence
at 43%. A step whose measured precision is under three in four cannot be
Strong on its own numbers.

No Qt and no IDA: the table's model and the inspector both read this.
"""

from __future__ import annotations

from enum import Enum


class AlgorithmClass(str, Enum):
    MANUAL = "manual"
    EXACT = "exact"            # signature of the whole body: hash, prime, feature
    STRUCTURAL = "structural"  # graph shape and neighbourhood
    POSITIONAL = "positional"  # leftovers paired by order
    UNKNOWN = "unknown"


class Trust(str, Enum):
    STRONG = "strong"
    CHECK = "check"
    WEAK = "weak"


TRUST_RANK = {Trust.WEAK.value: 0, Trust.CHECK.value: 1, Trust.STRONG.value: 2}

# Below this similarity nothing is trusted, whichever step found it. Half is
# the porting floor that measured at 93.8% precision (DEFAULT_PORT_MIN_SIMILARITY).
WEAK_SIMILARITY = 0.5
# A structural step needs both numbers here to be Strong; 0.81 reads Check.
STRONG_STRUCTURAL_SIMILARITY = 0.85
STRONG_STRUCTURAL_COVERAGE = 0.85
# A positional step is never Strong; at this similarity it earns a look.
CHECK_POSITIONAL_SIMILARITY = 0.85

# Order matters: the first substring that matches wins.
_CLASS_RULES = (
    ("manual", AlgorithmClass.MANUAL),
    ("hash matching", AlgorithmClass.EXACT),
    ("prime signature", AlgorithmClass.EXACT),
    ("feature ", AlgorithmClass.EXACT),
    ("address sequence", AlgorithmClass.POSITIONAL),
    ("call sequence matching", AlgorithmClass.POSITIONAL),
)


def algorithm_class(algorithm: str) -> AlgorithmClass:
    """Classes a step by its engine name. Anything else that starts with
    "function: " is structural; an empty or foreign name is unknown."""
    name = (algorithm or "").lower()
    for needle, kind in _CLASS_RULES:
        if needle in name:
            return kind
    if name.startswith("function: "):
        return AlgorithmClass.STRUCTURAL
    return AlgorithmClass.UNKNOWN


def assess(similarity: float, confidence: float, algorithm: str) -> Trust:
    kind = algorithm_class(algorithm)
    if kind is AlgorithmClass.MANUAL:
        return Trust.STRONG
    if similarity < WEAK_SIMILARITY:
        return Trust.WEAK
    if kind is AlgorithmClass.EXACT:
        return Trust.STRONG
    if kind is AlgorithmClass.POSITIONAL:
        return (Trust.CHECK if similarity >= CHECK_POSITIONAL_SIMILARITY
                else Trust.WEAK)
    if kind is AlgorithmClass.STRUCTURAL and (
            similarity >= STRONG_STRUCTURAL_SIMILARITY
            and confidence >= STRONG_STRUCTURAL_COVERAGE):
        return Trust.STRONG
    return Trust.CHECK


def explain(trust: Trust, algorithm: str, similarity: float,
            confidence: float) -> str:
    """One sentence for the inspector: why this verdict, and what to do."""
    kind = algorithm_class(algorithm)
    if kind is AlgorithmClass.MANUAL:
        return "Matched or verified by hand; the numbers are not consulted."
    if trust is Trust.STRONG:
        if kind is AlgorithmClass.EXACT:
            return ("Found by a whole-body signature, which is right in "
                    "practically every measured case.")
        return "Structural match with high similarity and block coverage."
    if trust is Trust.WEAK:
        if kind is AlgorithmClass.POSITIONAL:
            return ("Paired by address order among the leftovers -- right "
                    "less than half the time when measured. Treat as a guess.")
        return (f"Similarity {similarity:.2f} is below the floor at which "
                f"any step is trusted. Open both before believing it.")
    if kind is AlgorithmClass.POSITIONAL:
        return ("Paired by position, but the bodies are very alike. Worth "
                "opening; do not port on it unread.")
    if kind is AlgorithmClass.UNKNOWN:
        return "Found by a step this plugin does not know. Read it yourself."
    return ("Structural match with a mid similarity. Worth opening before "
            "porting.")


BLOCK_COVERAGE_CAVEAT = (
    "Block coverage says how much of the flow graph lined up. It does not "
    "say the pair is right. Trust weighs it against the algorithm that found "
    "the pair.")

_FOUND_BY = {
    "function: name hash matching": "name hash",
    "function: hash matching": "function hash",
    "function: feature imports/v1": "imports",
    "function: feature prototype/v1": "prototype",
    "function: edges flowgraph MD index": "flow-graph edges",
    "function: edges callgraph MD index": "call-graph edges",
    "function: MD index matching (flowgraph MD index, top down)":
        "flow-graph MD index",
    "function: MD index matching (flowgraph MD index, bottom up)":
        "flow-graph MD index",
    "function: prime signature matching": "prime signature",
    "function: MD index matching (callGraph MD index, top down)":
        "call-graph MD index",
    "function: MD index matching (callGraph MD index, bottom up)":
        "call-graph MD index",
    "function: relaxed MD index matching": "relaxed MD index",
    "function: instruction count": "instruction count",
    "function: address sequence": "address order",
    "function: string references": "string references",
    "function: loop count matching": "loop count",
    "function: call sequence matching(exact)": "call sequence",
    "function: call sequence matching(topology)": "call sequence (topology)",
    "function: call graph neighbour assignment": "call-graph neighbours",
    "function: call reference matching": "call reference",
    "function: manual": "by hand",
}


def found_by(algorithm: str) -> str:
    """The step's name as the table shows it: plain words, no prefix.

    The engine identifier stays available in the inspector and the
    algorithm editor; here it would be pure width -- every row is a
    function, so the "function: " prefix says nothing.
    """
    if not algorithm:
        return ""
    known = _FOUND_BY.get(algorithm)
    if known is not None:
        return known
    prefix = "function: "
    return algorithm[len(prefix):] if algorithm.startswith(prefix) else algorithm
