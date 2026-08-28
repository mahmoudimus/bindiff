"""Building the per-function metadata sidecar.

Split the usual way: everything here is pure and testable, and the parts that
need IDA live in metadata_ida.py. This module knows how to canonicalise and
hash a feature; it does not know how to get one out of a database.

Canonicalisation is the whole game for the exact-match features. Two builds of
the same function will not spell their types identically -- one compiler says
`unsigned int`, another `uint32_t`, IDA says `unsigned __int32` -- and a
prototype feature that hashes those to different keys is worse than no feature
at all, because it produces confident non-matches. So the normalisation is
deliberately aggressive and is the most heavily tested thing in here.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

PRODUCER = "bindiff-metadata/0.1"

# Feature names are versioned: a change to canonicalisation, or a retrained
# model, produces keys that are not comparable with the old ones. Mixing them
# silently degrades matching in a way that is very hard to notice, so the
# version is part of the name and a consumer can refuse a mismatch.
FEATURE_PROTOTYPE = "prototype/v1"
FEATURE_FRAME = "frame/v1"
FEATURE_CALLEE_SEQUENCE = "callee-sequence/v1"
FEATURE_CONSTANTS = "constants/v1"

METRIC_EXACT = "EXACT"
METRIC_COSINE = "COSINE"
METRIC_EUCLIDEAN = "EUCLIDEAN"
METRIC_HAMMING = "HAMMING"


def stable_key(text: str) -> int:
    """A 64-bit key that is the same in every process and every run.

    Not Python's hash(): that is randomised per process unless PYTHONHASHSEED
    is pinned, so sidecars produced by two runs would not agree and matching
    would quietly fall apart. SHA-256 truncated to 64 bits is stable, and the
    collision probability over a few tens of thousands of functions is
    negligible.
    """
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8],
                          "big")


# -- prototype canonicalisation -------------------------------------------

# Spellings that mean the same width and signedness. IDA, MSVC and GCC all
# disagree here, and a prototype feature is worthless if they hash differently.
_TYPE_ALIASES = {
    "unsigned __int8": "u8", "unsigned char": "u8", "uint8_t": "u8",
    "__uint8": "u8", "byte": "u8", "uchar": "u8", "BYTE": "u8",
    "__int8": "i8", "signed char": "i8", "int8_t": "i8", "char": "i8",

    "unsigned __int16": "u16", "unsigned short": "u16", "uint16_t": "u16",
    "ushort": "u16", "WORD": "u16", "wchar_t": "u16",
    "__int16": "i16", "short": "i16", "int16_t": "i16", "signed short": "i16",

    "unsigned __int32": "u32", "unsigned int": "u32", "uint32_t": "u32",
    "unsigned": "u32", "uint": "u32", "DWORD": "u32", "ULONG": "u32",
    "unsigned long": "u32",
    "__int32": "i32", "int": "i32", "int32_t": "i32", "signed int": "i32",
    "long": "i32", "LONG": "i32",

    "unsigned __int64": "u64", "unsigned long long": "u64", "uint64_t": "u64",
    "ULONGLONG": "u64", "QWORD": "u64", "size_t": "u64",
    "__int64": "i64", "long long": "i64", "int64_t": "i64",
    "LONGLONG": "i64", "ssize_t": "i64",

    "void": "void", "bool": "b", "_BOOL1": "b", "BOOL": "i32",
    "float": "f32", "double": "f64", "long double": "f80",
}

# Dropped before comparison: they describe how a function is called, not what
# it takes, and they differ between builds of the same source.
_CALLING_CONVENTIONS = (
    "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall",
    "__usercall", "__userpurge", "__spoils", "__noreturn", "__pure",
    "WINAPI", "APIENTRY", "CALLBACK", "NTAPI",
)

_QUALIFIERS = ("const", "volatile", "struct", "union", "enum", "class",
               "signed")


def canonical_type(text: str) -> str:
    """Normalises one type so equivalent spellings compare equal.

    Pointer depth is kept -- `char *` and `char` are genuinely different -- but
    what is pointed *at* is reduced to a width, and struct names are dropped,
    because a struct recovered from two binaries almost never has the same
    name and keeping it would make every prototype unique.
    """
    if text is None:
        return "?"
    normalised = text.strip()
    if not normalised:
        return "?"

    pointer_depth = normalised.count("*")
    # Arrays decay: as a parameter they are pointers anyway.
    if "[" in normalised:
        pointer_depth += 1
        normalised = re.sub(r"\[[^\]]*\]", "", normalised)
    normalised = normalised.replace("*", " ")

    for convention in _CALLING_CONVENTIONS:
        normalised = normalised.replace(convention, " ")
    words = [w for w in re.split(r"\s+", normalised) if w and w not in _QUALIFIERS]
    base = " ".join(words).strip()

    resolved = _TYPE_ALIASES.get(base)
    if resolved is None:
        # Try progressively shorter prefixes: "unsigned int foo" -> "unsigned int".
        for length in range(len(words), 0, -1):
            candidate = " ".join(words[:length])
            if candidate in _TYPE_ALIASES:
                resolved = _TYPE_ALIASES[candidate]
                break
    if resolved is None:
        # An aggregate. The name is not portable across binaries, so only the
        # fact that it is an aggregate survives.
        resolved = "agg" if base else "?"

    return resolved + "*" * pointer_depth


def canonical_prototype(return_type: str,
                        parameter_types: Sequence[str]) -> str:
    """Canonical form of a whole prototype, e.g. "i32(u8*,u32)".

    Parameter *names* are not included: they are debug information that rarely
    survives, and including them would make the feature far too specific.
    """
    parameters = ",".join(canonical_type(t) for t in parameter_types)
    return f"{canonical_type(return_type)}({parameters})"


# -- features --------------------------------------------------------------

@dataclass(frozen=True)
class Feature:
    """One named feature of one function."""

    name: str
    metric: str
    key: Optional[int] = None
    vector: Optional[Sequence[float]] = None
    packed: Optional[bytes] = None
    confidence: float = 1.0

    def __post_init__(self):
        provided = sum(x is not None for x in (self.key, self.vector, self.packed))
        if provided != 1:
            raise ValueError(
                f"feature {self.name!r} must carry exactly one of key, vector "
                f"or packed (got {provided})")
        if self.metric == METRIC_EXACT and self.key is None:
            raise ValueError(f"{self.name!r} is EXACT but carries no key")
        if self.metric in (METRIC_COSINE, METRIC_EUCLIDEAN) and self.vector is None:
            raise ValueError(f"{self.name!r} is {self.metric} but carries no vector")
        if self.metric == METRIC_HAMMING and self.packed is None:
            raise ValueError(f"{self.name!r} is HAMMING but carries no bytes")


@dataclass
class FunctionMetadata:
    address: int
    features: List[Feature] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)

    def feature(self, name: str) -> Optional[Feature]:
        return next((f for f in self.features if f.name == name), None)


@dataclass
class BinaryMetadata:
    binexport_sha256: str = ""
    producer: str = PRODUCER
    functions: List[FunctionMetadata] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def descriptors(self) -> List[dict]:
        """Summarises which features are present and how many carry them.

        A consumer uses this to skip a matching pass entirely: a feature on
        three functions out of four thousand is not worth a search.
        """
        summary: Dict[str, dict] = {}
        for function in self.functions:
            for feature in function.features:
                entry = summary.setdefault(feature.name, {
                    "name": feature.name,
                    "metric": feature.metric,
                    "dimension": len(feature.vector) if feature.vector else 0,
                    "count": 0,
                })
                entry["count"] += 1
                if feature.vector is not None:
                    dimension = len(feature.vector)
                    if entry["dimension"] != dimension:
                        raise ValueError(
                            f"feature {feature.name!r} has inconsistent "
                            f"dimensions ({entry['dimension']} and {dimension}); "
                            f"vectors of different length are not comparable")
        return sorted(summary.values(), key=lambda d: d["name"])


def prototype_feature(return_type: str, parameter_types: Sequence[str],
                      confidence: float = 1.0) -> Feature:
    return Feature(name=FEATURE_PROTOTYPE, metric=METRIC_EXACT,
                   key=stable_key(canonical_prototype(return_type,
                                                      parameter_types)),
                   confidence=confidence)


def frame_feature(frame_size: int, argument_count: int,
                  local_count: int, confidence: float = 1.0) -> Feature:
    """Stack frame shape.

    Bucketed rather than exact: frame sizes shift by a few bytes between
    builds for reasons that have nothing to do with the function's identity
    (alignment, a spilled register), and an exact key would treat those as
    different functions.
    """
    bucket = frame_size // 16
    return Feature(name=FEATURE_FRAME, metric=METRIC_EXACT,
                   key=stable_key(f"{bucket}:{argument_count}:{local_count}"),
                   confidence=confidence)


def callee_sequence_feature(callee_prototypes: Iterable[str],
                            confidence: float = 1.0) -> Feature:
    """The ordered prototypes of what this function calls.

    Aimed at wrappers and thin shims: structurally trivial, so BinDiff's
    graph-shaped algorithms have almost nothing to work with, but what they
    call is highly distinctive.
    """
    joined = "|".join(callee_prototypes)
    return Feature(name=FEATURE_CALLEE_SEQUENCE, metric=METRIC_EXACT,
                   key=stable_key(joined), confidence=confidence)


def constants_feature(constants: Iterable[int],
                      confidence: float = 1.0) -> Feature:
    """Distinctive constants, as the decompiler folded them.

    Small values are dropped: 0, 1 and 2 appear everywhere and carry no
    identifying information, so including them would make every function's set
    look alike.
    """
    interesting = sorted({c for c in constants if abs(c) > 0xFF})
    joined = ",".join(hex(c) for c in interesting)
    return Feature(name=FEATURE_CONSTANTS, metric=METRIC_EXACT,
                   key=stable_key(joined), confidence=confidence)


def sha256_of_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
