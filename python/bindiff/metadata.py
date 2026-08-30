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
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

PRODUCER = "bindiff-metadata/0.1"

# A sidecar sits beside its export: "foo.BinExport.meta".
SIDECAR_SUFFIX = ".meta"

# Feature names are versioned: a change to canonicalisation, or a retrained
# model, produces keys that are not comparable with the old ones. Mixing them
# silently degrades matching in a way that is very hard to notice, so the
# version is part of the name and a consumer can refuse a mismatch.
FEATURE_PROTOTYPE = "prototype/v1"
FEATURE_FRAME = "frame/v1"
FEATURE_CALLEE_SEQUENCE = "callee-sequence/v1"
FEATURE_CONSTANTS = "constants/v1"
FEATURE_IMPORTS = "imports/v1"

METRIC_EXACT = "EXACT"
METRIC_COSINE = "COSINE"
METRIC_EUCLIDEAN = "EUCLIDEAN"
METRIC_HAMMING = "HAMMING"
METRIC_JACCARD = "JACCARD"


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
    key_set: Optional[Sequence[int]] = None
    confidence: float = 1.0

    def __post_init__(self):
        provided = sum(x is not None for x in
                       (self.key, self.vector, self.packed, self.key_set))
        if provided != 1:
            raise ValueError(
                f"feature {self.name!r} must carry exactly one of key, vector, "
                f"packed or key_set (got {provided})")
        if self.metric == METRIC_EXACT and self.key is None:
            raise ValueError(f"{self.name!r} is EXACT but carries no key")
        if self.metric in (METRIC_COSINE, METRIC_EUCLIDEAN) and self.vector is None:
            raise ValueError(f"{self.name!r} is {self.metric} but carries no vector")
        if self.metric == METRIC_HAMMING and self.packed is None:
            raise ValueError(f"{self.name!r} is HAMMING but carries no bytes")
        if self.metric == METRIC_JACCARD:
            if self.key_set is None:
                raise ValueError(f"{self.name!r} is JACCARD but carries no set")
            if list(self.key_set) != sorted(set(self.key_set)):
                # The schema promises sorted and deduplicated so the C++ side
                # can intersect linearly; enforce it at construction rather
                # than trusting every producer to remember.
                raise ValueError(
                    f"{self.name!r} key_set must be sorted and deduplicated")


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
    executable_id: str = ""
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

    Not emitted by any producer, deliberately. Measured against the four
    ground-truth fixtures it recovered exactly one pair the engine did not
    already have -- as an exact key because two builds almost never agree on
    every folded constant, and no better as a Jaccard set at any threshold from
    0.6 to 0.9. Kept because the shape is right and a future producer with
    better constant recovery may make it worth something; wire it into
    bindiff.json only after measuring it again. Compare imports_feature, which
    is what did work.
    """
    interesting = sorted({c for c in constants if abs(c) > 0xFF})
    joined = ",".join(hex(c) for c in interesting)
    return Feature(name=FEATURE_CONSTANTS, metric=METRIC_EXACT,
                   key=stable_key(joined), confidence=confidence)


def imports_feature(import_names: Iterable[str],
                    confidence: float = 1.0) -> Feature:
    """The set of imported functions this function calls.

    The strongest signal measured so far, and the only one that needs nothing
    but the .BinExport. Import names come from the PE/ELF import table, so they
    survive stripping -- which is exactly the case where name matching, the
    engine's most reliable step, has nothing to work with.

    Compared by Jaccard rather than set equality because two builds of the same
    function agree on most of their imports but rarely all of them: on the
    ground-truth fixtures, exact set equality recovered 39 pairs the engine gets
    wrong or misses, and Jaccard at 0.8 recovered 52, with no disagreement
    against ground truth in either case.

    It contributes nothing when the two binaries do not share an import surface
    -- the insider fixture pairs a MinGW build against an LCC one, and their
    statically linked CRTs export different names -- which is a limit of the
    feature, not a defect: the case it targets is comparing builds of the same
    program.
    """
    keys = sorted({stable_key(name) for name in import_names})
    return Feature(name=FEATURE_IMPORTS, metric=METRIC_JACCARD,
                   key_set=keys, confidence=confidence)


def embedding_feature(name: str, values: Sequence[float],
                      confidence: float = 1.0) -> Feature:
    """A dense function embedding, compared by cosine.

    This is how a learned representation enters the engine, which never runs a
    model: a producer -- a bag of mnemonics, asm2vec, jTrans -- writes vectors
    here and the C++ side compares them. The model lives in the sidecar
    producer, which runs in a worker process, so nothing heavy is ever imported
    inside IDA or linked into the differ.

    The name carries the model *and its version*, because two embeddings are
    only comparable if they came from the same one. The engine checks that the
    widths agree, which catches a changed dimension but not a retrained model
    of the same shape -- that part is the name's job.
    """
    values = [float(v) for v in values]
    if not values:
        raise ValueError(f"{name!r} embedding is empty")
    if not any(values):
        # An all-zero vector has no direction, so it has no cosine to anything.
        # Rejected here rather than silently dropped on load, because a
        # producer emitting them is producing nothing and should hear about it.
        raise ValueError(f"{name!r} embedding has no direction (all zero)")
    if any(v != v or v in (float("inf"), float("-inf")) for v in values):
        raise ValueError(f"{name!r} embedding contains a non-finite value")
    return Feature(name=name, metric=METRIC_COSINE, vector=values,
                   confidence=confidence)


# -- serialisation ---------------------------------------------------------

def _load_pb2():
    """Imports the generated bindings, with an actionable error if absent."""
    try:
        from bindiff._pb import bindiff_metadata_pb2
    except ImportError as exc:
        raise ImportError(
            "bindiff_metadata_pb2 is missing. Generate the protobuf bindings "
            "with:\n  ./tools/scripts/run_tests_docker.sh build"
        ) from exc
    return bindiff_metadata_pb2


_METRIC_TO_PROTO = {
    METRIC_EXACT: 1,
    METRIC_COSINE: 2,
    METRIC_EUCLIDEAN: 3,
    METRIC_HAMMING: 4,
    METRIC_JACCARD: 5,
}
_METRIC_FROM_PROTO = {value: name for name, value in _METRIC_TO_PROTO.items()}


def to_proto(metadata: BinaryMetadata):
    """Converts to the wire message, filling in the descriptors."""
    pb2 = _load_pb2()

    proto = pb2.BinaryMetadata()
    proto.binexport_sha256 = metadata.binexport_sha256
    proto.executable_id = metadata.executable_id
    proto.producer = metadata.producer
    proto.warnings.extend(metadata.warnings)

    for descriptor in metadata.descriptors():
        entry = proto.descriptors.add()
        entry.name = descriptor["name"]
        entry.metric = _METRIC_TO_PROTO[descriptor["metric"]]
        entry.dimension = descriptor["dimension"]
        entry.count = descriptor["count"]

    for function in metadata.functions:
        message = proto.functions.add()
        message.address = function.address
        for name, value in function.attributes.items():
            message.attributes[name] = value
        for feature in function.features:
            entry = message.features.add()
            entry.name = feature.name
            entry.metric = _METRIC_TO_PROTO[feature.metric]
            entry.confidence = feature.confidence
            if feature.key is not None:
                entry.key = feature.key
            elif feature.vector is not None:
                entry.vector.values.extend(feature.vector)
            elif feature.packed is not None:
                entry.packed = feature.packed
            else:
                entry.key_set.keys.extend(feature.key_set)
    return proto


def from_proto(proto) -> BinaryMetadata:
    """Reads the wire message back.

    Strict where the C++ loader is forgiving: a key set that is not sorted and
    deduplicated raises here, because this side is tooling and surfacing a
    producer bug is more useful than papering over it. sidecar.cc normalises
    instead, because it must not fail in the middle of a diff.
    """
    metadata = BinaryMetadata(binexport_sha256=proto.binexport_sha256,
                              executable_id=proto.executable_id,
                              producer=proto.producer,
                              warnings=list(proto.warnings))
    for message in proto.functions:
        function = FunctionMetadata(address=message.address,
                                    attributes=dict(message.attributes))
        for entry in message.features:
            metric = _METRIC_FROM_PROTO.get(entry.metric)
            if metric is None:
                # An unknown metric is skipped rather than guessed at: the
                # producer knows how its values compare and we do not.
                continue
            kind = entry.WhichOneof("value")
            function.features.append(Feature(
                name=entry.name, metric=metric, confidence=entry.confidence,
                key=entry.key if kind == "key" else None,
                vector=list(entry.vector.values) if kind == "vector" else None,
                packed=entry.packed if kind == "packed" else None,
                key_set=list(entry.key_set.keys) if kind == "key_set" else None,
            ))
        metadata.functions.append(function)
    return metadata


def sidecar_path_for(binexport_path) -> str:
    """Where a sidecar lives: "foo.BinExport" -> "foo.BinExport.meta".

    Appended rather than substituted, which is what SidecarPathFor does in
    sidecar.cc. The two have to agree exactly or the engine would look for a
    file the producer never wrote.
    """
    return str(Path(binexport_path)) + SIDECAR_SUFFIX


def write_sidecar(binexport_path, metadata: BinaryMetadata) -> str:
    """Writes the sidecar beside its .BinExport and returns the path.

    The digest is filled in here rather than trusted from the caller, so a
    sidecar can never claim to describe an export it was not built from.
    """
    metadata.binexport_sha256 = sha256_of_file(binexport_path)
    path = sidecar_path_for(binexport_path)
    Path(path).write_bytes(to_proto(metadata).SerializeToString())
    return path


def read_sidecar(binexport_path) -> Optional[BinaryMetadata]:
    """Reads the sidecar for a .BinExport, or None if there is not one.

    Returns None for an absent file -- a sidecar is optional and its absence is
    not an error -- but raises for one that does not describe this export.
    Silently pairing metadata with the wrong binary would produce confident,
    wrong matches, which is worse than having no metadata at all.
    """
    pb2 = _load_pb2()

    path = Path(sidecar_path_for(binexport_path))
    if not path.is_file():
        return None

    proto = pb2.BinaryMetadata()
    proto.ParseFromString(path.read_bytes())
    expected = sha256_of_file(binexport_path)
    if proto.binexport_sha256 != expected:
        raise ValueError(
            f"{path} describes a different .BinExport "
            f"(sidecar says {proto.binexport_sha256[:16]}..., "
            f"{binexport_path} hashes to {expected[:16]}...)")
    return from_proto(proto)


def sha256_of_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
