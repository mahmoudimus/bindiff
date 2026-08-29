"""Sidecar features that only IDA can supply.

BinExport is disassembly-level: it has no types, no stack frame layout and
nothing from the decompiler. Those are the signals worth adding, and the export
pass is the one moment IDA is already open with the database analysed.

Split the same way as porting.py: everything that decides *what* a feature is
lives in pure functions over a small source interface, and only `IdaSource`
actually touches IDA. That is not just tidiness -- the fixture .idb files are
32-bit databases IDA 9.x cannot open without an upgrade tool the test image does
not ship, so the extractors cannot be measured against the checked-in ground
truth. Keeping the logic behind an interface means it can at least be tested
against a source that is not IDA.

Pairs with metadata_binexport.py, which supplies what the export alone can give.
Both write into the same sidecar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Protocol, Sequence

from bindiff.metadata import (
    FEATURE_FRAME,
    FEATURE_PROTOTYPE,
    BinaryMetadata,
    FunctionMetadata,
    canonical_prototype,
    frame_feature,
    prototype_feature,
)


@dataclass(frozen=True)
class Prototype:
    """A function signature, as the disassembler or decompiler recovered it."""

    return_type: str
    parameter_types: Sequence[str]

    @property
    def is_informative(self) -> bool:
        """False for a signature IDA guessed rather than recovered.

        IDA gives every unanalysed function `int __cdecl f()` by default. Those
        are indistinguishable from each other, so emitting them would put
        thousands of functions in one bucket and the feature would pair nothing
        while looking like it was working.
        """
        if not self.return_type:
            return False
        if not self.parameter_types:
            # A genuinely nullary function is real information only when the
            # return type is something other than the default guess.
            return self.return_type.strip() not in ("int", "", "_UNKNOWN")
        return True


@dataclass(frozen=True)
class Frame:
    """Stack frame shape."""

    size: int
    argument_count: int
    local_count: int


class FunctionSource(Protocol):
    """Everything the extractors need, small enough to fake in a test."""

    def function_addresses(self) -> Iterable[int]:
        ...

    def prototype(self, address: int) -> Optional[Prototype]:
        ...

    def frame(self, address: int) -> Optional[Frame]:
        ...

    def is_library(self, address: int) -> bool:
        ...


def build_metadata(source: FunctionSource,
                   include_library: bool = False) -> BinaryMetadata:
    """Builds the IDA-derived half of a sidecar.

    Library and thunk code is skipped by default: it is matched by name in
    practice, it is usually the bulk of a binary, and a prototype feature over
    thousands of identical CRT wrappers adds buckets without adding signal.
    """
    metadata = BinaryMetadata()
    prototypes = frames = 0

    for address in source.function_addresses():
        if not include_library and source.is_library(address):
            continue

        features = []
        attributes: Dict[str, str] = {}

        prototype = source.prototype(address)
        if prototype is not None and prototype.is_informative:
            features.append(prototype_feature(prototype.return_type,
                                              prototype.parameter_types))
            # The readable form, so a match can be explained. Never matched on.
            attributes["prototype"] = canonical_prototype(
                prototype.return_type, prototype.parameter_types)
            prototypes += 1

        frame = source.frame(address)
        if frame is not None:
            features.append(frame_feature(frame.size, frame.argument_count,
                                          frame.local_count))
            attributes["frame"] = (f"{frame.size} bytes, "
                                   f"{frame.argument_count} args, "
                                   f"{frame.local_count} locals")
            frames += 1

        if features:
            metadata.functions.append(FunctionMetadata(
                address=address, features=features, attributes=attributes))

    if not prototypes:
        metadata.warnings.append(
            "no function had an informative prototype; the database may not "
            "have been analysed, or every signature is IDA's default guess")
    if not frames:
        metadata.warnings.append("no function had frame information")
    return metadata


def _pointer_size() -> int:
    """Pointer width of the open database, in bytes.

    Probed rather than assumed because the accessor moved between IDA versions
    -- it lives in ida_ida in 9.x and lived in ida_nalt before that. It only
    sets the granularity of the frame buckets, so a wrong answer degrades the
    feature rather than breaking it; 8 is the safer default on a 64-bit-only
    IDA.
    """
    for module_name, attribute in (("ida_ida", "inf_is_64bit"),
                                   ("ida_nalt", "inf_is_64bit")):
        try:
            module = __import__(module_name)
            probe = getattr(module, attribute, None)
            if probe is not None:
                return 8 if probe() else 4
        except ImportError:
            continue
    return 8


class IdaSource:
    """The real source. The only thing in this module that imports IDA.

    Imported lazily inside the constructor rather than at module scope so that
    the pure half above can be imported anywhere -- importing ida_* outside a
    running IDA is what takes the interpreter down.
    """

    def __init__(self):
        import ida_frame
        import ida_funcs
        import ida_nalt
        import ida_typeinf
        import idautils

        self._funcs = ida_funcs
        self._frame = ida_frame
        self._nalt = ida_nalt
        self._typeinf = ida_typeinf
        self._idautils = idautils
        self._pointer_size = _pointer_size()

    def function_addresses(self) -> Iterable[int]:
        return list(self._idautils.Functions())

    def is_library(self, address: int) -> bool:
        function = self._funcs.get_func(address)
        if function is None:
            return True
        flags = function.flags
        return bool(flags & (self._funcs.FUNC_LIB | self._funcs.FUNC_THUNK))

    def prototype(self, address: int) -> Optional[Prototype]:
        """The function's signature, from IDA's type information.

        Uses the stored type rather than the decompiler: Hex-Rays is not
        licensed everywhere, is far slower, and for the purpose here -- a
        canonicalised shape, not a faithful signature -- the disassembler's
        guess carries the same information when it has one.
        """
        # get_tinfo lives in ida_nalt, not ida_typeinf, which is where the
        # rest of the type API is. Verified against the running IDA rather than
        # assumed -- the first version of this called ida_typeinf.get_tinfo and
        # failed at runtime with an AttributeError.
        info = self._typeinf.tinfo_t()
        if not self._nalt.get_tinfo(info, address):
            # No stored type. Deliberately not reconstructed from a printed
            # prototype: that round-trip has its own failure modes, and a
            # function IDA has no type for has nothing to canonicalise.
            return None

        data = self._typeinf.func_type_data_t()
        if not info.get_func_details(data):
            return None

        return Prototype(
            return_type=str(data.rettype),
            parameter_types=[str(argument.type) for argument in data],
        )

    def frame(self, address: int) -> Optional[Frame]:
        function = self._funcs.get_func(address)
        if function is None:
            return None

        size = self._frame.get_frame_size(function)
        if not size:
            return None

        # frsize is the locals area, frregs the saved registers; what is left
        # above them is the argument area.
        locals_size = function.frsize
        arguments_size = max(0, size - function.frsize - function.frregs)
        # Slot counts rather than byte sizes: a build that widens one local
        # should not move the key.
        return Frame(size=size,
                     argument_count=arguments_size // self._pointer_size,
                     local_count=locals_size // self._pointer_size)


def build_sidecar_from_ida(include_library: bool = False) -> BinaryMetadata:
    """Convenience wrapper for use inside a running IDA."""
    return build_metadata(IdaSource(), include_library=include_library)


def merge(into: BinaryMetadata, other: BinaryMetadata) -> BinaryMetadata:
    """Folds `other`'s features into `into`, by address.

    The two producers run separately -- one over the .BinExport, one inside IDA
    -- and both describe the same binary, so their features have to end up in
    one file. Features are appended rather than replaced: a function can carry
    an import set and a prototype, and they are matched independently.
    """
    by_address = {function.address: function for function in into.functions}
    for function in other.functions:
        existing = by_address.get(function.address)
        if existing is None:
            into.functions.append(function)
            by_address[function.address] = function
            continue
        present = {feature.name for feature in existing.features}
        for feature in function.features:
            if feature.name not in present:
                existing.features.append(feature)
        for name, value in function.attributes.items():
            existing.attributes.setdefault(name, value)

    into.warnings.extend(other.warnings)
    if not into.executable_id:
        into.executable_id = other.executable_id
    into.functions.sort(key=lambda function: function.address)
    return into
