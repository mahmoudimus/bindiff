"""Carrying C types between two IDA databases.

BinExport2 cannot represent a type: no type table, no prototypes, nothing. So
porting types cannot go through the export, and this is IDA-to-IDA -- one
database's type library written out, another's reading it in.

The order matters and is the whole difficulty. A prototype like

    int __fastcall parse(Header *h, Flags f)

cannot be applied until `Header` and `Flags` exist in the target, and `Header`
may itself contain a `Flags` and a pointer to a `Node` that contains a
`Header`. Diaphora handles this by calling parse_decls in a loop ten times and
letting the successes accumulate; that works and hides which definitions were
actually circular. This sorts them instead, and reports what could not be
sorted rather than retrying blindly.

A cycle through a *pointer* is not a real cycle: `struct Node { Node *next; }`
parses if `struct Node;` was declared first. Emitting those forward
declarations is what turns most cycles into an ordering.

Everything here is text and graph work with no IDA in it, so the ordering is
tested directly. The two ends -- reading a database's types and writing them
into another -- are thin and injected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# C keywords, storage classes and builtin types: anything matching these in a
# definition is not a reference to a user type.
_NOT_A_TYPE = frozenset("""
struct union enum typedef const volatile static extern register auto inline
unsigned signed void char short int long float double bool _Bool size_t
ssize_t ptrdiff_t intptr_t uintptr_t wchar_t va_list
int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t
__int8 __int16 __int32 __int64 __cdecl __stdcall __fastcall __thiscall
__usercall __userpurge __noreturn __pure __hidden __return_ptr __struct_ptr
""".split())

_IDENTIFIER = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
# A member declared as a pointer: the reference does not need a complete type.
_POINTER_USE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\*")


@dataclass(frozen=True)
class TypeDeclaration:
    """One user-defined type, as the C text that recreates it."""

    name: str
    definition: str
    kind: str = "struct"

    @property
    def forward_declaration(self) -> Optional[str]:
        """The one-liner that lets a pointer to this type resolve early.

        Only tagged types have one. A typedef cannot be forward declared, so
        a cycle through a typedef is a real cycle.
        """
        if self.kind in ("struct", "union", "enum"):
            return f"{self.kind} {self.name};"
        return None


@dataclass(frozen=True)
class FunctionType:
    """A function's declaration, and the types it needs."""

    address: int
    declaration: str
    name: str = ""


@dataclass
class TypePlan:
    """What to feed a target database, in the order to feed it."""

    forward_declarations: List[str] = field(default_factory=list)
    declarations: List[TypeDeclaration] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)

    @property
    def statements(self) -> List[str]:
        """Everything to parse, in order."""
        return self.forward_declarations + [d.definition
                                            for d in self.declarations]


# The sidecar's own version. Bumped when the shape changes, so a file written
# by an older plugin is refused with a reason rather than misread.
TYPES_FORMAT_VERSION = 1


def types_path_for(source_path) -> str:
    """Where the type sidecar for a database or export belongs.

    Beside its source and named after it, so it travels with the thing it
    describes and so two databases in one directory do not collide.
    """
    return f"{source_path}.types.json"


def to_json(declarations: Sequence[TypeDeclaration],
            functions: Sequence[FunctionType],
            source: str = "") -> dict:
    """The sidecar as plain data.

    Its own file rather than a message in the protobuf sidecar: the C++ engine
    parses that one and will never read a type, so putting types there would
    mean a schema change and a rebuild for data only the plugin uses.
    """
    return {
        "version": TYPES_FORMAT_VERSION,
        "source": str(source),
        "types": [{"name": d.name, "kind": d.kind, "definition": d.definition}
                  for d in declarations],
        "functions": [{"address": f.address, "name": f.name,
                       "declaration": f.declaration} for f in functions],
    }


def from_json(data: dict) -> Tuple[List[TypeDeclaration], List[FunctionType]]:
    """Reads a sidecar back. Raises ValueError on a version it cannot read."""
    version = data.get("version")
    if version != TYPES_FORMAT_VERSION:
        raise ValueError(
            f"type sidecar is version {version!r}, this reads "
            f"{TYPES_FORMAT_VERSION}")

    declarations = [
        TypeDeclaration(name=entry["name"],
                        definition=entry["definition"],
                        kind=entry.get("kind", "struct"))
        for entry in data.get("types", [])
        if entry.get("name") and entry.get("definition")
    ]
    functions = [
        FunctionType(address=int(entry["address"]),
                     declaration=entry["declaration"],
                     name=entry.get("name", ""))
        for entry in data.get("functions", [])
        if entry.get("declaration")
    ]
    return declarations, functions


# A parameter list with names in it: "(mblock_t *blk, bool x)" rather than
# "(_QWORD, _QWORD)". An identifier following a type is the signal.
_NAMED_PARAMETER = re.compile(r"[\w>*&\]]\s+[A-Za-z_]\w*\s*[,)]")


def carries_information(function: "FunctionType") -> bool:
    """True when a declaration says more than IDA would have guessed.

    Applying the other side's guess over this side's guess is not porting, it
    is swapping one default for another -- and the swap loses, because the
    declaration carries the *other* binary's function name with it. On a real
    pair the unfiltered set included

        int sub_180001000();
        __int64 __fastcall sub_180012650(_QWORD, _QWORD);

    which say nothing at all, beside

        mblock_t *__fastcall resolve_goto_target(mblock_t *blk,
                                                 bool require_single_pred);

    which is the whole point of the feature. The difference is a real name or
    named parameters; a declaration with neither is IDA's opinion about a
    binary the reader is not looking at.
    """
    from bindiff.stack_names import is_generated_name

    declaration = function.declaration or ""
    if not declaration:
        return False
    if function.name and not is_generated_name(function.name):
        return True
    return bool(_NAMED_PARAMETER.search(declaration))


def referenced_types(text: str, known: Iterable[str]) -> Set[str]:
    """Which of `known` a piece of C text mentions.

    Matched against a known set rather than guessed at: picking out
    "identifiers that look like types" from C text without a parser produces
    field names, macro names and half the standard library.
    """
    known = set(known)
    return {name for name in _IDENTIFIER.findall(text or "")
            if name in known and name not in _NOT_A_TYPE}


def pointer_only_references(text: str, names: Iterable[str]) -> Set[str]:
    """Of `names`, those this text only ever uses through a pointer.

    Such a reference is satisfied by a forward declaration, which is what
    breaks most apparent cycles.
    """
    names = set(names)
    pointed = set(_POINTER_USE.findall(text or ""))
    result = set()
    for name in names:
        if name not in pointed:
            continue
        # Used as a pointer somewhere; is it ever used by value?
        by_value = re.search(
            rf"\b{re.escape(name)}\b(?!\s*\*)\s+[A-Za-z_]", text or "")
        if not by_value:
            result.add(name)
    return result


def order_declarations(declarations: Sequence[TypeDeclaration],
                      already_present: Iterable[str] = ()) -> TypePlan:
    """Sorts type definitions so that parsing them in order succeeds.

    `already_present` names types the target database already has -- from a
    loaded type library, usually. They are dropped from the plan and treated
    as satisfied dependencies: a prototype naming mblock_t needs nothing
    emitted when hexrays.til is loaded, and re-parsing a definition that is
    already there is at best wasted and at worst a conflicting redefinition.

    Returns the order, the forward declarations needed to break pointer
    cycles, and the names that could not be ordered at all -- a genuine cycle
    through a by-value member, which no ordering fixes and which the caller
    should report rather than retry.
    """
    present = set(already_present)
    declarations = [d for d in declarations if d.name not in present]
    by_name: Dict[str, TypeDeclaration] = {d.name: d for d in declarations}
    names = set(by_name) | present

    hard: Dict[str, Set[str]] = {}
    forward_needed: Set[str] = set()
    for declaration in declarations:
        referenced = referenced_types(declaration.definition, names)
        referenced.discard(declaration.name)
        through_pointer = pointer_only_references(declaration.definition,
                                                  referenced)
        forward_needed |= (through_pointer - present)
        # A pointer reference is satisfied by the forward declaration, and a
        # type the target already has is satisfied by the target. Neither is
        # an ordering constraint.
        hard[declaration.name] = referenced - through_pointer - present

    plan = TypePlan()
    plan.forward_declarations = [
        by_name[name].forward_declaration
        for name in sorted(forward_needed)
        if by_name[name].forward_declaration is not None
    ]

    # Kahn's algorithm, taking ready names in a stable order so the output is
    # reproducible rather than dependent on set iteration.
    remaining = dict(hard)
    emitted: Set[str] = set()
    while remaining:
        ready = sorted(name for name, deps in remaining.items()
                       if not (deps - emitted))
        if not ready:
            break
        for name in ready:
            plan.declarations.append(by_name[name])
            emitted.add(name)
            del remaining[name]

    plan.unresolved = sorted(remaining)
    return plan


def plan_types(declarations: Sequence[TypeDeclaration],
               functions: Sequence[FunctionType] = (),
               already_present: Iterable[str] = (),
               only_what_is_needed: bool = True) -> TypePlan:
    """An ordering that covers what the given functions need, and no more.

    Restricted to what the functions actually reference by default. Porting a
    whole type library into someone's database because one function was
    imported is not a favour -- it is thousands of definitions they did not
    ask for, some of which will conflict with their own.

    With no functions given, nothing is needed and nothing is planned; pass
    only_what_is_needed=False to plan every declaration instead.
    """
    if only_what_is_needed:
        wanted = needed_by(functions, declarations)
        declarations = [d for d in declarations if d.name in wanted]
    return order_declarations(declarations, already_present=already_present)


def needed_by(functions: Sequence[FunctionType],
              declarations: Sequence[TypeDeclaration]) -> Set[str]:
    """Type names the given function declarations mention, transitively."""
    by_name = {d.name: d for d in declarations}
    wanted: Set[str] = set()
    queue: List[str] = []

    for function in functions:
        queue.extend(referenced_types(function.declaration, by_name))

    while queue:
        name = queue.pop()
        if name in wanted:
            continue
        wanted.add(name)
        declaration = by_name.get(name)
        if declaration is None:
            continue
        queue.extend(referenced_types(declaration.definition, by_name))
    return wanted
