"""Reads a database's types out of IDA, for porting into another one.

Runs where a database is open: in the worker's idalib process, given a .i64,
which is the same machinery the export already uses and needs no second IDA
running.

The spellings are probed rather than assumed. IDA moved the local type library
onto tinfo_t and renamed parts of the enumeration between 9.0 and 9.4, and
guessing at an IDA API is what disabled four views for a session
(AST_DISABLE_ALWAYS) and made a context menu dispatch nothing
(process_ui_action). Where two names are plausible this tries both and reports
which it found, so a build that has neither fails with a sentence instead of
an AttributeError halfway through a diff.

Nothing here writes to the database.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence, Tuple

from bindiff.typeinfo import FunctionType, TypeDeclaration


class Unavailable(Exception):
    """This IDA does not expose an API this needs."""


def _first_available(module, *names) -> Callable:
    """The first of `names` this build has, or a readable failure."""
    for name in names:
        found = getattr(module, name, None)
        if found is not None:
            return found
    raise Unavailable(
        f"{module.__name__} has none of {', '.join(names)}; "
        "the type API has moved and this needs updating")


def _kind_of(info) -> str:
    """struct / union / enum / typedef, for the forward-declaration rule.

    A typedef cannot be forward declared, so a cycle through one is a real
    cycle -- which is why this is worth getting right rather than defaulting
    everything to "struct".
    """
    for probe, kind in (("is_union", "union"), ("is_enum", "enum"),
                        ("is_struct", "struct"), ("is_typedef", "typedef")):
        test = getattr(info, probe, None)
        try:
            if test is not None and test():
                return kind
        except Exception:
            continue
    return "struct"


def read_local_types() -> List[TypeDeclaration]:
    """Every type defined in this database's own type library, as C text.

    Printed with idc.print_decls, one ordinal at a time and with no
    dependency flags. That is deliberate. PDF_INCL_DEPS pulls in what a
    definition references and PDF_DEF_FWD pulls in the world -- on a real
    database mblock_t alone came back as 62,512 characters and 1,355 lines of
    func_t, range_t and everything they touch. Ordering and deciding what the
    target is missing is this project's job, and it can only do it if it sees
    the definitions one at a time.

    The alternative spelling, tinfo._print with PRTYPE_MULTI|TYPE|SEMI, prints
    a type's *name* as its own type -- "_GUID _GUID;" -- which parse_decls can
    do nothing with. Checked against a running IDA rather than assumed.
    """
    import ida_typeinf
    import idc

    til = ida_typeinf.get_idati()
    count = _first_available(ida_typeinf, "get_ordinal_count",
                             "get_ordinal_qty")(til)
    if not count:
        return []

    declarations: List[TypeDeclaration] = []
    for ordinal in range(1, int(count) + 1):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue
        try:
            definition = idc.print_decls(str(ordinal), 0)
        except Exception:
            continue
        if not definition or not definition.strip():
            continue

        info = ida_typeinf.tinfo_t()
        kind = "struct"
        if info.get_numbered_type(til, ordinal):
            kind = _kind_of(info)
        declarations.append(TypeDeclaration(
            name=name, definition=definition.strip(), kind=kind))
    return declarations


def existing_type_names() -> List[str]:
    """Type names this database can already resolve.

    Asked of the *target* before porting, so definitions it already has are
    not re-parsed. On the pair that prompted this, mblock_t is a local type in
    both databases -- ordinal 86 in one and 499 in the other -- so the whole
    type half of the port is unnecessary and only the prototype is missing.
    Re-parsing a definition that is already present is at best wasted and at
    worst a conflicting redefinition.
    """
    import ida_typeinf

    til = ida_typeinf.get_idati()
    try:
        count = _first_available(ida_typeinf, "get_ordinal_count",
                                 "get_ordinal_qty")(til)
    except Unavailable:
        return []

    names = []
    for ordinal in range(1, int(count or 0) + 1):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if name:
            names.append(name)
    return names


def _print_prototype(info, name: str) -> Optional[str]:
    """A function's declaration as C text that SetType can read back.

    Verified against IDA 9.4: this returns

        mblock_t *__fastcall resolve_goto_target(mblock_t *blk,
                                                 bool require_single_pred);

    with the parameter names intact, which is the entire point -- the same
    function on the other side currently reads
    "__int64 __fastcall resolve_goto_target(__int64, char)" with both
    argument names empty.

    _print rather than str(tinfo): str gives the type without the function it
    belongs to.
    """
    import ida_typeinf

    try:
        text = info._print(name, ida_typeinf.PRTYPE_1LINE
                           | ida_typeinf.PRTYPE_SEMI)
    except Exception:
        return None
    return text or None


def read_function_types(addresses: Optional[Sequence[int]] = None
                        ) -> List[FunctionType]:
    """Every function's declaration, as text that can be applied elsewhere.

    Only functions IDA has a stored type for. A guessed prototype is IDA's
    opinion about the *other* binary, and carrying it across replaces this
    database's own guess with a foreign one of no better standing -- which is
    exactly the "__int64 a1, char a2" that porting was already producing.
    """
    import ida_funcs
    import ida_nalt
    import ida_name
    import ida_typeinf

    if addresses is None:
        addresses = [ida_funcs.getn_func(i).start_ea
                     for i in range(ida_funcs.get_func_qty())]

    functions: List[FunctionType] = []
    for address in addresses:
        info = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(info, address):
            continue
        name = ida_name.get_name(address) or ""
        declaration = _print_prototype(info, name)
        if not declaration:
            continue
        functions.append(FunctionType(address=int(address),
                                      declaration=declaration, name=name))
    return functions


def read_types() -> Tuple[List[TypeDeclaration], List[FunctionType]]:
    """Both halves, for a worker that has just opened a database."""
    return read_local_types(), read_function_types()


def parse_declarations(statements: Sequence[str]) -> Tuple[int, int]:
    """Defines types in this database. Returns (parsed, errors).

    idaapi.parse_decls takes the declarations as a string when HTI_FIL is not
    set, and returns the number of errors rather than raising -- so a batch
    that half-worked is countable instead of silent.

    Each statement is parsed on its own. In one batch a single bad definition
    takes the rest with it, and the whole point of ordering them is to know
    which one failed.

    IDA-specific extensions must stay enabled for this, which is the default:
    print_decls emits __cppobj, _DWORD and __usercall, and the clang parser
    accepts them. Turning on "No IDA specific extensions" makes IDA unable to
    read back what IDA wrote.
    """
    import idaapi

    parsed = errors = 0
    for statement in statements:
        text = (statement or "").strip()
        if not text:
            continue
        try:
            failed = idaapi.parse_decls(None, text, None, idaapi.HTI_PAKDEF)
        except Exception:
            errors += 1
            continue
        if failed:
            errors += 1
        else:
            parsed += 1
    return parsed, errors


def apply_prototype(address: int, declaration: str) -> bool:
    """Gives a function the declaration another database had for it.

    SetType's text wants a name in it, which is what print_decls and
    tinfo._print produce, so the string travels unchanged from one database to
    the other.
    """
    import idc

    text = (declaration or "").strip()
    if not text:
        return False
    if not text.endswith(";"):
        text += ";"
    if idc.SetType(address, text):
        return True

    # The declaration carries the other database's name for the function, and
    # a mangled symbol is not a C identifier: SetType cannot parse
    #
    #   __int64 __fastcall ??1?$_CIP@UIBindCtx@@$1?IID_IBindCtx@@...();
    #
    # The types in it are still what we came for, so retry with a name the
    # parser will accept. The name is not being applied here -- renaming is
    # the symbol port's job -- so substituting one loses nothing.
    replaced = _rename_in_declaration(text, "bindiff_ported_prototype")
    return bool(replaced and idc.SetType(address, replaced))


def _rename_in_declaration(declaration: str, placeholder: str):
    """The same declaration with its function name replaced.

    The name is whatever sits immediately before the argument list, at the
    outermost level. Found by scanning back from the first parenthesis rather
    than by parsing C, which is enough for a declaration IDA printed and not
    enough for C in general -- and this only ever sees the former.
    """
    opening = declaration.find("(")
    if opening <= 0:
        return None
    head = declaration[:opening].rstrip()
    # Walk back over the name: everything up to the last separator that
    # cannot be part of one.
    cut = len(head)
    while cut > 0 and head[cut - 1] not in " \t*&":
        cut -= 1
    if cut == 0:
        return None
    return f"{head[:cut]}{placeholder}{declaration[opening:]}"
