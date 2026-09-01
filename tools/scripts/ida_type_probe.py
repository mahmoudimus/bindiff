"""Reports what IDA's type API actually returns, so the type porting can be
written against it rather than guessed at.

Run in the IDA holding the database you want to port types *from* -- for the
example that started this, hexx64-9.3:

    exec(open("/Users/mahmoud/src/idapro/bindiff/tools/scripts/"
              "ida_type_probe.py").read())

Read-only. It renames nothing, defines nothing and writes no file.

Three things it answers, all of which differ between IDA versions and none of
which can be checked from outside IDA:

  * how a function's prototype comes back as text, and whether parameter
    names survive
  * how the local type library is enumerated, and what a definition looks
    like when printed
  * which of the several plausible API spellings this build actually has
"""

from __future__ import annotations

TARGET_NAME = "resolve_goto_target"


def line(label, value=""):
    print(f"  {label:<38} {value}")


def probe_api():
    print("\n=== which spellings this build has ===")
    import ida_typeinf
    import ida_nalt

    for module, name in (
            (ida_nalt, "get_tinfo"),
            (ida_typeinf, "print_tinfo"),
            (ida_typeinf, "idc_print_type"),
            (ida_typeinf, "get_ordinal_count"),
            (ida_typeinf, "get_ordinal_qty"),
            (ida_typeinf, "get_numbered_type_name"),
            (ida_typeinf, "parse_decls"),
            (ida_typeinf, "apply_tinfo"),
            (ida_typeinf, "get_idati"),
            (ida_typeinf, "tinfo_t"),
    ):
        line(f"{module.__name__}.{name}", hasattr(module, name))


def probe_prototype():
    print(f"\n=== the prototype of {TARGET_NAME} ===")
    import ida_funcs
    import ida_name
    import ida_nalt
    import ida_typeinf
    import idc

    address = ida_name.get_name_ea(0, TARGET_NAME)
    if address == 0xFFFFFFFFFFFFFFFF:
        line("not found in this database", "(try another name)")
        return
    line("address", f"{address:#x}")

    info = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(info, address):
        line("get_tinfo", "yes")
        line("str(tinfo)", str(info))
        # The form that can be fed back to parse_decls / SetType.
        try:
            printed = info._print(TARGET_NAME, ida_typeinf.PRTYPE_1LINE
                                  | ida_typeinf.PRTYPE_SEMI)
            line("tinfo._print(name)", printed)
        except Exception as exc:
            line("tinfo._print", f"failed: {exc}")
        data = ida_typeinf.func_type_data_t()
        if info.get_func_details(data):
            line("return type", str(data.rettype))
            for i, argument in enumerate(data):
                line(f"  arg {i}", f"{argument.type}  name={argument.name!r}")
    else:
        line("get_tinfo", "no stored type")

    line("idc.get_type", idc.get_type(address))
    line("idc.get_func_cmt", (idc.get_func_cmt(address, 0) or "")[:70])


def probe_local_types():
    print("\n=== the local type library ===")
    import ida_typeinf

    til = ida_typeinf.get_idati()
    count = None
    for spelling in ("get_ordinal_count", "get_ordinal_qty"):
        if hasattr(ida_typeinf, spelling):
            try:
                count = getattr(ida_typeinf, spelling)(til)
                line(f"{spelling}(til)", count)
                break
            except Exception as exc:
                line(spelling, f"failed: {exc}")
    if not count:
        line("no ordinals", "nothing to enumerate")
        return

    shown = 0
    for ordinal in range(1, count + 1):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue
        info = ida_typeinf.tinfo_t()
        if not info.get_numbered_type(til, ordinal):
            continue
        try:
            definition = info._print(
                name, ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE
                | ida_typeinf.PRTYPE_SEMI)
        except Exception as exc:
            definition = f"<print failed: {exc}>"
        one_line = " ".join((definition or "").split())
        line(f"ordinal {ordinal}", f"{name}")
        line("", one_line[:100])
        shown += 1
        if shown >= 5:
            break

    print("\n=== print_decls: the purpose-built way to dump a local type ===")
    import idc

    ordinal = None
    for candidate in range(1, count + 1):
        if ida_typeinf.get_numbered_type_name(til, candidate) == "mblock_t":
            ordinal = candidate
            break
    if ordinal is None:
        line("mblock_t", "not a local type here")
        return

    line("mblock_t ordinal", ordinal)
    for label, flags in (
            ("plain", 0),
            ("PDF_INCL_DEPS", getattr(idc, "PDF_INCL_DEPS", 1)),
            ("PDF_INCL_DEPS|PDF_DEF_FWD",
             getattr(idc, "PDF_INCL_DEPS", 1) | getattr(idc, "PDF_DEF_FWD", 2)),
    ):
        try:
            text = idc.print_decls(str(ordinal), flags)
        except Exception as exc:
            line(f"print_decls {label}", f"failed: {exc}")
            continue
        text = (text or "").strip()
        line(f"print_decls {label}", f"{len(text)} chars")
        for row in text.splitlines()[:8]:
            print(f"      {row}")
        if len(text.splitlines()) > 8:
            print(f"      ... {len(text.splitlines()) - 8} more lines")

    print("\n  -- the flags that print a definition rather than a name --")
    info = ida_typeinf.tinfo_t()
    info.get_numbered_type(til, ordinal)
    for label, flags in (
            ("MULTI|TYPE|SEMI",
             ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE
             | ida_typeinf.PRTYPE_SEMI),
            ("MULTI|TYPE|SEMI|DEF",
             ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE
             | ida_typeinf.PRTYPE_SEMI | getattr(ida_typeinf, "PRTYPE_DEF", 0)),
    ):
        try:
            out = info._print("mblock_t", flags) or ""
        except Exception as exc:
            out = f"failed: {exc}"
        line(f"_print {label}", " ".join(out.split())[:90])

    print(f"\n  -- is mblock_t among them? --")
    for ordinal in range(1, count + 1):
        if ida_typeinf.get_numbered_type_name(til, ordinal) == "mblock_t":
            line("mblock_t ordinal", ordinal)
            break
    else:
        line("mblock_t", "not a local type here "
                        "(it comes from a loaded .til, which is the easy case)")


def main():
    import idaapi
    print(f"\nIDA {idaapi.get_kernel_version()}")
    probe_api()
    probe_prototype()
    probe_local_types()
    print("\n  Paste this back and the producer gets written against it.\n")


main()
