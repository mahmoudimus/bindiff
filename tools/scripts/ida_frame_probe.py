"""Reports what IDA's frame API returns, so stack-variable porting can be
checked against a build other than the one it was written on.

    exec(open("/Users/mahmoud/src/idapro/bindiff/tools/scripts/"
              "ida_frame_probe.py").read())

Headlessly, against an image rather than a running IDA -- which is how 9.1
was checked, since idalib for it is only in the container:

    mkdir -p build/frame-probe && cat > build/frame-probe/driver.py <<'EOF'
    import shutil, sys, tempfile
    from pathlib import Path
    binary = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
    holder = Path(tempfile.mkdtemp())
    target = holder / Path(binary).name
    shutil.copyfile(binary, target)
    import idapro
    assert idapro.open_database(str(target), True) == 0
    try:
        exec(compile(Path("/work/tools/scripts/ida_frame_probe.py").read_text(),
                     "probe", "exec"), {"__name__": "__main__"})
    finally:
        idapro.close_database(False)
        shutil.rmtree(holder, ignore_errors=True)
    EOF
    docker compose run --rm -T idapro-tests-9.1 /work/build/frame-probe/driver.py

/bin/ls rather than a fixture: the checked-in .idb files are 32-bit and 9.x
refuses them without an upg32 the image does not ship, and this cares about
the API rather than about which program it is looking at.

Read-only in the database that matters: it renames a frame member and then
puts the old name back, because "does rename_udm work here" cannot be
answered without trying it. Nothing is saved -- close without saving and
even that is undone. It touches one function, named below.

The porting was written and measured against IDA 9.4. What differs between
versions, and cannot be checked from outside IDA:

  * whether a frame is a tinfo_t UDT (9.0+) or the old struc_t
  * whether the _ea spellings exist. 9.4 deprecates get_func_frame and
    calc_stkvar_struc_offset in favour of them; 9.1 does not have them at
    all, so following the warning would break the compatibility leg
  * whether rename_udm reports refusal, or accepts and drops silently --
    set_name returns False and raises nothing, and six bugs hid behind that
  * what calc_stkvar_struc_offset returns for an operand that is not a
    stack variable, and whether it ever returns something outside the frame
    (on 9.4 it returns BADADDR 74 times and an out-of-range value 97 times
    over one binary, and multiplying the latter by 8 raises OverflowError)
"""

from __future__ import annotations

# Any function with a frame will do. Overridden below if it has none.
TARGET = None


def line(label, value=""):
    print(f"  {label:<40} {value}")


def probe_api():
    import ida_frame
    import ida_typeinf

    print("\nAPI surface")
    for module, names in (
            (ida_frame, ("get_func_frame", "get_func_frame_ea",
                         "calc_stkvar_struc_offset",
                         "calc_stkvar_struc_offset_ea", "get_frame_size")),
            (ida_typeinf, ("STRMEM_OFFSET", "TERR_OK", "udm_t",
                           "udt_type_data_t"))):
        for name in names:
            line(f"{module.__name__}.{name}",
                 "yes" if getattr(module, name, None) is not None else "MISSING")
    for name in ("find_udm", "rename_udm", "get_udt_details"):
        line(f"tinfo_t.{name}",
             "yes" if hasattr(ida_typeinf.tinfo_t, name) else "MISSING")


def pick_function():
    import ida_frame
    import ida_funcs
    import ida_typeinf

    if TARGET is not None:
        return ida_funcs.get_func(TARGET)
    for index in range(min(ida_funcs.get_func_qty(), 4000)):
        function = ida_funcs.getn_func(index)
        if function is None:
            continue
        frame = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame, function):
            continue
        details = ida_typeinf.udt_type_data_t()
        if frame.get_udt_details(details) and len(details) > 2:
            return function
    return None


def probe_frame(function):
    import ida_frame
    import ida_typeinf

    print(f"\nFrame of {function.start_ea:#x}")
    frame = ida_typeinf.tinfo_t()
    line("get_func_frame", ida_frame.get_func_frame(frame, function))
    line("is_udt", frame.is_udt())
    line("get_size", frame.get_size())
    details = ida_typeinf.udt_type_data_t()
    frame.get_udt_details(details)
    line("members", len(details))
    for member in list(details)[:8]:
        line(f"  offset {member.offset // 8:#x}",
             f"{member.name!r} size={member.size // 8}")
    return frame, details


def probe_offsets(function):
    """What calc_stkvar_struc_offset says about this function's operands."""
    import ida_frame
    import ida_idaapi
    import ida_typeinf
    import ida_ua

    frame = ida_typeinf.tinfo_t()
    ida_frame.get_func_frame(frame, function)
    size = frame.get_size()

    print("\ncalc_stkvar_struc_offset over the function's operands")
    instruction = ida_ua.insn_t()
    address = function.start_ea
    counts = {"in the frame": 0, "BADADDR": 0, "outside the frame": 0}
    examples = []
    while address < function.end_ea:
        if ida_ua.decode_insn(instruction, address) <= 0:
            address += 1
            continue
        for index in range(len(instruction.ops)):
            if instruction.ops[index].type == 0:
                break
            try:
                offset = ida_frame.calc_stkvar_struc_offset(
                    function, instruction, index)
            except Exception as exc:
                counts.setdefault(f"raised {type(exc).__name__}", 0)
                counts[f"raised {type(exc).__name__}"] += 1
                continue
            if offset == ida_idaapi.BADADDR:
                counts["BADADDR"] += 1
            elif 0 <= offset < size:
                counts["in the frame"] += 1
                if len(examples) < 3:
                    examples.append((address, index, offset))
            else:
                counts["outside the frame"] += 1
        address += instruction.size
    for label, count in counts.items():
        line(label, count)
    for address, index, offset in examples:
        line(f"  {address:#x} op{index}", f"-> {offset:#x}")
    return examples


def probe_rename(function, examples):
    """The question no amount of reading answers: does the rename take, and
    does it report a refusal or swallow it?"""
    import ida_frame
    import ida_typeinf

    print("\nrename_udm")
    if not examples:
        line("skipped", "no stack operand found in this function")
        return
    offset = examples[0][2]
    frame = ida_typeinf.tinfo_t()
    ida_frame.get_func_frame(frame, function)
    member = ida_typeinf.udm_t()
    member.offset = offset * 8
    index = frame.find_udm(member, ida_typeinf.STRMEM_OFFSET)
    line("find_udm at that offset", f"index {index}, name {member.name!r}")
    if index < 0:
        return

    original = member.name
    line("rename to 'bindiff_probe_tmp'", frame.rename_udm(
        index, "bindiff_probe_tmp"))

    # Re-read from the database rather than from the object just mutated:
    # the question is whether it persisted, not whether the setter ran.
    fresh = ida_typeinf.tinfo_t()
    ida_frame.get_func_frame(fresh, function)
    details = ida_typeinf.udt_type_data_t()
    fresh.get_udt_details(details)
    now = next((m.name for m in details if m.offset // 8 == offset), None)
    line("re-read from the database", repr(now))

    # A name already used in this frame. set_name would return False; the
    # question is whether this reports anything at all.
    taken = next((m.name for m in details if m.offset // 8 != offset), None)
    if taken:
        again = ida_typeinf.tinfo_t()
        ida_frame.get_func_frame(again, function)
        member2 = ida_typeinf.udm_t()
        member2.offset = offset * 8
        idx2 = again.find_udm(member2, ida_typeinf.STRMEM_OFFSET)
        line(f"rename to {taken!r} (already taken)",
             again.rename_udm(idx2, taken))

    # Put it back.
    restore = ida_typeinf.tinfo_t()
    ida_frame.get_func_frame(restore, function)
    member3 = ida_typeinf.udm_t()
    member3.offset = offset * 8
    idx3 = restore.find_udm(member3, ida_typeinf.STRMEM_OFFSET)
    line("restored", f"{original!r} -> {restore.rename_udm(idx3, original)}")


def probe_decompiler(function):
    """Whether a frame rename reaches the pseudocode. On 9.4 it does not:
    Hex-Rays names its own locals, in its own store."""
    print("\nDecompiler")
    try:
        import ida_hexrays
    except ImportError:
        line("ida_hexrays", "not present")
        return
    line("init_hexrays_plugin", ida_hexrays.init_hexrays_plugin())


def main():
    import idaapi

    print(f"\nIDA {idaapi.get_kernel_version()}")
    probe_api()
    function = pick_function()
    if function is None:
        print("\n  No function with a frame found; nothing to probe.\n")
        return
    probe_frame(function)
    examples = probe_offsets(function)
    probe_rename(function, examples)
    probe_decompiler(function)
    print("\n  Paste this back. Close without saving.\n")


main()
