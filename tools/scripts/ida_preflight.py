"""Checks, from inside IDA, the things about a diff that cannot be checked
from outside it.

Run it in IDA's Python console before the first real diff. It touches nothing
and changes nothing: no database is saved, no export is started, and the only
file it writes is a copy it deletes again.

    exec(open("/Users/mahmoud/src/idapro/bindiff/tools/scripts/"
              "ida_preflight.py").read())

Every line it prints is something that was reasoned about rather than
observed, which is why it exists.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path("/Users/mahmoud/src/idapro/bindiff")


def ok(label, value, good=True):
    print(f"  [{'ok' if good else '!!'}] {label:<34} {value}")


def main():
    print("\n=== interpreter ===")
    ok("python", f"{sys.version_info.major}.{sys.version_info.minor}."
                 f"{sys.version_info.micro}")

    print("\n=== the bindiff package IDA actually loads ===")
    if str(REPO / "python") not in sys.path:
        sys.path.insert(0, str(REPO / "python"))
    try:
        import bindiff
        import bindiff.core
        ok("version", bindiff.__version__)
        ok("module", bindiff.__file__)
        ok("extension", Path(bindiff.core.__file__).name)
        ok("diff callable", callable(bindiff.diff))
    except Exception as exc:
        ok("import bindiff", f"FAILED: {exc}", good=False)
        return

    print("\n=== what would be exported for the primary side ===")
    import ida_loader
    import ida_nalt
    from ida_plugin.diff_runner import primary_export_source

    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    binary = ida_nalt.get_input_file_path()
    ok("PATH_TYPE_IDB", idb or "<empty>", good=bool(idb))
    ok("  exists", Path(idb).is_file() if idb else False, good=bool(idb))
    ok("input file", binary or "<empty>")
    chosen = primary_export_source(idb, binary)
    ok("chosen", chosen)
    # The whole point of the change: the database, not the binary.
    ok("  is the database", bool(idb) and chosen == idb,
       good=bool(idb) and chosen == idb)

    print("\n=== can the snapshot be made? (copied, verified, removed) ===")
    if chosen and Path(chosen).suffix.lower() in (".idb", ".i64"):
        source = Path(chosen)
        handle, target = tempfile.mkstemp(suffix=source.suffix,
                                          prefix="bindiff-preflight-")
        os.close(handle)
        try:
            shutil.copyfile(source, target)
            same = Path(target).stat().st_size == source.stat().st_size
            ok("copied", f"{source.stat().st_size:,} bytes", good=same)
            ok("  sizes match", same, good=same)
        except Exception as exc:
            ok("copy", f"FAILED: {exc}", good=False)
        finally:
            try:
                os.unlink(target)
            except OSError:
                pass
            ok("  removed", not Path(target).exists())
    else:
        ok("skipped", "the primary is not a database")

    print("\n=== BinExport, which the export needs ===")
    from bindiff import binexport_installer as installer

    dirs = []
    user = ida_loader.get_user_idadir() if hasattr(
        ida_loader, "get_user_idadir") else None
    if not user:
        import ida_diskio
        user = ida_diskio.get_user_idadir()
        dirs.append(Path(user) / "plugins")
        dirs.append(Path(ida_diskio.idadir("plugins")))
    found = installer.find_installed(dirs)
    ok("installed", found or "NO -- the plugin will offer to fetch it",
       good=bool(found))
    for directory in dirs:
        ok("  searched", directory)

    print("\n=== summary ===")
    print("  If every line above is [ok], run Ctrl-6 -> Diff database and")
    print("  keep clicking around the disassembly while it works. The UI")
    print("  staying live is the property the out-of-process design buys.\n")


main()
