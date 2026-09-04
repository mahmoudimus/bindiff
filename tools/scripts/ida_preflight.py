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

    # The bindings are stamped by the protoc the CMake build produces; IDA
    # ships its own interpreter with its own protobuf, and nothing makes the
    # two agree. pyproject's floor governs a pip install, which a plugin
    # loaded from a directory never performs -- so this is only ever visible
    # from in here, which is what this script is for.
    print("\n=== protobuf, which only IDA's interpreter can answer for ===")
    try:
        from google.protobuf import __version__ as runtime
    except Exception as exc:
        ok("runtime", f"not installed: {exc}", good=False)
        runtime = None
    else:
        ok("runtime", runtime)
    try:
        from bindiff.binexport import _gencode_version

        stamp = _gencode_version()
        ok("bindings stamped by protoc", stamp or "unreadable", good=bool(stamp))
        if runtime and stamp:
            def parts(text):
                return tuple(int(n) for n in text.split(".")[:3]
                             if n.isdigit())

            good = parts(runtime) >= parts(stamp)
            ok("runtime >= bindings", "yes" if good else
               f"NO -- install 'protobuf>={stamp}' into {sys.executable}",
               good=good)
    except Exception as exc:
        ok("bindings", f"could not be read: {exc}", good=False)

    # Reading a .BinExport is the thing that actually fails when they
    # disagree, and it fails with a VersionError that is not an ImportError.
    try:
        from bindiff.binexport import _load_pb2

        _load_pb2()
        ok("binexport2_pb2 loads", "yes")
    except Exception as exc:
        ok("binexport2_pb2 loads", f"NO -- {str(exc).splitlines()[0]}",
           good=False)
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

    print("\n=== the worker subprocess (this is what failed before) ===")
    import subprocess

    from bindiff.headless import find_python_interpreter, worker_environment

    interpreter = find_python_interpreter()
    ok("interpreter", interpreter)
    completed = subprocess.run(
        [str(interpreter), "-m", "bindiff.headless"],
        env=worker_environment(), capture_output=True, text=True, cwd="/")
    output = (completed.stdout or completed.stderr or "").strip()
    imported = "No module named" not in output
    ok("can import bindiff", imported if imported else f"NO -- {output[:70]}",
       good=imported)

    print("\n=== menu actions ===")
    import ida_kernwin

    for name, where in (("bindiff:main", "File, Shift-D"),
                        ("bindiff:diff_database", "the dialog"),
                        ("bindiff:load_results", "File/Load file, Ctrl-Shift-6"),
                        ("bindiff:show_matched", "View/BinDiff")):
        label = ida_kernwin.get_action_label(name)
        ok(name, f"{label!r} -> {where}" if label else "NOT REGISTERED",
           good=bool(label))

    print("\n=== summary ===")
    print("  If every line above is [ok]:")
    print("    File -> BinDiff...  (or Shift-D)  -> Diff database...")
    print("  Pick the *other* .BinExport as the secondary if you have one --")
    print("  it is used as-is now, so only this side gets exported.")
    print("  Then keep clicking around the disassembly while it works.\n")


main()
