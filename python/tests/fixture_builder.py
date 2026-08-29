"""Builds a diffable pair of binaries, with ground truth, at test time.

The checked-in fixtures cannot be used for anything that needs IDA: their .idb
files are 32-bit databases IDA 9.x will not open without an upgrade tool the
image does not ship, and there is no way to re-derive one from the .BinExport.
So the features that need a disassembler had no way to be measured at all.

This closes that. One C source is compiled twice at different optimisation
levels, each build is analysed and exported through the real BinExport plugin,
and the ground truth comes from the symbol names -- both builds contain the same
functions, so a pair is correct exactly when the names agree. That is stronger
ground truth than the checked-in .truth files, which were curated by hand.

Requires BinExport's IDA plugin, which the harness installs only when asked:

    ./tools/scripts/run_tests_docker.sh python --with-binexport
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# The corpus is generated rather than fixed so that its shape can be argued
# about. Three properties matter, and the first version of this file got two of
# them wrong:
#
#  * Distinct signatures. A prototype feature buckets by signature and only
#    pairs a bucket holding exactly one candidate per side, so a corpus where
#    forty functions share eight signatures can never produce a single match --
#    which is what the first version measured, and it measured nothing.
#  * Distinct structure. Forty near-identical functions give the MD-index and
#    prime-signature algorithms nothing to separate, so the baseline collapses
#    and every later comparison is against noise.
#  * Real imports. The import feature needs named library calls; a
#    self-contained corpus gives it nothing to work with.

_RETURN_TYPES = ["int", "unsigned", "long", "short", "char *", "double",
                 "unsigned long long", "void *"]
_PARAM_TYPES = ["int", "unsigned", "const char *", "double", "long",
                "unsigned char", "short *", "unsigned long long"]

# Library calls, so the import feature has named callees. Kept to functions
# every libc has, and spread across the corpus so import sets differ.
# p0 is always the const char * first parameter, which every body can use.
_LIBC = [
    ("strlen", 'n += (long)strlen(p0 ? p0 : "");'),
    ("memcmp", 'n += memcmp(p0 ? p0 : "", "a", 1);'),
    ("strchr", 'n += strchr(p0 ? p0 : "", \'a\') != 0;'),
    ("abs", "n += abs((int)n);"),
    ("memset", "{ char t[4]; memset(t, 0, sizeof t); n += t[0]; }"),
    ("strcmp", 'n += strcmp(p0 ? p0 : "", "b");'),
    ("labs", "n += (long)labs((long)n);"),
    ("memchr", 'n += memchr(p0 ? p0 : "", \'c\', 1) != 0;'),
]

_FUNCTION_COUNT = 48


def _signature(index: int):
    """A signature that differs from every other in the corpus.

    Built from the index so the mapping is total and obviously injective: the
    parameter count, the return type and each parameter type are separate
    digits of the index in mixed radix.
    """
    return_type = _RETURN_TYPES[index % len(_RETURN_TYPES)]
    count = 1 + (index // len(_RETURN_TYPES)) % 6
    params = [_PARAM_TYPES[(index + position) % len(_PARAM_TYPES)]
              for position in range(count)]
    # The first parameter is always a string so every body can use it.
    params[0] = "const char *"
    return return_type, params


def _body(index: int, return_type: str, params) -> str:
    """A body whose control flow depends on the index.

    Loops, nesting depth and the library call all vary, so the structural
    algorithms see genuinely different flow graphs rather than one shape
    repeated.
    """
    _, call = _LIBC[index % len(_LIBC)]
    depth = 1 + index % 3
    lines = ["{", "  long n = 0;"]
    for level in range(depth):
        lines.append("  " + "  " * level +
                     f"for (int i{level} = 0; i{level} < {3 + index % 5}; "
                     f"i{level}++) {{")
        lines.append("  " + "  " * (level + 1) +
                     f"n += i{level} * {1 + index % 7};")
    if index % 2:
        lines.append("  " + "  " * depth + "if (n > 3) n ^= 0x%x;" % (index + 1))
    lines.append("  " + "  " * depth + call)
    for level in reversed(range(depth)):
        lines.append("  " + "  " * level + "}")
    cast = {"char *": "(char *)(size_t)n", "void *": "(void *)(size_t)n",
            "double": "(double)n"}.get(return_type, f"({return_type})n")
    lines.append(f"  return {cast};")
    lines.append("}")
    return "\n".join(lines)


def _source_text() -> str:
    """A C file of distinctly shaped functions, plus a main that calls them."""
    lines = ["#include <stddef.h>", "#include <stdlib.h>", "#include <string.h>",
             ""]
    names = []
    for index in range(_FUNCTION_COUNT):
        return_type, params = _signature(index)
        name = f"bd_fn_{index:03d}"
        names.append((name, params))
        declaration = ", ".join(
            f"{kind} p{position}" for position, kind in enumerate(params))
        lines.append(f"{return_type} {name}({declaration})")
        lines.append(_body(index, return_type, params))
        lines.append("")

    lines.append("int main(void) {")
    lines.append("  unsigned long long acc = 0;")
    for name, params in names:
        arguments = []
        for position, kind in enumerate(params):
            arguments.append({
                "const char *": '"probe"',
                "int": "1", "unsigned": "2u", "long": "3l",
                "double": "1.5", "unsigned char": "(unsigned char)4",
                "short *": "(short *)0",
                "unsigned long long": "5ull",
            }[kind])
        lines.append(f"  acc += (unsigned long long)(size_t)"
                     f"{name}({', '.join(arguments)});")
    lines.append("  return (int)acc;")
    lines.append("}")
    return "\n".join(lines) + "\n"


class FixtureUnavailable(Exception):
    """Raised when the pair cannot be built, with the reason.

    Deliberately not a None return: a caller that skips needs to say *why* it
    skipped, or a broken toolchain is indistinguishable from an absent one.
    """


@dataclass(frozen=True)
class GeneratedPair:
    """Two builds of one program, exported, with ground truth."""

    primary: Path
    secondary: Path
    #: primary entry point -> secondary entry point, from matching symbols.
    truth: Dict[int, int]
    #: The function names the ground truth was derived from, for diagnostics.
    names: List[str]
    #: IDA-derived features for each side, captured while the database was
    #: open during export. Kept separate from the .BinExport-derived features
    #: so a test can measure either set, or both, against the same pair.
    primary_ida: "object" = None
    secondary_ida: "object" = None


def _compile(source: Path, output: Path, optimisation: str) -> None:
    try:
        subprocess.run(
            ["gcc", optimisation, "-fno-inline", "-g", "-o", str(output),
             str(source)],
            check=True, capture_output=True, timeout=300)
    except FileNotFoundError as exc:
        raise FixtureUnavailable("no gcc to build the corpus") from exc
    except subprocess.TimeoutExpired as exc:
        raise FixtureUnavailable(
            f"gcc {optimisation} timed out on the corpus") from exc
    except subprocess.CalledProcessError as exc:
        raise FixtureUnavailable(
            f"gcc {optimisation} failed: "
            f"{exc.stderr.decode('utf-8', 'replace')[-800:]}") from exc
    if not output.is_file():
        raise FixtureUnavailable(f"gcc {optimisation} produced no {output}")


def _export(binary: Path) -> Tuple[Path, object]:
    """Analyses `binary`, exports it, and captures the IDA-only features.

    Both in one session, which is the point: the export pass is the only moment
    IDA is open with the database analysed, and re-opening it later to collect
    types would double the cost of the slowest step in the pipeline.
    """
    import idapro

    from bindiff.metadata_ida import IdaSource, build_metadata

    output = binary.with_suffix(".BinExport")
    captured = {}

    def exporter(path: str) -> None:
        from bindiff.headless import _invoke_binexport

        _invoke_binexport(path)
        # After the export, while the database is still open.
        captured["metadata"] = build_metadata(IdaSource())

    from bindiff.headless import export

    result = export(str(binary), str(output), exporter=exporter)
    if not result.ok:
        raise FixtureUnavailable(
            f"exporting {binary.name} failed: {result.message}")
    if not output.is_file():
        raise FixtureUnavailable(
            f"exporting {binary.name} reported success but wrote no {output}")
    return output, captured.get("metadata")


def _named_functions(binexport: Path) -> Dict[str, int]:
    """Real-named functions in an export, by name.

    Only the functions this file defines are kept: CRT and library code differs
    between optimisation levels in ways that are not this fixture's business,
    and including it would put noise in the ground truth.
    """
    from bindiff.binexport import read_functions

    by_name: Dict[str, int] = {}
    for function in read_functions(str(binexport)):
        name = function.best_name
        if name.startswith("bd_fn_") or name == "main":
            # A duplicate name would make the pairing ambiguous; drop both.
            if name in by_name:
                by_name[name] = -1
            else:
                by_name[name] = function.address
    return {name: address for name, address in by_name.items() if address >= 0}


def build_pair(directory: Path) -> GeneratedPair:
    """Builds the pair, or raises FixtureUnavailable saying what was missing.

    Needs gcc, idalib and BinExport's IDA plugin. Only the first is universally
    present, so failure is expected -- but it has to be legible.
    """
    source = directory / "corpus.c"
    source.write_text(_source_text())

    primary_binary = directory / "corpus_O0"
    secondary_binary = directory / "corpus_O2"
    _compile(source, primary_binary, "-O0")
    _compile(source, secondary_binary, "-O2")

    primary, primary_ida = _export(primary_binary)
    secondary, secondary_ida = _export(secondary_binary)

    primary_names = _named_functions(primary)
    secondary_names = _named_functions(secondary)
    shared = sorted(set(primary_names) & set(secondary_names))
    if not shared:
        raise FixtureUnavailable(
            f"no function name is present in both exports "
            f"({len(primary_names)} named in the first, "
            f"{len(secondary_names)} in the second); the builds were stripped "
            f"or the corpus was optimised away")
    truth = {primary_names[name]: secondary_names[name] for name in shared}

    return GeneratedPair(primary=primary, secondary=secondary, truth=truth,
                         names=shared, primary_ida=primary_ida,
                         secondary_ida=secondary_ida)


def write_sidecars(pair: GeneratedPair, imports: bool = True,
                   ida_features: bool = True) -> None:
    """Writes a sidecar for each side of `pair`, or removes it.

    Which features go in is a parameter so a test can isolate one contribution
    from another against the same pair -- which is the only way to say what a
    feature is actually worth.
    """
    import copy

    from bindiff.metadata import BinaryMetadata, sidecar_path_for, write_sidecar
    from bindiff.metadata_binexport import build_sidecar
    from bindiff.metadata_ida import merge

    for export, ida_metadata in ((pair.primary, pair.primary_ida),
                                 (pair.secondary, pair.secondary_ida)):
        if not imports and not ida_features:
            Path(sidecar_path_for(str(export))).unlink(missing_ok=True)
            continue

        metadata = (build_sidecar(str(export)) if imports
                    else BinaryMetadata())
        if ida_features and ida_metadata is not None:
            # Copied because merge() appends the other side's objects by
            # reference, and the pair is session-scoped -- a later call would
            # otherwise be folding in objects an earlier one had already
            # attached somewhere else.
            merge(metadata, copy.deepcopy(ida_metadata))
        write_sidecar(str(export), metadata)
