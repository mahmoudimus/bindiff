#!/usr/bin/env python3
# Copyright 2011-2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Setup script for BinDiff Python interface.

This script builds Cython extensions for BinDiff's C++ core.
Supports platform detection and debug mode via DEBUG environment variable.
"""

import functools
import json
import os
import platform
import re
import shlex
import sys
from pathlib import Path
from setuptools import setup, Extension
from Cython.Build import cythonize

# Platform detection
OSTYPE = platform.system()
ARCH = platform.processor() or platform.machine()
x64 = platform.architecture()[0] == "64bit"
COMPILER_OPTIMIZATION_LEVEL = re.compile(r"-O[0-3]\b")
DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"

# Determine paths
PYTHON_DIR = Path(__file__).parent.resolve()
BINDIFF_ROOT = PYTHON_DIR.parent
# The CMake build tree. Overridable because the documented out-of-source layout
# is build/out, while a bare `cmake -B build` puts it directly in build/.
# Library directories are discovered by walking this tree, so either works.
BUILD_DIR = Path(
    os.environ.get("BINDIFF_BUILD_DIR", BINDIFF_ROOT / "build")
).resolve()

# Check if BinDiff has been built
if not BUILD_DIR.exists():
    print("ERROR: BinDiff build directory not found.")
    print(f"Expected: {BUILD_DIR}")
    print("\nPlease build BinDiff first using CMake:")
    print("  mkdir -p build && cd build")
    print("  cmake .. -DBINDIFF_BUILD_TESTING=OFF")
    print("  cmake --build .")
    sys.exit(1)

# Locate BinExport directory (sibling to BinDiff)
BINEXPORT_DIR = Path(
    os.environ.get("BINDIFF_BINEXPORT_DIR", BINDIFF_ROOT.parent / "binexport")
).resolve()
if not BINEXPORT_DIR.exists():
    print("ERROR: BinExport directory not found.")
    print(f"Expected: {BINEXPORT_DIR}")
    print("\nPlease clone BinExport as a sibling directory to BinDiff:")
    print("  cd ..")
    print("  git clone https://github.com/google/binexport.git")
    sys.exit(1)

# Include directories.
#
# wrappers.cc includes BinDiff headers, which pull in BinExport, Abseil,
# Protobuf and Boost. Rather than track that transitive set by hand -- it has
# drifted before, most recently over protobuf's vendored utf8_range -- take it
# from the CMake build these wrappers link against. CMakeLists.txt sets
# CMAKE_EXPORT_COMPILE_COMMANDS, so the exact flags used to compile the engine
# are on disk next to the libraries.
def _include_dirs_from_compile_commands(build_dir):
    """Returns the -I paths CMake used for the engine, or [] if unavailable."""
    db_path = build_dir / "compile_commands.json"
    if not db_path.is_file():
        return []
    try:
        with open(db_path, encoding="utf-8") as db_file:
            entries = json.load(db_file)
    except (OSError, ValueError):
        return []

    # Any BinDiff translation unit carries the full include set; sqlite.cc is
    # small and always built.
    for entry in entries:
        if not entry.get("file", "").endswith("sqlite.cc"):
            continue
        argv = shlex.split(entry.get("command") or " ".join(entry.get("arguments", [])))
        dirs = []
        for i, token in enumerate(argv):
            if token.startswith("-I") and len(token) > 2:
                dirs.append(token[2:])
            elif token == "-I" and i + 1 < len(argv):
                dirs.append(argv[i + 1])
        return [d for d in dirs if os.path.isdir(d)]
    return []


include_dirs = [
    str(BINDIFF_ROOT),  # For "python/bindiff/wrappers.h"
]

_cmake_includes = _include_dirs_from_compile_commands(BUILD_DIR)
if _cmake_includes:
    include_dirs.extend(_cmake_includes)
else:
    # Fallback for a build tree without compile_commands.json.
    include_dirs.extend([
        str(BUILD_DIR / "src_include"),                                # third_party/zynamics/bindiff/*
        str(BUILD_DIR / "gen_include"),                                # generated BinDiff headers
        str(BUILD_DIR / "_deps" / "binexport-build" / "src_include"),  # binexport/*.h
        str(BUILD_DIR / "_deps" / "binexport-build" / "gen_include"),  # binexport/*.pb.h
        str(BINEXPORT_DIR),
        str(BINEXPORT_DIR / "stubs"),
    ])

    deps_dir = BUILD_DIR / "_deps"
    if deps_dir.exists():
        for candidate in (
            deps_dir / "absl-src",
            deps_dir / "protobuf-src" / "src",
            # protobuf's parse_context.h includes "utf8_validity.h", which
            # lives in its vendored utf8_range copy.
            deps_dir / "protobuf-src" / "third_party" / "utf8_range",
            deps_dir / "protobuf-src",
        ):
            if candidate.exists():
                include_dirs.append(str(candidate))

# Add Boost - required by call_graph.h
boost_include = os.environ.get("BOOST_INCLUDE_DIR")
if boost_include:
    include_dirs.append(boost_include)
else:
    # Try common Boost locations
    boost_locations = [
        # BinExport vendors the subset of Boost that BinDiff needs; this is
        # what the CMake build itself compiles against (BinExportDeps.cmake
        # sets Boost_INCLUDE_DIR to it), so prefer it over any system copy.
        BINEXPORT_DIR / "boost_parts",
        BUILD_DIR / "_deps" / "boost-src",
        Path("/usr/include"),
        Path("/usr/local/include"),
    ]
    for loc in boost_locations:
        if (loc / "boost").exists():
            include_dirs.append(str(loc))
            break

# Directories under the build tree that must never be descended into.
#
# src_include and gen_include are the symlink trees the configure step creates
# so that the Google-internal absolute includes resolve; each points back at
# the source root, which contains the build tree. Walking into one is
# unbounded. .git belongs to whatever was checked out inside the build
# directory and holds no archives.
_PRUNED_DIRS = {"src_include", "gen_include", ".git"}


# A static archive is .a with the GNU toolchain and .lib with MSVC. Matching
# only .a is why the Windows wheel could never have linked even once the walk
# below stopped hanging: the archive list came back empty and setup.py exited.
_ARCHIVE_SUFFIXES = (".a", ".lib")


def _walk_build_tree(build_dir):
    """Yields (directory, filenames) under the build tree, without looping.

    os.walk with the directory list pruned **in place**, which is the only form
    that can refuse to descend. Path.rglob has already gone into a directory by
    the time it yields it, so testing is_symlink() on the result prevents
    nothing -- and on Windows the include trees are junctions, which
    is_symlink() does not report as links at all. Both walks in this file used
    that pattern; the Windows wheel build sat in one for over an hour where
    Linux and macOS each finished in under twenty seconds.
    """
    for root, dirnames, filenames in os.walk(build_dir):
        dirnames[:] = [
            name for name in dirnames
            if name not in _PRUNED_DIRS
            and not os.path.islink(os.path.join(root, name))
            and not getattr(os.path, "isjunction", lambda _p: False)(
                os.path.join(root, name))
        ]
        yield root, filenames


def _archive_dirs(build_dir):
    """Directories holding static archives."""
    return [root for root, filenames in _walk_build_tree(build_dir)
            if any(name.endswith(_ARCHIVE_SUFFIXES) for name in filenames)]


library_dirs = [str(BUILD_DIR)]
for _archive_dir in _archive_dirs(BUILD_DIR):
    if _archive_dir not in library_dirs:
        library_dirs.append(_archive_dir)

# Add common subdirectories
for subdir_name in ["_deps", "lib", "lib64", "Release", "Debug"]:
    subdir = BUILD_DIR / subdir_name
    if subdir.exists() and str(subdir) not in library_dirs:
        library_dirs.append(str(subdir))

# Print diagnostic info
if os.environ.get("VERBOSE_BUILD"):
    print(f"\n{'='*60}")
    print(f"BinDiff Python Build Configuration")
    print(f"{'='*60}")
    print(f"Platform: {OSTYPE} ({ARCH})")
    print(f"Python: {sys.version}")
    print(f"Build directory: {BUILD_DIR}")
    print(f"\nLibrary search paths ({len(library_dirs)} found):")
    for libdir in library_dirs[:10]:  # Show first 10
        print(f"  - {libdir}")
    if len(library_dirs) > 10:
        print(f"  ... and {len(library_dirs) - 10} more")
    print(f"{'='*60}\n")

# Libraries to link.
#
# This used to be a hand-maintained list of ~60 Abseil archive names. That list
# goes stale every time BinExport moves its Abseil pin -- absl_crc_cpu_detect,
# for one, no longer exists -- and the failure is a link error naming a single
# missing -l at a time. Instead, link the archives CMake actually produced.
# Passing full paths also removes the need to get -l ordering right.
def _static_libraries(build_dir):
    """Every static archive CMake built, minus the test-only ones."""
    # Test-only and build-tool archives have no business in a runtime
    # extension: the *_main variants define main(), bindiff_test_util and
    # binexport_testing are gtest fixtures, and protoc is the protobuf
    # *compiler*, not its runtime (libprotobuf and upb are). --start-group only
    # pulls objects that resolve something, so these contributed nothing
    # anyway, but naming them keeps an accident from linking one in.
    # The LTO probe directories hold throwaway objects.
    skip_names = ("gtest", "gtest_main", "gmock", "gmock_main",
                  "benchmark", "benchmark_main",
                  "bindiff_test_util", "binexport_testing", "protoc")
    skip_path_parts = ("CMakeFiles", "_CMakeLTOTest-C", "_CMakeLTOTest-CXX")

    found = {}
    for root, filenames in _walk_build_tree(build_dir):
        if any(part in skip_path_parts for part in Path(root).parts):
            continue
        for name in sorted(filenames):
            if not name.endswith(_ARCHIVE_SUFFIXES):
                continue
            stem = Path(name).stem
            # libfoo.a and foo.lib are the same archive named two ways.
            stem = stem[3:] if stem.startswith("lib") else stem
            if stem in skip_names:
                continue
            # Keep the first of any duplicate basename; the walk and the inner
            # sort are both deterministic, so two runs agree.
            found.setdefault(stem, os.path.join(root, name))
    return found


_archives = _static_libraries(BUILD_DIR)
if not _archives:
    print("ERROR: no static libraries found under", BUILD_DIR)
    print("Build the C++ tree first:")
    print("  cmake -S . -B build/out -G Ninja -DCMAKE_BUILD_TYPE=Release \\")
    print("    -DBINDIFF_BINEXPORT_DIR=../binexport")
    print("  cmake --build build/out")
    sys.exit(1)

# BinDiff's own archives must come first so the linker has undefined symbols
# outstanding when it reaches their dependencies; --start-group then resolves
# whatever remains, regardless of order.
_priority = ["bindiff_shared", "bindiff_config", "bindiff_version",
             "binexport_shared", "sqlite", "protobuf", "utf8_validity"]
link_objects = [_archives[name] for name in _priority if name in _archives]
link_objects += [path for name, path in sorted(_archives.items())
                 if name not in _priority]

# The archives are linked by full path above, so nothing is left for -l.
#
# Windows is the exception. CMake passes a default set of system import
# libraries when *it* links (CMAKE_CXX_STANDARD_LIBRARIES) and setuptools does
# not, so binexport_shared's calls into the shell and path APIs arrive
# unresolved: SHCreateDirectoryExA and SHGetFolderPathA from shell32,
# PathCanonicalizeA, PathFileExistsA and PathIsRelativeA from shlwapi. That is
# why the engine links under CMake and the extension did not.
#
# shlwapi is the one BinExport names for itself; the rest are CMake's own
# defaults, listed so a future call into another of them does not send someone
# back around this loop.
libraries = ([
    "shlwapi", "shell32", "kernel32", "user32", "advapi32",
    "ole32", "oleaut32", "uuid",
] if OSTYPE == "Windows" else [])

if os.environ.get("VERBOSE_BUILD"):
    print(f"Linking {len(link_objects)} static archives:")
    for obj in link_objects:
        print(f"  - {obj}")


# The C++ standard, spelled for the compiler in hand. MSVC does not accept the
# GNU form and does not reject it either -- it warns D9002, ignores the flag,
# and compiles at its default standard, at which point Abseil's own
# policy_checks.h stops the build with "C++ versions less than C++17 are not
# supported". A silently ignored flag is why this looked like an Abseil problem
# rather than a spelling one.
CXX_STANDARD = ["/std:c++20"] if OSTYPE == "Windows" else ["-std=c++20"]


def compile_args(debug_mode=False):
    """Return platform-specific compilation arguments."""
    debug_flags = []
    base_args = list(CXX_STANDARD)  # must match what BinDiff itself builds with

    if OSTYPE == "Windows":
        if debug_mode:
            debug_flags = ["/Z7", "/Od"]
        return base_args + ["/TP", "/EHa"] + debug_flags

    elif OSTYPE == "Linux":
        if debug_mode:
            debug_flags = ["-g", "-O0", "-Wall", "-Wextra"]
        else:
            debug_flags = ["-O3"]
        return base_args + ["-fPIC"] + debug_flags + [
            "-Wno-stringop-truncation",
            "-Wno-catch-value",
            "-Wno-unused-variable",
        ]

    elif OSTYPE == "Darwin":
        ignore_warnings = [
            "-Wno-unused-variable",
            "-Wno-nullability-completeness",
            "-Wno-sign-compare",
        ]
        if debug_mode:
            debug_flags = [
                "-g", "-fno-omit-frame-pointer", "-O0", "-ggdb",
                "-UNDEBUG", "-Wall", "-Wno-deprecated-declarations"
            ]
            # Remove any -O[0-3] flags from CFLAGS if in debug mode
            cflags = os.environ.get("CFLAGS", "")
            cflags = COMPILER_OPTIMIZATION_LEVEL.sub("", cflags)
            cflags = "-O0 " + cflags.strip()
            os.environ["CFLAGS"] = cflags.strip()
        else:
            debug_flags = ["-O3"]

        return base_args + [
            "-stdlib=libc++",
            "-mmacosx-version-min=10.15"
        ] + debug_flags + ignore_warnings

    return base_args


def link_args(debug_mode=False):
    """Return platform-specific linker arguments."""
    if OSTYPE == "Darwin":
        args = ["-stdlib=libc++", "-mmacosx-version-min=10.15"]
        if debug_mode:
            args.append("-g")
        return args
    elif OSTYPE == "Linux":
        return ["-g"] if debug_mode else []
    elif OSTYPE == "Windows":
        return ["/DEBUG"] if debug_mode else []
    return []


# Extra compile and link arguments
extra_compile_args = compile_args(DEBUG_MODE)
extra_link_args = link_args(DEBUG_MODE)

# GNU ld resolves archives in a single pass, so a cycle between (say) absl_status
# and absl_strings would otherwise need the same archive listed twice.
# --start-group makes the order irrelevant. ld64 on macOS already re-scans
# archives and rejects the flag.
if OSTYPE == "Linux":
    extra_link_args = (
        extra_link_args + ["-Wl,--start-group"] + link_objects + ["-Wl,--end-group"]
    )
else:
    extra_link_args = extra_link_args + link_objects

# Define extensions
extensions = [
    Extension(
        "bindiff.core",
        sources=[
            "bindiff/core.pyx",
            "bindiff/wrappers.cc",
        ],
        # The static archives are listed as dependencies, not just linked.
        # Without this, changing a C++ source rebuilds libbindiff_shared.a but
        # setuptools sees no newer *source* and skips the relink, so the
        # extension keeps the old object code -- and a fix to the engine
        # silently does not reach the Python tests. That cost real time to
        # find: an engine bug looked unfixed through three rebuilds because the
        # .so was never relinked.
        depends=[
            "bindiff/core.pxd",
            "bindiff/wrappers.h",
        ] + link_objects,
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        language="c++",
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    ),
    # There is no second extension. bindiff.ida_plugin used to wrap a
    # ResultsWrapper class that reimplemented the engine's Results against an
    # in-memory vector, with its writes unimplemented and its reads querying
    # tables that do not exist. Reading and editing a .BinDiff is now
    # bindiff.database, in plain sqlite3, so there is nothing left for it to do.
]

# Cythonize with Cython 3.0+ features
compiler_directives = {
    "language_level": "3",
    "embedsignature": True,
    "binding": True,
    "boundscheck": False if not DEBUG_MODE else True,
    "wraparound": False if not DEBUG_MODE else True,
    # Debug-only directives
    "profile": DEBUG_MODE,
    "linetrace": DEBUG_MODE,
}

# Debug mode macros
macros = []
if DEBUG_MODE:
    macros.append(("CYTHON_TRACE", "1"))
    macros.append(("CYTHON_CLINE_IN_TRACEBACK", "1"))
    if sys.version_info >= (3, 13):
        macros.append(("CYTHON_USE_SYS_MONITORING", "1"))
    if sys.version_info < (3, 12):
        macros.append(("CYTHON_PROFILE", "1"))

    # Add macros to extensions
    for ext in extensions:
        ext.define_macros = macros

setup(
    ext_modules=cythonize(
        extensions,
        compiler_directives=compiler_directives,
        annotate=DEBUG_MODE,  # Generate HTML annotation files in debug mode
        gdb_debug=DEBUG_MODE,
    ),
)
