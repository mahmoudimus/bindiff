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
import os
import platform
import re
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
BUILD_DIR = BINDIFF_ROOT / "build"

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
BINEXPORT_DIR = BINDIFF_ROOT.parent / "binexport"
if not BINEXPORT_DIR.exists():
    print("ERROR: BinExport directory not found.")
    print(f"Expected: {BINEXPORT_DIR}")
    print("\nPlease clone BinExport as a sibling directory to BinDiff:")
    print("  cd ..")
    print("  git clone https://github.com/google/binexport.git")
    sys.exit(1)

# Include directories
# Note: wrappers.h only uses standard library, but wrappers.cc needs BinDiff headers
include_dirs = [
    str(BINDIFF_ROOT),                                             # For python/bindiff/wrappers.h
    str(BUILD_DIR / "src_include"),                                # For third_party/zynamics/bindiff/*
    str(BUILD_DIR / "gen_include"),                                # For generated BinDiff headers
    str(BUILD_DIR / "_deps" / "binexport-build" / "src_include"),  # For third_party/zynamics/binexport/*.h
    str(BUILD_DIR / "_deps" / "binexport-build" / "gen_include"),  # For third_party/zynamics/binexport/*.pb.h
    str(BINEXPORT_DIR / "stubs"),                                  # For BinExport stubs
]

# Add dependency headers from CMake _deps
deps_dir = BUILD_DIR / "_deps"
if deps_dir.exists():
    # Add absl - required by BinDiff headers
    absl_src = deps_dir / "absl-src"
    if absl_src.exists():
        include_dirs.append(str(absl_src))

    # Add protobuf - required by BinDiff headers
    protobuf_src = deps_dir / "protobuf-src" / "src"
    if protobuf_src.exists():
        include_dirs.append(str(protobuf_src))

# Add Boost - required by call_graph.h
boost_include = os.environ.get("BOOST_INCLUDE_DIR")
if boost_include:
    include_dirs.append(boost_include)
else:
    # Try common Boost locations
    boost_locations = [
        BUILD_DIR / "_deps" / "boost-src",
        Path("/usr/include"),
        Path("/usr/local/include"),
    ]
    for loc in boost_locations:
        if (loc / "boost").exists():
            include_dirs.append(str(loc))
            break

# Library directories - recursively find all CMake build output directories
library_dirs = [str(BUILD_DIR)]

# Find all directories containing static libraries
for subdir in BUILD_DIR.rglob("*"):
    if subdir.is_dir():
        # Check if this directory contains any libraries
        has_libs = any(subdir.glob("*.a")) or any(subdir.glob("*.lib"))
        if has_libs and str(subdir) not in library_dirs:
            library_dirs.append(str(subdir))

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

# Libraries to link
# Note: Order matters - list dependencies after dependents
libraries = [
    "bindiff_shared",
    "bindiff_config",
    "bindiff_version",
]

# Add required dependencies (abseil, binexport, sqlite)
# These are typically built by CMake as static libraries
if OSTYPE != "Windows":
    libraries.extend([
        "binexport_shared",
        "sqlite",
        # Protocol Buffers - required by BinExport
        "protobuf",
        "utf8_validity",
        # Abseil libraries - required by bindiff_shared and protobuf
        # Order matters: list dependencies after dependents
        "absl_strings",
        "absl_str_format_internal",
        "absl_strings_internal",
        "absl_string_view",
        "absl_int128",
        "absl_raw_hash_set",
        "absl_hashtablez_sampler",
        "absl_hash",
        "absl_city",
        "absl_status",
        "absl_statusor",
        "absl_cord",
        "absl_cordz_info",
        "absl_cord_internal",
        "absl_cordz_handle",
        "absl_cordz_functions",
        "absl_exponential_biased",
        "absl_synchronization",
        "absl_graphcycles_internal",
        "absl_kernel_timeout_internal",
        "absl_time",
        "absl_civil_time",
        "absl_time_zone",
        "absl_malloc_internal",
        "absl_base",
        "absl_spinlock_wait",
        "absl_throw_delegate",
        "absl_raw_logging_internal",
        "absl_log_severity",
        "absl_log_internal_check_op",
        "absl_log_internal_conditions",
        "absl_log_internal_message",
        "absl_log_internal_log_sink_set",
        "absl_log_internal_globals",
        "absl_log_internal_proto",
        "absl_log_internal_format",
        "absl_log_internal_nullguard",
        "absl_log_sink",
        "absl_log_globals",
        "absl_log_initialize",
        "absl_strerror",
        "absl_examine_stack",
        "absl_stacktrace",
        "absl_symbolize",
        "absl_debugging_internal",
        "absl_demangle_internal",
        "absl_vlog_config_internal",
    ])
else:
    # Windows uses different naming
    libraries.extend([
        "binexport_shared",
        "sqlite3",
        # TODO: Add absl libraries for Windows
    ])


def compile_args(debug_mode=False):
    """Return platform-specific compilation arguments."""
    debug_flags = []
    base_args = ["-std=c++17"]

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

# Define extensions
extensions = [
    Extension(
        "bindiff.core",
        sources=[
            "bindiff/core.pyx",
            "bindiff/wrappers.cc",
        ],
        depends=[
            "bindiff/core.pxd",
            "bindiff/wrappers.h",
        ],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        language="c++",
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    ),
    Extension(
        "bindiff.ida_plugin",
        sources=[
            "bindiff/ida_plugin.pyx",
            "bindiff/results_wrapper.cc",
        ],
        depends=[
            "bindiff/ida_plugin.pxd",
            "bindiff/results_wrapper.h",
        ],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        language="c++",
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    ),
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
