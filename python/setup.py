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
"""

import os
import sys
from pathlib import Path
from setuptools import setup, Extension
from Cython.Build import cythonize

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
include_dirs = [
    str(BINDIFF_ROOT),
    str(BUILD_DIR / "src_include"),
    str(BUILD_DIR / "gen_include"),
    str(BINEXPORT_DIR / "stubs"),
]

# Add Boost include directory if available
boost_include = os.environ.get("BOOST_INCLUDE_DIR")
if boost_include:
    include_dirs.append(boost_include)
else:
    # Try to find Boost in common locations
    boost_locations = [
        BUILD_DIR / "_deps" / "boost-src",
        Path("/usr/include"),
        Path("/usr/local/include"),
    ]
    for loc in boost_locations:
        if (loc / "boost").exists():
            include_dirs.append(str(loc))
            break

# Library directories
library_dirs = [
    str(BUILD_DIR),
]

# Libraries to link
libraries = [
    "bindiff_shared",
    "bindiff_config",
    "bindiff_version",
]

# Extra compile arguments
extra_compile_args = [
    "-std=c++17",
    "-O3",
]

# Platform-specific settings
if sys.platform == "darwin":
    extra_compile_args.extend(["-stdlib=libc++", "-mmacosx-version-min=10.15"])
elif sys.platform == "linux":
    extra_compile_args.append("-fPIC")

# Extra link arguments
extra_link_args = []
if sys.platform == "darwin":
    extra_link_args.extend(["-stdlib=libc++", "-mmacosx-version-min=10.15"])

# Define extensions
extensions = [
    Extension(
        "bindiff.core",
        sources=[
            "bindiff/core.pyx",
            "bindiff/wrappers.cc",
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
}

setup(
    ext_modules=cythonize(
        extensions,
        compiler_directives=compiler_directives,
        annotate=True,  # Generate HTML annotation files
    ),
)
