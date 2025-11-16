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

# CMake build file for BinDiff Python bindings

cmake_minimum_required(VERSION 3.20)

# C++ wrapper library for Python bindings
# This provides simplified C++ wrappers around Boost graph types
add_library(bindiff_python_wrappers STATIC
  bindiff/wrappers.cc
  bindiff/wrappers.h
  bindiff/results_wrapper.cc
  bindiff/results_wrapper.h
)

target_link_libraries(bindiff_python_wrappers
  bindiff_base
  bindiff_shared
  absl::status
  absl::strings
)

# Conditionally link IDA plugin Results if available
if(TARGET bindiff_ida_results)
  target_link_libraries(bindiff_python_wrappers bindiff_ida_results)
  target_compile_definitions(bindiff_python_wrappers PRIVATE BINDIFF_IDA_PLUGIN=1)
endif()

set_target_properties(bindiff_python_wrappers PROPERTIES
  INTERPROCEDURAL_OPTIMIZATION ${BINDIFF_ENABLE_IPO}
  POSITION_INDEPENDENT_CODE ON  # Required for Python extension modules
)

# Installation target for Python package
# Users can run: pip install python/
install(
  FILES
    bindiff/__init__.py
    bindiff/core.pxd
    bindiff/core.pyx
    bindiff/results.py
    bindiff/wrappers.h
    bindiff/wrappers.cc
    bindiff/results_wrapper.h
    bindiff/results_wrapper.cc
    bindiff/ida_plugin.pxd
    bindiff/ida_plugin.pyx
  DESTINATION python/bindiff
)

install(
  FILES
    setup.py
    pyproject.toml
    README.md
  DESTINATION python
)

install(
  FILES
    examples/basic_diff.py
    examples/analyze_results.py
    examples/pyside6_viewer.py
  DESTINATION python/examples
)

install(
  FILES
    ida_plugin/bindiff_plugin.py
    ida_plugin/README.md
  DESTINATION python/ida_plugin
)

# Optional: Build Python extension directly with CMake
# This requires FindPython and Cython modules
option(BINDIFF_BUILD_PYTHON_EXTENSION
       "Build Python extension module with CMake (requires Python and Cython)" OFF)

if(BINDIFF_BUILD_PYTHON_EXTENSION)
  find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

  # Check for Cython
  execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import Cython; print(Cython.__version__)"
    RESULT_VARIABLE CYTHON_CHECK
    OUTPUT_VARIABLE CYTHON_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  if(NOT CYTHON_CHECK EQUAL 0)
    message(FATAL_ERROR "Cython not found. Install with: pip install Cython>=3.0")
  endif()

  message(STATUS "Found Cython version: ${CYTHON_VERSION}")

  # Cythonize .pyx files
  set(CYTHON_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bindiff/core.cpp)

  add_custom_command(
    OUTPUT ${CYTHON_OUTPUT}
    COMMAND ${Python3_EXECUTABLE} -m cython
            --cplus
            -3
            ${CMAKE_CURRENT_SOURCE_DIR}/bindiff/core.pyx
            -o ${CYTHON_OUTPUT}
    DEPENDS bindiff/core.pyx bindiff/core.pxd
    COMMENT "Cythonizing core.pyx"
  )

  # Python extension module
  add_library(bindiff_python_core MODULE
    ${CYTHON_OUTPUT}
  )

  target_include_directories(bindiff_python_core PRIVATE
    ${Python3_INCLUDE_DIRS}
  )

  target_link_libraries(bindiff_python_core
    bindiff_python_wrappers
    bindiff_shared
    ${Python3_LIBRARIES}
  )

  set_target_properties(bindiff_python_core PROPERTIES
    PREFIX ""  # No 'lib' prefix
    OUTPUT_NAME "core"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bindiff
  )

  if(APPLE)
    set_target_properties(bindiff_python_core PROPERTIES
      SUFFIX ".so"  # Use .so on macOS (not .dylib)
    )
  endif()

  message(STATUS "Python extension module will be built: bindiff.core")
endif()
