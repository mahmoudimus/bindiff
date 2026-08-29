// Copyright 2011-2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PYTHON_BINDIFF_WRAPPERS_H_
#define PYTHON_BINDIFF_WRAPPERS_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "third_party/absl/base/nullability.h"

namespace security::bindiff {

// Simplified match information struct for Python bindings
struct MatchInfo {
  uint64_t primary_address;
  uint64_t secondary_address;
  std::string primary_name;
  std::string secondary_name;
  double similarity;
  double confidence;
  int algorithm_id;
  std::string algorithm_name;
  bool is_manual;
  int flags;
};

// Simplified wrapper for statistics
struct StatisticsInfo {
  // Function counts
  int primary_function_count;
  int secondary_function_count;
  int matched_function_count;

  // Basic block counts
  int primary_basic_block_count;
  int secondary_basic_block_count;
  int matched_basic_block_count;

  // Instruction counts
  int primary_instruction_count;
  int secondary_instruction_count;
  int matched_instruction_count;

  // Edge counts
  int primary_edge_count;
  int secondary_edge_count;
  int matched_edge_count;
};

// Progress and cancellation for DiffBinaries.
//
// A plain function pointer plus an opaque pointer, not std::function: the
// caller is Cython, which can hand over a `cdef` function marked `with gil`
// but cannot easily build a std::function that reacquires the GIL. The engine
// side wraps this back into a DiffCallback.
//
// Returning zero cancels. Whatever has been matched so far is still written,
// so a cancelled diff produces a smaller usable database rather than nothing.
//
// `int` rather than `bool` deliberately: Cython's `bint` generates a C `int`,
// and a function pointer returning `bool` is a different type, so the two do
// not convert.
//
// Called from the thread running the diff, which has released the GIL --
// an implementation must take it back before touching Python.
using DiffProgressFn = int (*)(int step_index, int step_count,
                               const char* absl_nonnull step_name,
                               uint64_t fixed_points,
                               void* absl_nullable user_data);

// High-level functions for Python bindings
int DiffBinaries(const std::string& primary_path,
                 const std::string& secondary_path,
                 const std::string& output_database,
                 DiffProgressFn absl_nullable progress = nullptr,
                 void* absl_nullable user_data = nullptr);

// Re-runs matching over the functions an existing diff left unmatched.
//
// The matches already in `existing_database` are re-created as fixed points
// before the matching steps run. Every matching step skips a function that
// already has one (IsValidCandidate checks exactly that), so the existing
// matches are preserved verbatim -- manual ones included -- and only the
// remainder is considered. The result is written to `output_database`, which
// may be the same path as the input.
//
// Returns the number of *newly* discovered matches, or a negative error code
// on the same scheme as DiffBinaries.
int IncrementalDiff(const std::string& primary_path,
                    const std::string& secondary_path,
                    const std::string& existing_database,
                    const std::string& output_database);

// Reads the comments recorded in a .BinExport, keyed by address.
//
// Porting comments between databases needs the *secondary* binary's comments,
// which the .BinDiff result file does not carry -- it stores matches only.
// This is where they come from.
std::vector<std::pair<uint64_t, std::string>> LoadComments(
    const std::string& binexport_path);

// Load results from database
std::vector<MatchInfo> LoadMatches(const std::string& database_path);
StatisticsInfo LoadStatistics(const std::string& database_path);

// Configuration.
//
// The engine takes its matching algorithms, their order and their confidence
// values from a process-wide config. These expose it as JSON so the Python side
// can read it, change it and put it back without a bespoke setter per field.
//
// GetConfigJson returns the config currently in effect; GetDefaultConfigJson
// returns the compiled-in defaults. SetConfigJson merges the supplied JSON over
// the defaults and installs the result, and throws if the JSON does not parse
// as a Config.
//
// Not synchronised: the config is a shared global that the differ reads while
// it runs. Change it between diffs, never during one.
std::string GetConfigJson();
std::string GetDefaultConfigJson();
void SetConfigJson(const std::string& json);

}  // namespace security::bindiff

#endif  // PYTHON_BINDIFF_WRAPPERS_H_
