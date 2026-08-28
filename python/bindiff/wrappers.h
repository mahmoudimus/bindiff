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
#include <vector>

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

// High-level functions for Python bindings
int DiffBinaries(const std::string& primary_path,
                 const std::string& secondary_path,
                 const std::string& output_database);

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
