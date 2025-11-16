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
#include <memory>
#include <string>
#include <vector>

#include "third_party/zynamics/bindiff/call_graph.h"
#include "third_party/zynamics/bindiff/flow_graph.h"
#include "third_party/zynamics/bindiff/fixed_points.h"
#include "third_party/zynamics/bindiff/match/context.h"

namespace security::bindiff {

// Forward declarations
class Results;
class CallGraph;
class FlowGraph;

// Simplified wrapper for function information
struct FunctionInfo {
  uint64_t address;
  std::string name;
  std::string demangled_name;
  int basic_block_count;
  int edge_count;
  int instruction_count;
  double md_index;
};

// Simplified wrapper for basic block information
struct BasicBlockInfo {
  uint64_t address;
  int instruction_count;
  double md_index;
};

// Simplified wrapper for match information
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

// CallGraph wrapper providing Python-friendly interface
class CallGraphWrapper {
 public:
  explicit CallGraphWrapper(CallGraph* graph);
  ~CallGraphWrapper() = default;

  // Basic information
  std::string GetFilePath() const;
  std::string GetExeFilename() const;
  std::string GetExeHash() const;
  int GetNumFunctions() const;

  // Function access
  std::vector<uint64_t> GetFunctionAddresses() const;
  FunctionInfo GetFunctionInfo(uint64_t address) const;
  bool HasFunction(uint64_t address) const;

  // Statistics
  int GetNumBasicBlocks() const;
  int GetNumEdges() const;
  int GetNumInstructions() const;

 private:
  CallGraph* graph_;  // Non-owning pointer
};

// FlowGraph wrapper providing Python-friendly interface
class FlowGraphWrapper {
 public:
  explicit FlowGraphWrapper(FlowGraph* graph);
  ~FlowGraphWrapper() = default;

  // Basic information
  uint64_t GetAddress() const;
  std::string GetName(const CallGraph& call_graph) const;
  int GetNumBasicBlocks() const;
  int GetNumEdges() const;
  int GetNumInstructions() const;

  // Basic block access
  std::vector<uint64_t> GetBasicBlockAddresses() const;
  BasicBlockInfo GetBasicBlockInfo(uint64_t address) const;
  bool HasBasicBlock(uint64_t address) const;

  // Entry point
  uint64_t GetEntryPointAddress() const;

 private:
  FlowGraph* graph_;  // Non-owning pointer
};

// FixedPoint wrapper providing Python-friendly interface
class FixedPointWrapper {
 public:
  explicit FixedPointWrapper(const FixedPoint& fixed_point);
  ~FixedPointWrapper() = default;

  // Match information
  uint64_t GetPrimaryAddress() const;
  uint64_t GetSecondaryAddress() const;
  double GetSimilarity() const;
  double GetConfidence() const;
  int GetAlgorithm() const;
  int GetFlags() const;

  // Basic block matches
  int GetNumBasicBlockMatches() const;
  std::vector<std::pair<uint64_t, uint64_t>> GetBasicBlockMatches() const;

 private:
  const FixedPoint& fixed_point_;
};

// High-level diff function
int DiffBinaries(const std::string& primary_path,
                 const std::string& secondary_path,
                 const std::string& output_database);

// Load results from database
std::vector<MatchInfo> LoadMatches(const std::string& database_path);
StatisticsInfo LoadStatistics(const std::string& database_path);

}  // namespace security::bindiff

#endif  // PYTHON_BINDIFF_WRAPPERS_H_
