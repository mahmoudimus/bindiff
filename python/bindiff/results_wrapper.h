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

#ifndef PYTHON_BINDIFF_RESULTS_WRAPPER_H_
#define PYTHON_BINDIFF_RESULTS_WRAPPER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "third_party/zynamics/bindiff/change_classifier.h"

namespace security::bindiff {

// Forward declaration
class Results;

// Wrapper structs matching ida/results.h API

struct MatchDescription {
  double similarity;
  double confidence;
  int change_type;  // ChangeType enum
  uint64_t address_primary;
  std::string name_primary;
  uint64_t address_secondary;
  std::string name_secondary;
  bool comments_ported;
  std::string algorithm_name;
  int basic_block_count;
  int basic_block_count_primary;
  int basic_block_count_secondary;
  int edge_count;
  int edge_count_primary;
  int edge_count_secondary;
  int instruction_count;
  int instruction_count_primary;
  int instruction_count_secondary;
  bool manual;
};

struct UnmatchedDescription {
  uint64_t address;
  std::string name;
  int basic_block_count;
  int instruction_count;
  int edge_count;
};

struct StatisticDescription {
  std::string name;
  bool is_count;
  union {
    size_t count;
    double value;
  };
};

// Results wrapper providing complete API for IDA plugin
class ResultsWrapper {
 public:
  // Factory method to create Results
  static std::unique_ptr<ResultsWrapper> Create();

  // Destructor
  ~ResultsWrapper();

  // Matched functions
  size_t GetNumMatches() const;
  MatchDescription GetMatchDescription(size_t index) const;
  uint64_t GetPrimaryAddress(size_t index) const;
  uint64_t GetSecondaryAddress(size_t index) const;
  uint64_t GetMatchPrimaryAddress(size_t index) const;
  uint64_t GetMatchSecondaryAddress(size_t index) const;

  // Unmatched functions
  size_t GetNumUnmatchedPrimary() const;
  UnmatchedDescription GetUnmatchedDescriptionPrimary(size_t index) const;
  size_t GetNumUnmatchedSecondary() const;
  UnmatchedDescription GetUnmatchedDescriptionSecondary(size_t index) const;

  // Statistics
  size_t GetNumStatistics() const;
  StatisticDescription GetStatisticDescription(size_t index) const;

  // Match manipulation
  int DeleteMatches(const std::vector<size_t>& indices);
  int AddMatch(uint64_t primary, uint64_t secondary);
  int ConfirmMatches(const std::vector<size_t>& indices);

  // Comment/symbol porting
  enum PortCommentsKind { kNormal = 0, kAsExternalLib = 1 };
  int PortComments(const std::vector<size_t>& indices, PortCommentsKind how);
  int PortCommentsByAddress(uint64_t start_address_source,
                            uint64_t end_address_source,
                            uint64_t start_address_target,
                            uint64_t end_address_target,
                            double min_confidence,
                            double min_similarity);

  // Diff operations
  int IncrementalDiff();
  void MarkPortedCommentsInDatabase();

  // Visual diff preparation
  bool PrepareVisualDiff(size_t index, std::string* message);
  bool PrepareVisualCallGraphDiff(size_t index, std::string* message);

  // File I/O
  int ReadFromFile(const std::string& filename);
  int WriteToFile(const std::string& filename);

  // State management
  bool is_incomplete() const;
  bool is_modified() const;
  void set_modified();
  bool should_reset_selection() const;
  void set_should_reset_selection(bool value);

  // Get underlying Results object (for advanced use)
  Results* GetResults() { return results_.get(); }

 private:
  ResultsWrapper();
  std::unique_ptr<Results> results_;
};

}  // namespace security::bindiff

#endif  // PYTHON_BINDIFF_RESULTS_WRAPPER_H_
