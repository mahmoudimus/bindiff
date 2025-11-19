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

#include "python/bindiff/results_wrapper.h"

#include <algorithm>
#include <map>
#include <stdexcept>

#include "third_party/zynamics/bindiff/sqlite.h"

namespace security::bindiff {

// Internal implementation using pimpl pattern
class ResultsWrapper::Impl {
 public:
  Impl() : modified_(false), incomplete_(false), reset_selection_(false) {}

  std::string database_path_;
  std::vector<MatchDescription> matches_;
  std::vector<UnmatchedDescription> unmatched_primary_;
  std::vector<UnmatchedDescription> unmatched_secondary_;
  std::vector<StatisticDescription> statistics_;
  bool modified_;
  bool incomplete_;
  bool reset_selection_;
};

ResultsWrapper::ResultsWrapper() : impl_(std::make_unique<Impl>()) {}

ResultsWrapper::~ResultsWrapper() = default;

std::unique_ptr<ResultsWrapper> ResultsWrapper::Create() {
  return std::make_unique<ResultsWrapper>();
}

// Matched functions
size_t ResultsWrapper::GetNumMatches() const {
  return impl_->matches_.size();
}

MatchDescription ResultsWrapper::GetMatchDescription(size_t index) const {
  if (index >= impl_->matches_.size()) {
    throw std::out_of_range("Match index out of range");
  }
  return impl_->matches_[index];
}

uint64_t ResultsWrapper::GetPrimaryAddress(size_t index) const {
  return GetMatchDescription(index).address_primary;
}

uint64_t ResultsWrapper::GetSecondaryAddress(size_t index) const {
  return GetMatchDescription(index).address_secondary;
}

uint64_t ResultsWrapper::GetMatchPrimaryAddress(size_t index) const {
  return GetPrimaryAddress(index);
}

uint64_t ResultsWrapper::GetMatchSecondaryAddress(size_t index) const {
  return GetSecondaryAddress(index);
}

// Unmatched functions
size_t ResultsWrapper::GetNumUnmatchedPrimary() const {
  return impl_->unmatched_primary_.size();
}

UnmatchedDescription ResultsWrapper::GetUnmatchedDescriptionPrimary(
    size_t index) const {
  if (index >= impl_->unmatched_primary_.size()) {
    throw std::out_of_range("Unmatched primary index out of range");
  }
  return impl_->unmatched_primary_[index];
}

size_t ResultsWrapper::GetNumUnmatchedSecondary() const {
  return impl_->unmatched_secondary_.size();
}

UnmatchedDescription ResultsWrapper::GetUnmatchedDescriptionSecondary(
    size_t index) const {
  if (index >= impl_->unmatched_secondary_.size()) {
    throw std::out_of_range("Unmatched secondary index out of range");
  }
  return impl_->unmatched_secondary_[index];
}

// Statistics
size_t ResultsWrapper::GetNumStatistics() const {
  return impl_->statistics_.size();
}

StatisticDescription ResultsWrapper::GetStatisticDescription(
    size_t index) const {
  if (index >= impl_->statistics_.size()) {
    throw std::out_of_range("Statistic index out of range");
  }
  return impl_->statistics_[index];
}

// Match manipulation
int ResultsWrapper::DeleteMatches(const std::vector<size_t>& indices) {
  // Create a set of indices to delete (sorted in reverse order)
  std::vector<size_t> sorted_indices = indices;
  std::sort(sorted_indices.rbegin(), sorted_indices.rend());

  for (size_t index : sorted_indices) {
    if (index >= impl_->matches_.size()) {
      return -1;  // Error: index out of range
    }
    impl_->matches_.erase(impl_->matches_.begin() + index);
  }

  impl_->modified_ = true;
  impl_->reset_selection_ = true;
  return 0;
}

int ResultsWrapper::AddMatch(uint64_t primary, uint64_t secondary) {
  MatchDescription match{};
  match.address_primary = primary;
  match.address_secondary = secondary;
  match.similarity = 1.0;
  match.confidence = 1.0;
  match.manual = true;
  match.change_type = 0;

  impl_->matches_.push_back(match);
  impl_->modified_ = true;
  impl_->reset_selection_ = true;
  return 0;
}

int ResultsWrapper::ConfirmMatches(const std::vector<size_t>& indices) {
  for (size_t index : indices) {
    if (index >= impl_->matches_.size()) {
      return -1;
    }
    impl_->matches_[index].manual = true;
  }

  impl_->modified_ = true;
  return 0;
}

// Comment/symbol porting
int ResultsWrapper::PortComments(const std::vector<size_t>& indices, int how) {
  for (size_t index : indices) {
    if (index >= impl_->matches_.size()) {
      return -1;
    }
    impl_->matches_[index].comments_ported = true;
  }

  impl_->modified_ = true;
  return 0;
}

int ResultsWrapper::PortCommentsByAddress(uint64_t start_address_source,
                                          uint64_t end_address_source,
                                          uint64_t start_address_target,
                                          uint64_t end_address_target,
                                          double min_confidence,
                                          double min_similarity) {
  // Port comments for matches within address ranges
  for (auto& match : impl_->matches_) {
    if (match.address_primary >= start_address_source &&
        match.address_primary <= end_address_source &&
        match.address_secondary >= start_address_target &&
        match.address_secondary <= end_address_target &&
        match.confidence >= min_confidence &&
        match.similarity >= min_similarity) {
      match.comments_ported = true;
    }
  }

  impl_->modified_ = true;
  return 0;
}

// Diff operations
int ResultsWrapper::IncrementalDiff() {
  // TODO: Implement incremental diff
  // This would re-run matching algorithms on unmatched functions
  return 0;
}

void ResultsWrapper::MarkPortedCommentsInDatabase() {
  impl_->modified_ = true;
}

// Visual diff preparation
bool ResultsWrapper::PrepareVisualDiff(size_t index, std::string* message) {
  if (index >= impl_->matches_.size()) {
    *message = "Match index out of range";
    return false;
  }

  // In standalone mode, we can't actually prepare visual diffs
  *message = "Visual diff not available in standalone mode";
  return false;
}

bool ResultsWrapper::PrepareVisualCallGraphDiff(size_t index,
                                               std::string* message) {
  if (index >= impl_->matches_.size()) {
    *message = "Match index out of range";
    return false;
  }

  // In standalone mode, we can't actually prepare visual diffs
  *message = "Visual call graph diff not available in standalone mode";
  return false;
}

// File I/O
int ResultsWrapper::ReadFromFile(const std::string& filename) {
  try {
    impl_->database_path_ = filename;
    impl_->matches_.clear();
    impl_->unmatched_primary_.clear();
    impl_->unmatched_secondary_.clear();
    impl_->statistics_.clear();

    auto db = *SqliteDatabase::Connect(filename);

    // Load matches
    const char* match_query = R"(
      SELECT
        f1.address AS primary_address,
        f2.address AS secondary_address,
        f1.name AS primary_name,
        f2.name AS secondary_name,
        m.similarity,
        m.confidence,
        m.algorithm,
        m.evaluate,
        m.flags
      FROM function AS f1
      INNER JOIN functionmatch AS m ON f1.id = m.function1id
      INNER JOIN function AS f2 ON f2.id = m.function2id
      ORDER BY m.similarity DESC
    )";

    SqliteStatement match_stmt = db.StatementOrThrow(match_query);
    for (match_stmt.ExecuteOrThrow(); match_stmt.GotData();
         match_stmt.ExecuteOrThrow()) {
      MatchDescription match{};
      int64_t primary_addr = 0, secondary_addr = 0;
      int algorithm = 0, evaluate = 0, flags = 0;
      std::string primary_name, secondary_name;

      match_stmt.Into(&primary_addr)
          .Into(&secondary_addr)
          .Into(&primary_name)
          .Into(&secondary_name)
          .Into(&match.similarity)
          .Into(&match.confidence)
          .Into(&algorithm)
          .Into(&evaluate)
          .Into(&flags);

      match.address_primary = static_cast<uint64_t>(primary_addr);
      match.address_secondary = static_cast<uint64_t>(secondary_addr);
      match.name_primary = primary_name;
      match.name_secondary = secondary_name;
      match.manual = (evaluate != 0);
      match.comments_ported = false;
      match.change_type = 0;

      // Get basic block/edge/instruction counts for matched functions
      match.basic_block_count = 0;
      match.edge_count = 0;
      match.instruction_count = 0;

      impl_->matches_.push_back(match);
    }

    // Load unmatched primary functions
    const char* unmatched_primary_query = R"(
      SELECT address, name
      FROM function
      WHERE file = 1 AND id NOT IN (SELECT function1id FROM functionmatch)
    )";

    SqliteStatement unmatched_primary_stmt =
        db.StatementOrThrow(unmatched_primary_query);
    for (unmatched_primary_stmt.ExecuteOrThrow();
         unmatched_primary_stmt.GotData();
         unmatched_primary_stmt.ExecuteOrThrow()) {
      UnmatchedDescription unmatched{};
      int64_t addr = 0;
      std::string name;

      unmatched_primary_stmt.Into(&addr).Into(&name);

      unmatched.address = static_cast<uint64_t>(addr);
      unmatched.name = name;
      unmatched.basic_block_count = 0;
      unmatched.instruction_count = 0;
      unmatched.edge_count = 0;

      impl_->unmatched_primary_.push_back(unmatched);
    }

    // Load unmatched secondary functions
    const char* unmatched_secondary_query = R"(
      SELECT address, name
      FROM function
      WHERE file = 2 AND id NOT IN (SELECT function2id FROM functionmatch)
    )";

    SqliteStatement unmatched_secondary_stmt =
        db.StatementOrThrow(unmatched_secondary_query);
    for (unmatched_secondary_stmt.ExecuteOrThrow();
         unmatched_secondary_stmt.GotData();
         unmatched_secondary_stmt.ExecuteOrThrow()) {
      UnmatchedDescription unmatched{};
      int64_t addr = 0;
      std::string name;

      unmatched_secondary_stmt.Into(&addr).Into(&name);

      unmatched.address = static_cast<uint64_t>(addr);
      unmatched.name = name;
      unmatched.basic_block_count = 0;
      unmatched.instruction_count = 0;
      unmatched.edge_count = 0;

      impl_->unmatched_secondary_.push_back(unmatched);
    }

    // Load basic statistics
    StatisticDescription stat{};
    stat.name = "Matched Functions";
    stat.is_count = true;
    stat.count = impl_->matches_.size();
    stat.value = 0.0;
    impl_->statistics_.push_back(stat);

    stat.name = "Unmatched Primary Functions";
    stat.count = impl_->unmatched_primary_.size();
    impl_->statistics_.push_back(stat);

    stat.name = "Unmatched Secondary Functions";
    stat.count = impl_->unmatched_secondary_.size();
    impl_->statistics_.push_back(stat);

    impl_->incomplete_ = true;  // Loaded from disk
    impl_->modified_ = false;
    return 0;
  } catch (...) {
    return -1;
  }
}

int ResultsWrapper::WriteToFile(const std::string& filename) {
  // TODO: Implement write to database
  // This would save modifications back to the .BinDiff file
  impl_->database_path_ = filename;
  impl_->modified_ = false;
  return 0;
}

// State management
bool ResultsWrapper::is_incomplete() const { return impl_->incomplete_; }

bool ResultsWrapper::is_modified() const { return impl_->modified_; }

void ResultsWrapper::set_modified() { impl_->modified_ = true; }

bool ResultsWrapper::should_reset_selection() const {
  return impl_->reset_selection_;
}

void ResultsWrapper::set_should_reset_selection(bool value) {
  impl_->reset_selection_ = value;
}

}  // namespace security::bindiff
