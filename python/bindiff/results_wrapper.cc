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

#include "python/bindiff/sqlite_throwing.h"

namespace security::bindiff {

using ::security::bindiff::python::ConnectOrThrow;
using ::security::bindiff::python::ThrowingStatement;

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
  // NOT IMPLEMENTED: only set comments_ported on each match, so a later read
  // reported comments as ported when no comment had been touched. The real
  // operation copies names and comments into the primary database, which needs
  // a disassembler back end this wrapper does not have.
  for (size_t index : indices) {
    if (index >= impl_->matches_.size()) {
      return -1;
    }
  }
  (void)how;
  return kNotImplemented;
}

int ResultsWrapper::PortCommentsByAddress(uint64_t start_address_source,
                                          uint64_t end_address_source,
                                          uint64_t start_address_target,
                                          uint64_t end_address_target,
                                          double min_confidence,
                                          double min_similarity) {
  // NOT IMPLEMENTED, for the same reason as PortComments().
  (void)start_address_source;
  (void)end_address_source;
  (void)start_address_target;
  (void)end_address_target;
  (void)min_confidence;
  (void)min_similarity;
  return kNotImplemented;
}


// Diff operations
int ResultsWrapper::IncrementalDiff() {
  // NOT IMPLEMENTED: would re-run the matching steps over the still-unmatched
  // functions. Returned success without doing so.
  return kNotImplemented;
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

    auto db = ConnectOrThrow(filename);

    // The .BinDiff "function" table is itself the match table: each row is one
    // matched pair, with both addresses and names on it, plus the per-pair
    // basic block / edge / instruction counts. See
    // DatabaseWriter::PrepareDatabase() for the schema.
    const char* match_query = R"(
      SELECT
        f.address1,
        f.address2,
        f.name1,
        f.name2,
        f.similarity,
        f.confidence,
        f.algorithm,
        f.evaluate,
        f.flags,
        f.commentsported,
        f.basicblocks,
        f.edges,
        f.instructions,
        COALESCE(a.name, '')
      FROM function AS f
      LEFT JOIN functionalgorithm AS a ON f.algorithm = a.id
      ORDER BY f.similarity DESC
    )";

    ThrowingStatement match_stmt = db.StatementOrThrow(match_query);
    for (match_stmt.ExecuteOrThrow(); match_stmt.GotData();
         match_stmt.ExecuteOrThrow()) {
      MatchDescription match{};
      int64_t primary_addr = 0, secondary_addr = 0;
      int algorithm = 0, evaluate = 0, flags = 0;
      std::string primary_name, secondary_name;

      int comments_ported = 0;
      std::string algorithm_name;
      match_stmt.Into(&primary_addr)
          .Into(&secondary_addr)
          .Into(&primary_name)
          .Into(&secondary_name)
          .Into(&match.similarity)
          .Into(&match.confidence)
          .Into(&algorithm)
          .Into(&evaluate)
          .Into(&flags)
          .Into(&comments_ported)
          .Into(&match.basic_block_count)
          .Into(&match.edge_count)
          .Into(&match.instruction_count)
          .Into(&algorithm_name);

      match.address_primary = static_cast<uint64_t>(primary_addr);
      match.address_secondary = static_cast<uint64_t>(secondary_addr);
      match.name_primary = primary_name;
      match.name_secondary = secondary_name;
      match.algorithm_name = algorithm_name;
      // `evaluate` is always 0 on disk -- DatabaseWriter binds a literal 0 --
      // so it is not the manual flag. A match is manual when it was recorded
      // against the "function: manual" algorithm at full confidence, which is
      // the rule FixedPointInfo::IsManual() uses.
      match.manual = match.confidence == 1.0 &&
                     algorithm_name.find("manual") != std::string::npos;
      (void)evaluate;
      match.comments_ported = (comments_ported != 0);
      match.change_type = flags;

      impl_->matches_.push_back(match);
    }

    // Unmatched functions are deliberately not recoverable from a .BinDiff
    // file: the format stores matches only. The queries that used to be here
    // selected on a "file" column of the function table and a functionmatch
    // table, neither of which exists, so they could only ever have thrown --
    // and the catch-all below turned that into a silent "no results". A caller
    // that needs the unmatched sets must diff these matches against the
    // function lists in the two .BinExport inputs, which this wrapper does not
    // read. Left empty rather than silently wrong.
    impl_->unmatched_primary_.clear();
    impl_->unmatched_secondary_.clear();

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
  } catch (const std::exception&) {
    // Non-zero tells the caller the load failed. Callers must check it: the
    // wrapper is left holding whatever partial state it had read.
    return -1;
  }
}

int ResultsWrapper::WriteToFile(const std::string& filename) {
  // NOT IMPLEMENTED. This used to record the path, clear modified_ and return
  // success without writing anything, so AddMatch() -> WriteToFile() -> 0 lost
  // the edit silently. Persisting means writing the match tables back through
  // DatabaseWriter (or straight to the sqlite schema); until that exists,
  // failing is the only honest answer.
  (void)filename;
  return kNotImplemented;
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
