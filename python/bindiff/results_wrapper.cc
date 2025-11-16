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

#include <utility>

#ifdef BINDIFF_IDA_PLUGIN
#include "third_party/zynamics/bindiff/ida/results.h"
#else
// For standalone builds, we need to provide a minimal Results implementation
// or link against a stub. For now, we'll create wrapper functions that
// work with database files directly.
#include "third_party/zynamics/bindiff/database_writer.h"
#include "third_party/zynamics/bindiff/reader.h"
#include "third_party/zynamics/bindiff/sqlite.h"
#include "third_party/zynamics/bindiff/writer.h"
#endif

namespace security::bindiff {

#ifdef BINDIFF_IDA_PLUGIN

// IDA plugin build - use real Results class

ResultsWrapper::ResultsWrapper() = default;

ResultsWrapper::~ResultsWrapper() = default;

std::unique_ptr<ResultsWrapper> ResultsWrapper::Create() {
  auto wrapper = std::unique_ptr<ResultsWrapper>(new ResultsWrapper());
  auto results = Results::Create();
  if (!results.ok()) {
    return nullptr;
  }
  wrapper->results_ = std::move(*results);
  return wrapper;
}

size_t ResultsWrapper::GetNumMatches() const {
  return results_->GetNumMatches();
}

MatchDescription ResultsWrapper::GetMatchDescription(size_t index) const {
  auto desc = results_->GetMatchDescription(index);
  MatchDescription result;
  result.similarity = desc.similarity;
  result.confidence = desc.confidence;
  result.change_type = static_cast<int>(desc.change_type);
  result.address_primary = desc.address_primary;
  result.name_primary = desc.name_primary;
  result.address_secondary = desc.address_secondary;
  result.name_secondary = desc.name_secondary;
  result.comments_ported = desc.comments_ported;
  result.algorithm_name = desc.algorithm_name;
  result.basic_block_count = desc.basic_block_count;
  result.basic_block_count_primary = desc.basic_block_count_primary;
  result.basic_block_count_secondary = desc.basic_block_count_secondary;
  result.edge_count = desc.edge_count;
  result.edge_count_primary = desc.edge_count_primary;
  result.edge_count_secondary = desc.edge_count_secondary;
  result.instruction_count = desc.instruction_count;
  result.instruction_count_primary = desc.instruction_count_primary;
  result.instruction_count_secondary = desc.instruction_count_secondary;
  result.manual = desc.manual;
  return result;
}

uint64_t ResultsWrapper::GetPrimaryAddress(size_t index) const {
  return results_->GetPrimaryAddress(index);
}

uint64_t ResultsWrapper::GetSecondaryAddress(size_t index) const {
  return results_->GetSecondaryAddress(index);
}

uint64_t ResultsWrapper::GetMatchPrimaryAddress(size_t index) const {
  return results_->GetMatchPrimaryAddress(index);
}

uint64_t ResultsWrapper::GetMatchSecondaryAddress(size_t index) const {
  return results_->GetMatchSecondaryAddress(index);
}

size_t ResultsWrapper::GetNumUnmatchedPrimary() const {
  return results_->GetNumUnmatchedPrimary();
}

UnmatchedDescription ResultsWrapper::GetUnmatchedDescriptionPrimary(
    size_t index) const {
  auto desc = results_->GetUnmatchedDescriptionPrimary(index);
  UnmatchedDescription result;
  result.address = desc.address;
  result.name = desc.name;
  result.basic_block_count = desc.basic_block_count;
  result.instruction_count = desc.instruction_count;
  result.edge_count = desc.edge_count;
  return result;
}

size_t ResultsWrapper::GetNumUnmatchedSecondary() const {
  return results_->GetNumUnmatchedSecondary();
}

UnmatchedDescription ResultsWrapper::GetUnmatchedDescriptionSecondary(
    size_t index) const {
  auto desc = results_->GetUnmatchedDescriptionSecondary(index);
  UnmatchedDescription result;
  result.address = desc.address;
  result.name = desc.name;
  result.basic_block_count = desc.basic_block_count;
  result.instruction_count = desc.instruction_count;
  result.edge_count = desc.edge_count;
  return result;
}

size_t ResultsWrapper::GetNumStatistics() const {
  return results_->GetNumStatistics();
}

StatisticDescription ResultsWrapper::GetStatisticDescription(
    size_t index) const {
  auto desc = results_->GetStatisticDescription(index);
  StatisticDescription result;
  result.name = desc.name;
  result.is_count = desc.is_count;
  if (desc.is_count) {
    result.count = desc.count;
  } else {
    result.value = desc.value;
  }
  return result;
}

int ResultsWrapper::DeleteMatches(const std::vector<size_t>& indices) {
  auto status = results_->DeleteMatches(indices);
  return status.ok() ? 0 : -1;
}

int ResultsWrapper::AddMatch(uint64_t primary, uint64_t secondary) {
  auto status = results_->AddMatch(primary, secondary);
  return status.ok() ? 0 : -1;
}

int ResultsWrapper::ConfirmMatches(const std::vector<size_t>& indices) {
  auto status = results_->ConfirmMatches(indices);
  return status.ok() ? 0 : -1;
}

int ResultsWrapper::PortComments(const std::vector<size_t>& indices,
                                PortCommentsKind how) {
  auto kind = how == kAsExternalLib ? Results::kAsExternalLib : Results::kNormal;
  auto status = results_->PortComments(indices, kind);
  return status.ok() ? 0 : -1;
}

int ResultsWrapper::PortCommentsByAddress(uint64_t start_address_source,
                                         uint64_t end_address_source,
                                         uint64_t start_address_target,
                                         uint64_t end_address_target,
                                         double min_confidence,
                                         double min_similarity) {
  auto status = results_->PortComments(start_address_source, end_address_source,
                                      start_address_target, end_address_target,
                                      min_confidence, min_similarity);
  return status.ok() ? 0 : -1;
}

int ResultsWrapper::IncrementalDiff() {
  auto status = results_->IncrementalDiff();
  return status.ok() ? 0 : -1;
}

void ResultsWrapper::MarkPortedCommentsInDatabase() {
  results_->MarkPortedCommentsInDatabase();
}

bool ResultsWrapper::PrepareVisualDiff(size_t index, std::string* message) {
  return results_->PrepareVisualDiff(index, message);
}

bool ResultsWrapper::PrepareVisualCallGraphDiff(size_t index,
                                               std::string* message) {
  return results_->PrepareVisualCallGraphDiff(index, message);
}

int ResultsWrapper::ReadFromFile(const std::string& filename) {
  try {
    SqliteDatabase db(filename, SqliteDatabase::kReadOnly);
    Reader reader(&db);
    results_->Read(&reader);
    return 0;
  } catch (...) {
    return -1;
  }
}

int ResultsWrapper::WriteToFile(const std::string& filename) {
  try {
    SqliteDatabase db(filename, SqliteDatabase::kReadWrite);
    Writer writer(&db);
    auto status = results_->Write(&writer);
    return status.ok() ? 0 : -1;
  } catch (...) {
    return -1;
  }
}

bool ResultsWrapper::is_incomplete() const {
  return results_->is_incomplete();
}

bool ResultsWrapper::is_modified() const {
  return results_->is_modified();
}

void ResultsWrapper::set_modified() {
  results_->set_modified();
}

bool ResultsWrapper::should_reset_selection() const {
  return results_->should_reset_selection();
}

void ResultsWrapper::set_should_reset_selection(bool value) {
  results_->set_should_reset_selection(value);
}

#else  // !BINDIFF_IDA_PLUGIN

// Standalone build - provide minimal implementation
// This allows building the Python package without IDA SDK

ResultsWrapper::ResultsWrapper() = default;
ResultsWrapper::~ResultsWrapper() = default;

std::unique_ptr<ResultsWrapper> ResultsWrapper::Create() {
  // For standalone builds, Results is not available
  // This would only work in IDA plugin context
  return nullptr;
}

// Stub implementations for standalone build
size_t ResultsWrapper::GetNumMatches() const { return 0; }
MatchDescription ResultsWrapper::GetMatchDescription(size_t) const { return {}; }
uint64_t ResultsWrapper::GetPrimaryAddress(size_t) const { return 0; }
uint64_t ResultsWrapper::GetSecondaryAddress(size_t) const { return 0; }
uint64_t ResultsWrapper::GetMatchPrimaryAddress(size_t) const { return 0; }
uint64_t ResultsWrapper::GetMatchSecondaryAddress(size_t) const { return 0; }
size_t ResultsWrapper::GetNumUnmatchedPrimary() const { return 0; }
UnmatchedDescription ResultsWrapper::GetUnmatchedDescriptionPrimary(size_t) const { return {}; }
size_t ResultsWrapper::GetNumUnmatchedSecondary() const { return 0; }
UnmatchedDescription ResultsWrapper::GetUnmatchedDescriptionSecondary(size_t) const { return {}; }
size_t ResultsWrapper::GetNumStatistics() const { return 0; }
StatisticDescription ResultsWrapper::GetStatisticDescription(size_t) const { return {}; }
int ResultsWrapper::DeleteMatches(const std::vector<size_t>&) { return -1; }
int ResultsWrapper::AddMatch(uint64_t, uint64_t) { return -1; }
int ResultsWrapper::ConfirmMatches(const std::vector<size_t>&) { return -1; }
int ResultsWrapper::PortComments(const std::vector<size_t>&, PortCommentsKind) { return -1; }
int ResultsWrapper::PortCommentsByAddress(uint64_t, uint64_t, uint64_t, uint64_t, double, double) { return -1; }
int ResultsWrapper::IncrementalDiff() { return -1; }
void ResultsWrapper::MarkPortedCommentsInDatabase() {}
bool ResultsWrapper::PrepareVisualDiff(size_t, std::string*) { return false; }
bool ResultsWrapper::PrepareVisualCallGraphDiff(size_t, std::string*) { return false; }
int ResultsWrapper::ReadFromFile(const std::string&) { return -1; }
int ResultsWrapper::WriteToFile(const std::string&) { return -1; }
bool ResultsWrapper::is_incomplete() const { return false; }
bool ResultsWrapper::is_modified() const { return false; }
void ResultsWrapper::set_modified() {}
bool ResultsWrapper::should_reset_selection() const { return false; }
void ResultsWrapper::set_should_reset_selection(bool) {}

#endif  // BINDIFF_IDA_PLUGIN

}  // namespace security::bindiff
