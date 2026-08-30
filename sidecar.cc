// Copyright 2011-2026 Google LLC
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

#include "third_party/zynamics/bindiff/sidecar.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/zynamics/bindiff/bindiff_metadata.pb.h"

namespace security::bindiff {

const FeatureIndex::KeySet* absl_nullable FeatureIndex::LookupKeySet(
    absl::string_view feature, Address address) const {
  auto by_name = key_sets_.find(feature);
  if (by_name == key_sets_.end()) {
    return nullptr;
  }
  auto found = by_name->second.find(address);
  return found != by_name->second.end() ? &found->second : nullptr;
}

const uint64_t* absl_nullable FeatureIndex::LookupExactKey(
    absl::string_view feature, Address address) const {
  auto by_name = exact_keys_.find(feature);
  if (by_name == exact_keys_.end()) {
    return nullptr;
  }
  auto found = by_name->second.find(address);
  return found != by_name->second.end() ? &found->second : nullptr;
}

const FeatureIndex::Vector* absl_nullable FeatureIndex::LookupVector(
    absl::string_view feature, Address address) const {
  auto by_name = vectors_.find(feature);
  if (by_name == vectors_.end()) {
    return nullptr;
  }
  auto found = by_name->second.find(address);
  return found != by_name->second.end() ? &found->second : nullptr;
}

int FeatureIndex::Dimension(absl::string_view feature) const {
  auto found = dimensions_.find(feature);
  return found != dimensions_.end() ? found->second : 0;
}

int FeatureIndex::Count(absl::string_view feature) const {
  if (auto found = key_sets_.find(feature); found != key_sets_.end()) {
    return found->second.size();
  }
  if (auto found = exact_keys_.find(feature); found != exact_keys_.end()) {
    return found->second.size();
  }
  if (auto found = vectors_.find(feature); found != vectors_.end()) {
    return found->second.size();
  }
  return 0;
}

void FeatureIndex::AddKeySet(absl::string_view feature, Address address,
                             KeySet keys) {
  // The schema promises sorted and deduplicated so the intersection below can
  // be linear. A producer that forgot would otherwise cause silently wrong
  // similarities rather than an obvious failure, so normalise on the way in.
  std::sort(keys.begin(), keys.end());
  keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
  key_sets_[std::string(feature)][address] = std::move(keys);
}

void FeatureIndex::AddExactKey(absl::string_view feature, Address address,
                               uint64_t key) {
  exact_keys_[std::string(feature)][address] = key;
}

bool FeatureIndex::AddVector(absl::string_view feature, Address address,
                             Vector values) {
  if (values.empty()) {
    return false;
  }
  const int dimension = static_cast<int>(values.size());
  auto [known, inserted] =
      dimensions_.emplace(std::string(feature), dimension);
  if (!inserted && known->second != dimension) {
    // The first vector seen sets the width. A producer that changed its model
    // halfway through a file would otherwise have half its functions compared
    // against the other half on a prefix, which is not a similarity.
    return false;
  }

  // Normalised here so every consumer gets a dot product. Done in double and
  // stored as float: the sum of squares over a few hundred dimensions loses
  // real precision in float, and the storage is what costs memory, not the
  // arithmetic.
  double sum_of_squares = 0.0;
  for (float value : values) {
    sum_of_squares += static_cast<double>(value) * value;
  }
  if (!(sum_of_squares > 0.0)) {
    // Zero, or a NaN that made the comparison false. Either way there is no
    // direction to compare, and normalising would produce NaNs that quietly
    // poison every score they touch.
    return false;
  }
  const double norm = std::sqrt(sum_of_squares);
  for (float& value : values) {
    value = static_cast<float>(value / norm);
  }
  vectors_[std::string(feature)][address] = std::move(values);
  return true;
}

double JaccardSimilarity(const FeatureIndex::KeySet& lhs,
                         const FeatureIndex::KeySet& rhs) {
  if (lhs.empty() || rhs.empty()) {
    return 0.0;
  }
  // Both sides are sorted and deduplicated, so one merge pass suffices.
  size_t intersection = 0;
  auto left = lhs.begin();
  auto right = rhs.begin();
  while (left != lhs.end() && right != rhs.end()) {
    if (*left < *right) {
      ++left;
    } else if (*right < *left) {
      ++right;
    } else {
      ++intersection;
      ++left;
      ++right;
    }
  }
  const size_t union_size = lhs.size() + rhs.size() - intersection;
  return union_size ? static_cast<double>(intersection) / union_size : 0.0;
}

double CosineSimilarity(const FeatureIndex::Vector& lhs,
                        const FeatureIndex::Vector& rhs) {
  if (lhs.empty() || lhs.size() != rhs.size()) {
    return 0.0;
  }
  double dot = 0.0;
  for (size_t i = 0; i < lhs.size(); ++i) {
    dot += static_cast<double>(lhs[i]) * rhs[i];
  }
  // Both sides are unit length, so the dot product is already the cosine;
  // clamped because rounding can put it a hair outside [-1, 1].
  dot = std::clamp(dot, -1.0, 1.0);
  return (dot + 1.0) / 2.0;
}

std::string SidecarPathFor(absl::string_view binexport_path) {
  return absl::StrCat(binexport_path, ".meta");
}

absl::StatusOr<FeatureIndex> LoadSidecar(const std::string& binexport_path,
                                         absl::string_view executable_id) {
  FeatureIndex index;

  const std::string path = SidecarPathFor(binexport_path);
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    // No sidecar. This is the normal case and not an error: BinDiff behaves
    // exactly as it does without any metadata at all.
    return index;
  }

  BinaryMetadata metadata;
  if (!metadata.ParseFromIstream(&stream)) {
    return absl::FailedPreconditionError(
        absl::StrCat("parsing failed for metadata sidecar: ", path));
  }

  if (!executable_id.empty() && !metadata.executable_id().empty() &&
      metadata.executable_id() != executable_id) {
    return absl::FailedPreconditionError(absl::StrCat(
        path, " describes a different executable (sidecar says ",
        metadata.executable_id(), ", ", binexport_path, " says ",
        executable_id, ")"));
  }

  for (const auto& function : metadata.functions()) {
    for (const auto& feature : function.features()) {
      switch (feature.metric()) {
        case FEATURE_METRIC_JACCARD:
          if (feature.has_key_set()) {
            index.AddKeySet(feature.name(), function.address(),
                            FeatureIndex::KeySet(
                                feature.key_set().keys().begin(),
                                feature.key_set().keys().end()));
          }
          break;
        case FEATURE_METRIC_EXACT:
          if (feature.has_key()) {
            index.AddExactKey(feature.name(), function.address(),
                              feature.key());
          }
          break;
        case FEATURE_METRIC_COSINE:
          if (feature.has_vector()) {
            // A rejected vector -- wrong width for its feature, or no
            // direction -- is dropped rather than failing the load. One bad
            // function should not cost the whole sidecar, and the step simply
            // has one fewer candidate.
            index.AddVector(feature.name(), function.address(),
                            FeatureIndex::Vector(
                                feature.vector().values().begin(),
                                feature.vector().values().end()));
          }
          break;
        default:
          // Fuzzy hashes are parsed and dropped: nothing consumes them yet. An
          // unknown metric is skipped rather than guessed at -- only the
          // producer knows how its values compare.
          break;
      }
    }
  }
  return index;
}

}  // namespace security::bindiff
