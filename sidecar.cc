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

int FeatureIndex::Count(absl::string_view feature) const {
  if (auto found = key_sets_.find(feature); found != key_sets_.end()) {
    return found->second.size();
  }
  if (auto found = exact_keys_.find(feature); found != exact_keys_.end()) {
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
        default:
          // Vectors and fuzzy hashes are parsed and dropped: nothing consumes
          // them yet, and keeping an embedding per function would cost real
          // memory for no benefit. An unknown metric is skipped rather than
          // guessed at -- only the producer knows how its values compare.
          break;
      }
    }
  }
  return index;
}

}  // namespace security::bindiff
