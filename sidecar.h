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

#ifndef SIDECAR_H_
#define SIDECAR_H_

#include <cstdint>
#include <string>
#include <vector>

#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/base/nullability.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/zynamics/binexport/util/types.h"

namespace security::bindiff {

// Per-function feature values read from a metadata sidecar, indexed for lookup
// by entry point address.
//
// A sidecar is optional: "foo.BinExport.meta" sits beside "foo.BinExport" and
// carries features BinExport itself does not record. When there is no sidecar
// the index is simply empty and every step that consumes it finds nothing,
// which is how the engine behaves with no sidecars anywhere.
//
// Only the metrics the engine can act on are indexed. Fuzzy hashes are parsed
// and dropped rather than stored, because nothing consumes them yet.
class FeatureIndex {
 public:
  using KeySet = std::vector<uint64_t>;
  // Normalised on the way in, so cosine similarity is a plain dot product and
  // no consumer has to remember to divide.
  using Vector = std::vector<float>;

  // Sorted, deduplicated key set for `feature` at `address`, or nullptr when
  // this function does not carry the feature.
  const KeySet* absl_nullable LookupKeySet(absl::string_view feature,
                                           Address address) const;

  // Exact key for `feature` at `address`, or nullptr.
  const uint64_t* absl_nullable LookupExactKey(absl::string_view feature,
                                               Address address) const;

  // Unit-length embedding for `feature` at `address`, or nullptr.
  const Vector* absl_nullable LookupVector(absl::string_view feature,
                                           Address address) const;

  // Dimension of `feature`'s vectors, or 0 when it has none. A feature is one
  // width for the whole file; a function whose vector disagrees is dropped on
  // load, because comparing two different embeddings would produce a number
  // that means nothing.
  int Dimension(absl::string_view feature) const;

  // How many functions carry `feature`. A feature present on three functions
  // out of four thousand is not worth running a matching pass over, and a
  // caller can skip it without walking the index.
  int Count(absl::string_view feature) const;

  // Which comparison `feature` was written for. A feature is one shape or the
  // other for the whole file -- the producer decides, and a consumer must not
  // guess -- so a caller asks once and dispatches rather than probing each
  // function.
  bool HasKeySets(absl::string_view feature) const {
    return key_sets_.contains(feature);
  }
  bool HasExactKeys(absl::string_view feature) const {
    return exact_keys_.contains(feature);
  }
  bool HasVectors(absl::string_view feature) const {
    return vectors_.contains(feature);
  }

  bool empty() const {
    return key_sets_.empty() && exact_keys_.empty() && vectors_.empty();
  }

  // Adds one function's value. Public so tests can build an index without a
  // file on disk; the loader below is the usual way in.
  void AddKeySet(absl::string_view feature, Address address, KeySet keys);
  void AddExactKey(absl::string_view feature, Address address, uint64_t key);
  // Returns false when `values` disagrees with the width already recorded for
  // this feature, or is empty or all zero -- a zero vector has no direction and
  // so no cosine to anything.
  bool AddVector(absl::string_view feature, Address address, Vector values);

 private:
  // Feature name -> address -> value. Two hashes per lookup, which is the same
  // cost the existing steps pay to reach a flow graph's cached features.
  absl::flat_hash_map<std::string, absl::flat_hash_map<Address, KeySet>>
      key_sets_;
  absl::flat_hash_map<std::string, absl::flat_hash_map<Address, uint64_t>>
      exact_keys_;
  absl::flat_hash_map<std::string, absl::flat_hash_map<Address, Vector>>
      vectors_;
  absl::flat_hash_map<std::string, int> dimensions_;
};

// Jaccard overlap of two sorted, deduplicated key sets: |A n B| / |A u B|.
// Returns 0 when either side is empty -- two functions that call nothing are
// not thereby similar.
double JaccardSimilarity(const FeatureIndex::KeySet& lhs,
                         const FeatureIndex::KeySet& rhs);

// Cosine similarity of two vectors the index has already normalised, so this
// is their dot product. Returns 0 for differing widths rather than comparing a
// prefix, which would be a number with no meaning.
//
// Mapped from [-1, 1] onto [0, 1]: an opposed pair is as far from a match as
// two vectors get, and every threshold in the engine is a similarity in [0, 1].
double CosineSimilarity(const FeatureIndex::Vector& lhs,
                        const FeatureIndex::Vector& rhs);

// Loads the sidecar for `binexport_path`, if there is one.
//
// Returns an empty index when no sidecar exists: absence is the normal case
// and is not an error. Returns an error when a sidecar exists but cannot be
// parsed, or when it describes a different executable than `executable_id`
// -- pairing metadata with the wrong binary would produce confident, wrong
// matches, which is worse than having no metadata at all.
//
// `executable_id` is BinExport2.Meta.executable_id, which a caller already has
// after reading the export. It is compared only when both sides have one; an
// exporter that set no id leaves the weaker guarantee that the sidecar was
// found at the expected path.
absl::StatusOr<FeatureIndex> LoadSidecar(const std::string& binexport_path,
                                         absl::string_view executable_id);

// The path a sidecar is expected at: "foo.BinExport" -> "foo.BinExport.meta".
std::string SidecarPathFor(absl::string_view binexport_path);

}  // namespace security::bindiff

#endif  // SIDECAR_H_
