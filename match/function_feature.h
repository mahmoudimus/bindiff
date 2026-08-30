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

#ifndef MATCH_FUNCTION_FEATURE_H_
#define MATCH_FUNCTION_FEATURE_H_

#include <cstdint>
#include <string>

#include "third_party/absl/strings/string_view.h"
#include "third_party/zynamics/bindiff/flow_graph.h"
#include "third_party/zynamics/bindiff/match/call_graph.h"
#include "third_party/zynamics/bindiff/match/context.h"
#include "third_party/zynamics/bindiff/match/flow_graph.h"

namespace security::bindiff {

// Matches functions on a named feature read from a metadata sidecar.
//
// Unlike every other algorithm this one is not a fixed thing: the set of
// features is open-ended and comes from the sidecar, so a step exists per
// feature *name* and is created from the configuration rather than registered
// in a hardcoded list. Adding a new feature is meant to be a producer change
// and a config entry, not a change to the engine.
//
// Which comparison is used comes from the sidecar too, because only the
// producer knows what it emitted:
//
//   EXACT   - buckets by key and pairs buckets holding exactly one candidate
//             per side, exactly like the existing steps. Delegates to the
//             shared bucket-pairing code, so it inherits the drill-down into
//             later steps on an ambiguous bucket.
//   JACCARD - set overlap above a threshold, taking a pair only when each side
//             is the other's strictly best candidate. Needed because two
//             builds of one function agree on most of a set but rarely all of
//             it, which exact bucketing cannot express.
//   COSINE  - the same mutual-best-match rule over dense embeddings, which is
//             how a learned function representation enters the engine. The
//             engine never runs a model: a producer writes vectors into the
//             sidecar and this compares them.
class MatchingStepFeature : public MatchingStep {
 public:
  // The prefix a feature step is registered under in the configuration:
  // "imports/v1" is configured as "function: feature imports/v1".
  static constexpr const char kNamePrefix[] = "function: feature ";

  explicit MatchingStepFeature(std::string feature_name);

  bool FindFixedPoints(const FlowGraph* primary_parent,
                       const FlowGraph* secondary_parent,
                       FlowGraphs& flow_graphs_1, FlowGraphs& flow_graphs_2,
                       MatchingContext& context, MatchingSteps& matching_steps,
                       const MatchingStepsFlowGraph& default_steps) override;

  const std::string& feature_name() const { return feature_name_; }

  // The configuration name a step for `feature_name` is registered under.
  static std::string ConfigNameFor(absl::string_view feature_name);

  // The feature a configuration name refers to, or empty when `config_name` is
  // not a feature step at all.
  static std::string FeatureNameFrom(absl::string_view config_name);

 private:
  bool FindExactFixedPoints(const FlowGraph* primary_parent,
                            const FlowGraph* secondary_parent,
                            FlowGraphs& flow_graphs_1,
                            FlowGraphs& flow_graphs_2,
                            MatchingContext& context,
                            MatchingSteps& matching_steps,
                            const MatchingStepsFlowGraph& default_steps);

  bool FindSimilarFixedPoints(FlowGraphs& flow_graphs_1,
                              FlowGraphs& flow_graphs_2,
                              MatchingContext& context,
                              const MatchingStepsFlowGraph& default_steps);

  bool FindNearestVectorFixedPoints(
      FlowGraphs& flow_graphs_1, FlowGraphs& flow_graphs_2,
      MatchingContext& context, const MatchingStepsFlowGraph& default_steps);

  std::string feature_name_;
};

// Minimum Jaccard overlap for a pair to be taken. Below this the evidence is
// too weak to be worth a match that later steps would otherwise find
// structurally.
//
// Measured on the four ground-truth fixtures with the import feature: every
// threshold from 0.6 to 0.9 produced zero disagreements with ground truth, and
// the number of recovered pairs moved only from 48 to 57 across that range. So
// the value is not delicate, and this sits in the middle of the range that was
// actually tested rather than at the edge of it.
inline constexpr double kDefaultSimilarityThreshold = 0.8;

// Minimum cosine, on the same [0, 1] scale, for an embedding pair to be taken.
//
// Much higher than the Jaccard threshold, and it has to be. A set feature
// scores unrelated functions at zero because they share no keys; a dense
// embedding returns a number for every pair, and non-negative features leave
// every score above 0.5 before the threshold is even considered. The two
// numbers are not on comparable footings despite both being "similarity".
//
// Swept on nine pairs of real programs with the mnemonic-histogram producer,
// 1634 truth pairs carrying an embedding on both sides:
//
//   0.90   598 taken, 416 correct, 69.6% precision
//   0.95   410 taken, 353 correct, 86.1%
//   0.98   323 taken, 306 correct, 94.7%
//   0.995  286 taken, 281 correct, 98.3%
//
// 0.98 is where precision reaches what the import feature achieves (95%),
// which is the bar for a step that runs early: the ladder runs strongest
// first, so a step here taking a wrong pair denies it to every later step.
// Going further buys little and costs matches.
inline constexpr double kDefaultVectorThreshold = 0.98;

// Locality-sensitive hashing parameters for cosine candidate generation.
//
// Dense vectors share no discrete keys, so the inverted index the set features
// use has nothing to key on and the search would be all-pairs -- quadratic in
// the function count, which on a 36k-function binary is a billion comparisons.
// Signed random projections give back a discrete key: two vectors agree on a
// projection's sign with probability falling off in the angle between them, so
// a band of bits is a bucket that similar vectors tend to share.
//
// Bands trade recall against work. Each band is an independent chance to
// collide, so more bands find more true neighbours and inspect more candidates.
// These values put the collision probability for a 0.9-similarity pair (an
// angle of about 26 degrees) well above 0.99 while leaving the buckets narrow
// enough to prune.
inline constexpr int kVectorHashBands = 8;
inline constexpr int kVectorHashBits = 12;

// Fixed, so the same inputs always produce the same matches. A matcher whose
// answers moved between runs would make every regression test a coin flip and
// every bug report unreproducible; the projections must be drawn from a
// generator seeded identically in every process.
inline constexpr uint64_t kVectorHashSeed = 0x9E3779B97F4A7C15ULL;

}  // namespace security::bindiff

#endif  // MATCH_FUNCTION_FEATURE_H_
