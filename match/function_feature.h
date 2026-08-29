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

}  // namespace security::bindiff

#endif  // MATCH_FUNCTION_FEATURE_H_
