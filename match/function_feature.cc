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

#include "third_party/zynamics/bindiff/match/function_feature.h"

#include <string>
#include <utility>
#include <vector>

#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/strings/ascii.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/zynamics/bindiff/sidecar.h"

namespace security::bindiff {
namespace {

// One side's candidates: the flow graphs that are still unmatched, are worth
// matching at all, and actually carry the feature.
struct Candidate {
  FlowGraph* flow_graph;
  const FeatureIndex::KeySet* keys;
};

std::vector<Candidate> CollectCandidates(const FlowGraphs& flow_graphs,
                                         const FeatureIndex& index,
                                         absl::string_view feature) {
  std::vector<Candidate> candidates;
  for (FlowGraph* flow_graph : flow_graphs) {
    if (!IsValidCandidate(flow_graph)) {
      continue;
    }
    if (const auto* keys =
            index.LookupKeySet(feature, flow_graph->GetEntryPointAddress())) {
      candidates.push_back({flow_graph, keys});
    }
  }
  return candidates;
}

// The best-scoring candidate on the other side, and whether it beat the
// runner-up outright. A tie is treated the way the existing steps treat an
// ambiguous bucket: no match is taken from it.
struct BestMatch {
  int index = -1;
  double score = 0.0;
  bool unique = false;
};

BestMatch FindBest(const FeatureIndex::KeySet& keys,
                   const std::vector<Candidate>& others,
                   const absl::flat_hash_map<uint64_t, std::vector<int>>&
                       postings,
                   double threshold) {
  // Only candidates sharing at least one key can score above zero, so the
  // inverted index keeps this from being an all-pairs comparison. Without it
  // a large binary would be quadratic in its function count.
  absl::flat_hash_map<int, bool> seen;
  BestMatch best;
  double runner_up = 0.0;
  for (uint64_t key : keys) {
    auto found = postings.find(key);
    if (found == postings.end()) {
      continue;
    }
    for (int other : found->second) {
      if (!seen.emplace(other, true).second) {
        continue;
      }
      const double score = JaccardSimilarity(keys, *others[other].keys);
      if (score > best.score) {
        runner_up = best.score;
        best.score = score;
        best.index = other;
      } else if (score > runner_up) {
        runner_up = score;
      }
    }
  }
  best.unique = best.index >= 0 && best.score >= threshold &&
                best.score > runner_up;
  return best;
}

}  // namespace

MatchingStepFeature::MatchingStepFeature(std::string feature_name)
    : MatchingStep(ConfigNameFor(feature_name),
                   absl::StrCat("Function: Feature ", feature_name)),
      feature_name_(std::move(feature_name)) {}

std::string MatchingStepFeature::ConfigNameFor(absl::string_view feature_name) {
  return absl::StrCat(kNamePrefix, feature_name);
}

std::string MatchingStepFeature::FeatureNameFrom(
    absl::string_view config_name) {
  if (!absl::StartsWith(config_name, kNamePrefix)) {
    return "";
  }
  return std::string(absl::StripAsciiWhitespace(
      config_name.substr(sizeof(kNamePrefix) - 1)));
}

bool MatchingStepFeature::FindFixedPoints(
    const FlowGraph* primary_parent, const FlowGraph* secondary_parent,
    FlowGraphs& flow_graphs_1, FlowGraphs& flow_graphs_2,
    MatchingContext& context, MatchingSteps& matching_steps,
    const MatchingStepsFlowGraph& default_steps) {
  const FeatureIndex* primary_index = context.primary_features();
  const FeatureIndex* secondary_index = context.secondary_features();

  // Both sides must carry the feature for it to pair anything. When they do
  // not -- no sidecars at all, or a sidecar that does not have this feature --
  // there is nothing to do, but the step must still remove itself from the
  // list it was handed: the shared drill-down re-enters whatever is at the
  // front, and a step that left itself there would recurse into itself.
  if (!primary_index || !secondary_index ||
      primary_index->Count(feature_name_) == 0 ||
      secondary_index->Count(feature_name_) == 0) {
    matching_steps.pop_front();
    return false;
  }

  // Exact features bucket the way every other algorithm does, so they delegate
  // to the shared code and inherit its drill-down into later steps on an
  // ambiguous bucket. Similarity cannot be expressed that way and runs its own
  // search.
  if (primary_index->HasExactKeys(feature_name_) &&
      secondary_index->HasExactKeys(feature_name_)) {
    return FindExactFixedPoints(primary_parent, secondary_parent,
                                flow_graphs_1, flow_graphs_2, context,
                                matching_steps, default_steps);
  }

  matching_steps.pop_front();
  if (!primary_index->HasKeySets(feature_name_) ||
      !secondary_index->HasKeySets(feature_name_)) {
    // One side exact and the other a set: the two are not comparable, and
    // guessing at a conversion would produce matches nobody could justify.
    return false;
  }
  return FindSimilarFixedPoints(flow_graphs_1, flow_graphs_2, context,
                                default_steps);
}

bool MatchingStepFeature::FindExactFixedPoints(
    const FlowGraph* primary_parent, const FlowGraph* secondary_parent,
    FlowGraphs& flow_graphs_1, FlowGraphs& flow_graphs_2,
    MatchingContext& context, MatchingSteps& matching_steps,
    const MatchingStepsFlowGraph& default_steps) {
  const FeatureIndex& primary_index = *context.primary_features();
  const FeatureIndex& secondary_index = *context.secondary_features();

  FlowGraphIntMap map_1;
  FlowGraphIntMap map_2;
  for (FlowGraph* flow_graph : flow_graphs_1) {
    if (!IsValidCandidate(flow_graph)) {
      continue;
    }
    if (const uint64_t* key = primary_index.LookupExactKey(
            feature_name_, flow_graph->GetEntryPointAddress())) {
      map_1.emplace(*key, flow_graph);
    }
  }
  for (FlowGraph* flow_graph : flow_graphs_2) {
    if (!IsValidCandidate(flow_graph)) {
      continue;
    }
    if (const uint64_t* key = secondary_index.LookupExactKey(
            feature_name_, flow_graph->GetEntryPointAddress())) {
      map_2.emplace(*key, flow_graph);
    }
  }

  // Pops the step itself, and drills down into later steps for any bucket that
  // is ambiguous on either side.
  return ::security::bindiff::FindFixedPoints(
      primary_parent, secondary_parent, map_1, map_2, &context, matching_steps,
      default_steps);
}

bool MatchingStepFeature::FindSimilarFixedPoints(
    FlowGraphs& flow_graphs_1, FlowGraphs& flow_graphs_2,
    MatchingContext& context, const MatchingStepsFlowGraph& default_steps) {
  const std::vector<Candidate> left = CollectCandidates(
      flow_graphs_1, *context.primary_features(), feature_name_);
  if (left.empty()) {
    return false;
  }
  const std::vector<Candidate> right = CollectCandidates(
      flow_graphs_2, *context.secondary_features(), feature_name_);
  if (right.empty()) {
    return false;
  }

  absl::flat_hash_map<uint64_t, std::vector<int>> right_postings;
  for (int i = 0; i < static_cast<int>(right.size()); ++i) {
    for (uint64_t key : *right[i].keys) {
      right_postings[key].push_back(i);
    }
  }
  absl::flat_hash_map<uint64_t, std::vector<int>> left_postings;
  for (int i = 0; i < static_cast<int>(left.size()); ++i) {
    for (uint64_t key : *left[i].keys) {
      left_postings[key].push_back(i);
    }
  }

  bool fixed_points_discovered = false;
  for (int i = 0; i < static_cast<int>(left.size()); ++i) {
    const BestMatch forward = FindBest(*left[i].keys, right, right_postings,
                                       kDefaultSimilarityThreshold);
    if (!forward.unique) {
      continue;
    }
    // Require the other side to agree. A one-directional best match pairs a
    // function with whatever happens to look closest to it, which on a binary
    // full of similar wrappers is not evidence of anything.
    const BestMatch backward =
        FindBest(*right[forward.index].keys, left, left_postings,
                 kDefaultSimilarityThreshold);
    if (!backward.unique || backward.index != i) {
      continue;
    }
    // Both directions are scored against the candidate lists as they were
    // before this pass started, so a left candidate matched a few iterations
    // ago can still win the backward comparison and cause a legitimate pair to
    // be skipped. That errs towards taking fewer matches rather than wrong
    // ones, and what is skipped here remains available to every later step.

    FlowGraph* primary = left[i].flow_graph;
    FlowGraph* secondary = right[forward.index].flow_graph;
    // Re-check: an earlier iteration of this same pass may have matched one of
    // them, and CollectCandidates ran before any of that happened.
    if (primary->GetFixedPoint() || secondary->GetFixedPoint()) {
      continue;
    }

    auto [fixed_point_it, inserted] =
        context.AddFixedPoint(primary, secondary, name());
    if (!inserted) {
      continue;
    }
    FixedPoint& fixed_point = const_cast<FixedPoint&>(*fixed_point_it);
    FindFixedPointsBasicBlock(&fixed_point, &context, default_steps);
    UpdateFixedPointConfidence(fixed_point);
    fixed_points_discovered = true;
  }
  return fixed_points_discovered;
}

}  // namespace security::bindiff
