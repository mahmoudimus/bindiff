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

#ifndef MATCH_FUNCTION_NEIGHBOUR_ASSIGNMENT_H_
#define MATCH_FUNCTION_NEIGHBOUR_ASSIGNMENT_H_

#include <vector>

#include "third_party/zynamics/bindiff/flow_graph.h"
#include "third_party/zynamics/bindiff/match/call_graph.h"
#include "third_party/zynamics/bindiff/match/context.h"
#include "third_party/zynamics/bindiff/match/flow_graph.h"

namespace security::bindiff {

// Matches the functions every other step left over, by agreeing on their
// call-graph neighbours and resolving the result as one global assignment.
//
// Every other step in the ladder is greedy: it buckets, takes what is
// unambiguous, and commits. That is why it runs strongest first, and it is
// also its limit -- a pair taken early is denied to every later step, and a
// pair that is ambiguous *locally* is discarded even when the rest of the
// graph would settle it. Measured on nine pairs of real programs, the engine
// mismatched more functions than it left unmatched (472 against 420), which is
// what a greedy assignment looks like from the outside.
//
// This step is the other shape. It scores each surviving candidate pair by how
// many of their call-graph neighbours are already matched *to each other* --
// the quantity IsoRank propagates, and the one BinSlayer's Hungarian pass
// scores -- and then chooses the set of pairs maximising the total rather than
// taking each best pair as it is found. Two functions with one shared
// neighbour each are ambiguous alone and decided together.
//
// It runs last, on purpose. The evidence it uses is other steps' matches, so
// it has the most to work with once they are done, and taking a weakly
// evidenced pair earlier would deny a strongly evidenced one later.
class MatchingStepCallGraphNeighbourAssignment : public MatchingStep {
 public:
  MatchingStepCallGraphNeighbourAssignment();

  bool FindFixedPoints(const FlowGraph* primary_parent,
                       const FlowGraph* secondary_parent,
                       FlowGraphs& flow_graphs_1, FlowGraphs& flow_graphs_2,
                       MatchingContext& context, MatchingSteps& matching_steps,
                       const MatchingStepsFlowGraph& default_steps) override;
};

// Minimum number of neighbour pairs that must already agree.
//
// I first argued that one was enough *because* the assignment is global -- a
// single shared neighbour rarely picks out one candidate alone, but combined
// with every other function's claims it often does. Measured, that is wrong.
// One shared neighbour is mostly noise, and a global optimum over noise is
// still noise. Correct/wrong for the step's own matches, and for the whole
// diff on two corpora:
//
//   minimum   step's own      nine real pairs    four fixtures
//   (off)          --            948 / 196         691 / 164
//   1         163/231  41%      1058 / 377         717 / 185
//   2         136/ 92  60%      1042 / 248         720 / 172
//   3         103/ 44  70%      1027 / 211         710 / 172
//
// Three adds about 98 correct matches across both corpora at a precision
// indistinguishable from not running the step at all (81.9% against 82.0%),
// which is the only version of this that pays for itself.
inline constexpr int kMinAgreeingNeighbours = 3;

// Size ratio below which a pair is not considered however well its neighbours
// agree. Two functions can sit in the same place in the call graph and still
// be nothing alike, and this step has no other content signal to notice that
// with; the ratio is the cheapest one available.
inline constexpr double kMinInstructionRatio = 0.5;

// Above this many candidates in one connected component, the exact assignment
// is abandoned for a greedy pass over the same scores. The Hungarian solve is
// cubic, and a component that large means the neighbour evidence was not
// discriminating anyway -- paying O(n^3) to arbitrate a tangle of equally
// weak claims buys nothing.
inline constexpr int kMaxComponentSize = 256;

// Solves the rectangular assignment problem: picks at most one column per row
// and one row per column, maximising the total of `weights`.
//
// Exposed for testing. `weights` is row-major, `rows` by `columns`, and a pair
// that must not be chosen carries a weight of zero -- the result is filtered
// on positive weight afterwards, so a zero-weight assignment is discarded
// rather than taken.
//
// Returns, per row, the chosen column or -1.
std::vector<int> SolveAssignment(const std::vector<double>& weights, int rows,
                                 int columns);

}  // namespace security::bindiff

#endif  // MATCH_FUNCTION_NEIGHBOUR_ASSIGNMENT_H_
