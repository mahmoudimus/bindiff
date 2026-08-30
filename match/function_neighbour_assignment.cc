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

#include "third_party/zynamics/bindiff/match/function_neighbour_assignment.h"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <limits>
#include <utility>
#include <vector>

#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/container/flat_hash_set.h"
#include "third_party/zynamics/bindiff/call_graph.h"
#include "third_party/zynamics/bindiff/fixed_points.h"

namespace security::bindiff {
namespace {

// Both directions. A caller identifies a function as well as a callee does,
// and the evidence this step uses is symmetric.
std::vector<FlowGraph*> Neighbours(const CallGraph& call_graph,
                                   FlowGraph* flow_graph) {
  std::vector<FlowGraph*> neighbours;
  const CallGraph::Vertex vertex =
      call_graph.GetVertex(flow_graph->GetEntryPointAddress());
  const auto& graph = call_graph.GetGraph();
  for (auto [edge, end] = boost::out_edges(vertex, graph); edge != end;
       ++edge) {
    if (FlowGraph* other = call_graph.GetFlowGraph(boost::target(*edge, graph));
        other && other != flow_graph) {
      neighbours.push_back(other);
    }
  }
  for (auto [edge, end] = boost::in_edges(vertex, graph); edge != end; ++edge) {
    if (FlowGraph* other = call_graph.GetFlowGraph(boost::source(*edge, graph));
        other && other != flow_graph) {
      neighbours.push_back(other);
    }
  }
  std::sort(neighbours.begin(), neighbours.end());
  neighbours.erase(std::unique(neighbours.begin(), neighbours.end()),
                   neighbours.end());
  return neighbours;
}

// The counterpart of an already-matched function, or nullptr.
FlowGraph* MatchedCounterpart(FlowGraph* flow_graph) {
  FixedPoint* fixed_point = flow_graph->GetFixedPoint();
  return fixed_point ? fixed_point->GetSecondary() : nullptr;
}

// How alike two functions are in size, in [0, 1]. Not a similarity measure so
// much as a veto: it stops the step pairing a two-instruction thunk with a
// thousand-instruction function because they happen to sit in the same corner
// of the call graph.
double InstructionRatio(FlowGraph* lhs, FlowGraph* rhs) {
  const int left = lhs->GetInstructionCount();
  const int right = rhs->GetInstructionCount();
  if (left <= 0 || right <= 0) {
    return 0.0;
  }
  return static_cast<double>(std::min(left, right)) / std::max(left, right);
}

struct Component {
  std::vector<int> rows;
  std::vector<int> columns;
};

// Connected components of the sparse candidate graph.
//
// The assignment only has to be solved within a component: a row in one
// component has no candidate in another, so choosing for one cannot change the
// best choice for the other. Sparse evidence makes the components small, which
// is what keeps a cubic solve affordable.
std::vector<Component> ConnectedComponents(
    int rows, int columns,
    const absl::flat_hash_map<int, absl::flat_hash_map<int, double>>& edges) {
  // Union-find over rows [0, rows) and columns offset by `rows`.
  std::vector<int> parent(rows + columns);
  for (int i = 0; i < static_cast<int>(parent.size()); ++i) {
    parent[i] = i;
  }
  std::function<int(int)> find = [&](int node) {
    while (parent[node] != node) {
      parent[node] = parent[parent[node]];
      node = parent[node];
    }
    return node;
  };
  for (const auto& [row, columns_for_row] : edges) {
    for (const auto& [column, unused_weight] : columns_for_row) {
      const int a = find(row);
      const int b = find(rows + column);
      if (a != b) {
        parent[a] = b;
      }
    }
  }

  absl::flat_hash_map<int, Component> by_root;
  absl::flat_hash_set<int> seen_columns;
  for (const auto& [row, columns_for_row] : edges) {
    Component& component = by_root[find(row)];
    component.rows.push_back(row);
    for (const auto& [column, unused_weight] : columns_for_row) {
      if (seen_columns.insert(column).second) {
        by_root[find(rows + column)].columns.push_back(column);
      }
    }
  }

  std::vector<Component> components;
  for (auto& [unused_root, component] : by_root) {
    if (!component.rows.empty() && !component.columns.empty()) {
      components.push_back(std::move(component));
    }
  }
  return components;
}

}  // namespace

std::vector<int> SolveAssignment(const std::vector<double>& weights, int rows,
                                 int columns) {
  std::vector<int> assignment(rows, -1);
  if (rows <= 0 || columns <= 0) {
    return assignment;
  }

  // The augmenting-path solve below assumes there is a column for every row:
  // with more rows than columns it runs out of columns to augment into and
  // leaves the matching half-built. Transposing costs one pass and makes that
  // case the one the algorithm is written for.
  if (rows > columns) {
    std::vector<double> transposed(weights.size());
    for (int row = 0; row < rows; ++row) {
      for (int column = 0; column < columns; ++column) {
        transposed[static_cast<size_t>(column) * rows + row] =
            weights[static_cast<size_t>(row) * columns + column];
      }
    }
    const std::vector<int> flipped = SolveAssignment(transposed, columns, rows);
    for (int column = 0; column < static_cast<int>(flipped.size()); ++column) {
      if (flipped[column] >= 0) {
        assignment[flipped[column]] = column;
      }
    }
    return assignment;
  }

  // Jonker-Volgenant style shortest augmenting path, the textbook O(n^3)
  // Hungarian. It minimises, so weights are negated: what is wanted is the set
  // of pairs with the greatest total agreement.
  //
  // Indices are 1-based inside, which is what makes the sentinel column 0
  // usable as the start of every augmenting path.
  const int n = rows;
  const int m = columns;
  constexpr double kInfinity = std::numeric_limits<double>::max();

  auto cost = [&](int i, int j) {  // 1-based
    return -weights[static_cast<size_t>(i - 1) * columns + (j - 1)];
  };

  std::vector<double> potential_row(n + 1, 0.0);
  std::vector<double> potential_column(m + 1, 0.0);
  std::vector<int> match_for_column(m + 1, 0);
  std::vector<int> previous(m + 1, 0);

  for (int i = 1; i <= n; ++i) {
    match_for_column[0] = i;
    int column = 0;
    std::vector<double> shortest(m + 1, kInfinity);
    std::vector<char> visited(m + 1, false);
    do {
      visited[column] = true;
      const int row = match_for_column[column];
      double delta = kInfinity;
      int next_column = -1;
      for (int j = 1; j <= m; ++j) {
        if (visited[j]) {
          continue;
        }
        const double current =
            cost(row, j) - potential_row[row] - potential_column[j];
        if (current < shortest[j]) {
          shortest[j] = current;
          previous[j] = column;
        }
        if (shortest[j] < delta) {
          delta = shortest[j];
          next_column = j;
        }
      }
      if (next_column < 0) {
        break;  // Fewer columns than rows; the rest stay unassigned.
      }
      for (int j = 0; j <= m; ++j) {
        if (visited[j]) {
          potential_row[match_for_column[j]] += delta;
          potential_column[j] -= delta;
        } else {
          shortest[j] -= delta;
        }
      }
      column = next_column;
    } while (match_for_column[column] != 0);

    if (column == 0) {
      continue;
    }
    // Walk the augmenting path back, reassigning as it goes.
    while (column != 0) {
      const int from = previous[column];
      match_for_column[column] = match_for_column[from];
      column = from;
    }
  }

  for (int j = 1; j <= m; ++j) {
    if (match_for_column[j] > 0) {
      assignment[match_for_column[j] - 1] = j - 1;
    }
  }
  return assignment;
}

MatchingStepCallGraphNeighbourAssignment::
    MatchingStepCallGraphNeighbourAssignment()
    : MatchingStep("function: call graph neighbour assignment",
                   "Function: Call Graph Neighbour Assignment") {}

bool MatchingStepCallGraphNeighbourAssignment::FindFixedPoints(
    const FlowGraph* primary_parent, const FlowGraph* secondary_parent,
    FlowGraphs& flow_graphs_1, FlowGraphs& flow_graphs_2,
    MatchingContext& context, MatchingSteps& matching_steps,
    const MatchingStepsFlowGraph& default_steps) {
  matching_steps.pop_front();

  std::vector<FlowGraph*> left;
  for (FlowGraph* flow_graph : flow_graphs_1) {
    if (IsValidCandidate(flow_graph)) {
      left.push_back(flow_graph);
    }
  }
  std::vector<FlowGraph*> right;
  absl::flat_hash_map<FlowGraph*, int> right_index;
  for (FlowGraph* flow_graph : flow_graphs_2) {
    if (IsValidCandidate(flow_graph)) {
      right_index[flow_graph] = static_cast<int>(right.size());
      right.push_back(flow_graph);
    }
  }
  if (left.empty() || right.empty()) {
    return false;
  }

  // Sparse candidate graph: a pair is a candidate only when at least one of
  // their neighbours is already matched to one of the other's. Building it
  // this way rather than scoring all pairs is what keeps the step affordable;
  // the dense matrix would be |left| x |right|.
  absl::flat_hash_map<int, absl::flat_hash_map<int, double>> agreements;
  for (int row = 0; row < static_cast<int>(left.size()); ++row) {
    absl::flat_hash_map<int, int> shared;
    for (FlowGraph* neighbour :
         Neighbours(context.primary_call_graph_, left[row])) {
      FlowGraph* counterpart = MatchedCounterpart(neighbour);
      if (!counterpart) {
        continue;
      }
      // Every unmatched neighbour of the counterpart is a candidate, and this
      // agreement is one vote for it.
      for (FlowGraph* candidate :
           Neighbours(context.secondary_call_graph_, counterpart)) {
        auto found = right_index.find(candidate);
        if (found != right_index.end()) {
          ++shared[found->second];
        }
      }
    }
    for (const auto& [column, votes] : shared) {
      if (votes < kMinAgreeingNeighbours) {
        continue;
      }
      const double ratio = InstructionRatio(left[row], right[column]);
      if (ratio < kMinInstructionRatio) {
        continue;
      }
      // The vote count dominates and the size ratio only breaks ties: an extra
      // agreeing neighbour is stronger evidence than any amount of similarity
      // in length, and a weight that let the ratio overturn it would be
      // preferring the wrong signal.
      agreements[row][column] = votes + 0.5 * ratio;
    }
  }
  if (agreements.empty()) {
    return false;
  }

  bool fixed_points_discovered = false;
  for (const Component& component :
       ConnectedComponents(static_cast<int>(left.size()),
                           static_cast<int>(right.size()), agreements)) {
    std::vector<std::pair<int, int>> chosen;
    if (static_cast<int>(component.rows.size()) > kMaxComponentSize ||
        static_cast<int>(component.columns.size()) > kMaxComponentSize) {
      // Too tangled to be worth solving exactly. Falls back to taking each
      // best pair in descending order of agreement, which is what the rest of
      // the engine would have done anyway.
      std::vector<std::pair<double, std::pair<int, int>>> ranked;
      for (int row : component.rows) {
        for (const auto& [column, weight] : agreements[row]) {
          ranked.push_back({weight, {row, column}});
        }
      }
      std::sort(ranked.rbegin(), ranked.rend());
      absl::flat_hash_set<int> used_rows;
      absl::flat_hash_set<int> used_columns;
      for (const auto& [unused_weight, pair] : ranked) {
        if (used_rows.insert(pair.first).second &&
            used_columns.insert(pair.second).second) {
          chosen.push_back(pair);
        }
      }
    } else {
      std::vector<double> weights(
          component.rows.size() * component.columns.size(), 0.0);
      absl::flat_hash_map<int, int> column_position;
      for (int i = 0; i < static_cast<int>(component.columns.size()); ++i) {
        column_position[component.columns[i]] = i;
      }
      for (int i = 0; i < static_cast<int>(component.rows.size()); ++i) {
        for (const auto& [column, weight] : agreements[component.rows[i]]) {
          weights[i * component.columns.size() + column_position[column]] =
              weight;
        }
      }
      const std::vector<int> assignment =
          SolveAssignment(weights, static_cast<int>(component.rows.size()),
                          static_cast<int>(component.columns.size()));
      for (int i = 0; i < static_cast<int>(assignment.size()); ++i) {
        if (assignment[i] < 0) {
          continue;
        }
        // A zero weight means the solver filled a slot with a pair that is not
        // a candidate at all -- the matrix is dense and most of it is zero --
        // so it is discarded rather than taken.
        if (weights[i * component.columns.size() + assignment[i]] <= 0.0) {
          continue;
        }
        chosen.push_back({component.rows[i],
                          component.columns[assignment[i]]});
      }
    }

    for (const auto& [row, column] : chosen) {
      FlowGraph* primary = left[row];
      FlowGraph* secondary = right[column];
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
  }
  return fixed_points_discovered;
}

}  // namespace security::bindiff
