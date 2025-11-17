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

#include "python/bindiff/wrappers.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "third_party/zynamics/bindiff/database_writer.h"
#include "third_party/zynamics/bindiff/differ.h"
#include "third_party/zynamics/bindiff/flow_graph.h"
#include "third_party/zynamics/bindiff/instruction.h"
#include "third_party/zynamics/bindiff/match/context.h"
#include "third_party/zynamics/bindiff/reader.h"
#include "third_party/zynamics/bindiff/sqlite.h"

namespace security::bindiff {

// CallGraphWrapper implementation
CallGraphWrapper::CallGraphWrapper(CallGraph* graph) : graph_(graph) {}

std::string CallGraphWrapper::GetFilePath() const {
  return graph_->GetFilePath();
}

std::string CallGraphWrapper::GetExeFilename() const {
  return graph_->GetExeFilename();
}

std::string CallGraphWrapper::GetExeHash() const {
  return graph_->GetExeHash();
}

int CallGraphWrapper::GetNumFunctions() const {
  return boost::num_vertices(graph_->GetGraph());
}

std::vector<uint64_t> CallGraphWrapper::GetFunctionAddresses() const {
  std::vector<uint64_t> addresses;
  const auto& graph = graph_->GetGraph();

  for (auto [it, end] = boost::vertices(graph); it != end; ++it) {
    addresses.push_back(graph_->GetAddress(*it));
  }

  return addresses;
}

FunctionInfo CallGraphWrapper::GetFunctionInfo(uint64_t address) const {
  FunctionInfo info{};

  auto vertex = graph_->GetVertex(address);
  if (vertex == CallGraph::kInvalidVertex) {
    return info;
  }

  const auto& graph = graph_->GetGraph();

  info.address = address;
  info.name = graph_->GetName(vertex);
  info.demangled_name = graph_->GetDemangledName(vertex);
  info.md_index = graph_->GetMdIndex(vertex);

  // Get flow graph if available
  auto* flow_graph = graph_->GetFlowGraph(vertex);
  if (flow_graph) {
    const auto& fg = flow_graph->GetGraph();
    info.basic_block_count = boost::num_vertices(fg);
    info.edge_count = boost::num_edges(fg);

    // Count instructions
    int instruction_count = 0;
    for (auto [it, end] = boost::vertices(fg); it != end; ++it) {
      instruction_count += flow_graph->GetInstructions(*it).size();
    }
    info.instruction_count = instruction_count;
  }

  return info;
}

bool CallGraphWrapper::HasFunction(uint64_t address) const {
  return graph_->GetVertex(address) != CallGraph::kInvalidVertex;
}

int CallGraphWrapper::GetNumBasicBlocks() const {
  int count = 0;
  const auto& graph = graph_->GetGraph();

  for (auto [it, end] = boost::vertices(graph); it != end; ++it) {
    auto* flow_graph = graph_->GetFlowGraph(*it);
    if (flow_graph) {
      count += boost::num_vertices(flow_graph->GetGraph());
    }
  }

  return count;
}

int CallGraphWrapper::GetNumEdges() const {
  int count = 0;
  const auto& graph = graph_->GetGraph();

  for (auto [it, end] = boost::vertices(graph); it != end; ++it) {
    auto* flow_graph = graph_->GetFlowGraph(*it);
    if (flow_graph) {
      count += boost::num_edges(flow_graph->GetGraph());
    }
  }

  return count;
}

int CallGraphWrapper::GetNumInstructions() const {
  int count = 0;
  const auto& graph = graph_->GetGraph();

  for (auto [it, end] = boost::vertices(graph); it != end; ++it) {
    auto* flow_graph = graph_->GetFlowGraph(*it);
    if (flow_graph) {
      const auto& fg = flow_graph->GetGraph();
      for (auto [bb_it, bb_end] = boost::vertices(fg); bb_it != bb_end; ++bb_it) {
        count += flow_graph->GetInstructions(*bb_it).size();
      }
    }
  }

  return count;
}

// FlowGraphWrapper implementation
FlowGraphWrapper::FlowGraphWrapper(FlowGraph* graph) : graph_(graph) {}

uint64_t FlowGraphWrapper::GetAddress() const {
  return graph_->GetEntryPointAddress();
}

std::string FlowGraphWrapper::GetName(const CallGraph& call_graph) const {
  auto vertex = call_graph.GetVertex(GetAddress());
  if (vertex != CallGraph::kInvalidVertex) {
    return call_graph.GetName(vertex);
  }
  return "";
}

int FlowGraphWrapper::GetNumBasicBlocks() const {
  return boost::num_vertices(graph_->GetGraph());
}

int FlowGraphWrapper::GetNumEdges() const {
  return boost::num_edges(graph_->GetGraph());
}

int FlowGraphWrapper::GetNumInstructions() const {
  int count = 0;
  const auto& graph = graph_->GetGraph();

  for (auto [it, end] = boost::vertices(graph); it != end; ++it) {
    count += graph_->GetInstructions(*it).size();
  }

  return count;
}

std::vector<uint64_t> FlowGraphWrapper::GetBasicBlockAddresses() const {
  std::vector<uint64_t> addresses;
  const auto& graph = graph_->GetGraph();

  for (auto [it, end] = boost::vertices(graph); it != end; ++it) {
    addresses.push_back(graph_->GetAddress(*it));
  }

  return addresses;
}

BasicBlockInfo FlowGraphWrapper::GetBasicBlockInfo(uint64_t address) const {
  BasicBlockInfo info{};

  auto vertex = graph_->GetVertex(address);
  if (vertex == FlowGraph::kInvalidVertex) {
    return info;
  }

  info.address = address;
  info.instruction_count = graph_->GetInstructions(vertex).size();
  info.md_index = graph_->GetMdIndex(vertex);

  return info;
}

bool FlowGraphWrapper::HasBasicBlock(uint64_t address) const {
  return graph_->GetVertex(address) != FlowGraph::kInvalidVertex;
}

uint64_t FlowGraphWrapper::GetEntryPointAddress() const {
  return graph_->GetEntryPointAddress();
}

// FixedPointWrapper implementation
FixedPointWrapper::FixedPointWrapper(const FixedPoint& fixed_point)
    : fixed_point_(fixed_point) {}

uint64_t FixedPointWrapper::GetPrimaryAddress() const {
  return fixed_point_.GetPrimary() ?
         fixed_point_.GetPrimary()->GetEntryPointAddress() : 0;
}

uint64_t FixedPointWrapper::GetSecondaryAddress() const {
  return fixed_point_.GetSecondary() ?
         fixed_point_.GetSecondary()->GetEntryPointAddress() : 0;
}

double FixedPointWrapper::GetSimilarity() const {
  return fixed_point_.GetSimilarity();
}

double FixedPointWrapper::GetConfidence() const {
  return fixed_point_.GetConfidence();
}

int FixedPointWrapper::GetAlgorithm() const {
  return fixed_point_.GetMatchingStep();
}

int FixedPointWrapper::GetFlags() const {
  return fixed_point_.GetFlags();
}

int FixedPointWrapper::GetNumBasicBlockMatches() const {
  return fixed_point_.GetBasicBlockFixedPoints().size();
}

std::vector<std::pair<uint64_t, uint64_t>>
FixedPointWrapper::GetBasicBlockMatches() const {
  std::vector<std::pair<uint64_t, uint64_t>> matches;

  for (const auto& bb_fp : fixed_point_.GetBasicBlockFixedPoints()) {
    matches.emplace_back(bb_fp.GetPrimaryAddress(),
                         bb_fp.GetSecondaryAddress());
  }

  return matches;
}

// High-level diff function
int DiffBinaries(const std::string& primary_path,
                 const std::string& secondary_path,
                 const std::string& output_database) {
  try {
    // Create call graphs and instruction cache
    CallGraph call_graph1;
    CallGraph call_graph2;
    FlowGraphs flow_graphs1;
    FlowGraphs flow_graphs2;
    FlowGraphInfos flow_graph_infos1;
    FlowGraphInfos flow_graph_infos2;
    Instruction::Cache instruction_cache;

    // Read primary binary
    auto status = Read(primary_path, &call_graph1, &flow_graphs1,
                      &flow_graph_infos1, &instruction_cache);
    if (!status.ok()) {
      return -1;
    }

    // Read secondary binary
    status = Read(secondary_path, &call_graph2, &flow_graphs2,
                 &flow_graph_infos2, &instruction_cache);
    if (!status.ok()) {
      return -2;
    }

    // Perform diff
    FixedPoints fixed_points;
    MatchingContext context(call_graph1, call_graph2,
                           flow_graphs1, flow_graphs2,
                           fixed_points);

    MatchingSteps call_graph_steps;
    MatchingStepsFlowGraph flow_graph_steps;
    GetDefaultMatchingSteps(&call_graph_steps, &flow_graph_steps);

    Diff(&context, call_graph_steps, flow_graph_steps);

    // Write results to database
    auto writer = DatabaseWriter::Create(output_database,
                                        DatabaseWriter::Options());
    if (!writer.ok()) {
      return -3;
    }

    status = (*writer)->Write(call_graph1, call_graph2,
                             flow_graphs1, flow_graphs2,
                             fixed_points);
    if (!status.ok()) {
      return -4;
    }

    return 0;  // Success
  } catch (...) {
    return -99;
  }
}

// Load matches from database
std::vector<MatchInfo> LoadMatches(const std::string& database_path) {
  std::vector<MatchInfo> matches;

  try {
    auto db = *SqliteDatabase::Connect(database_path);

    // Query matches
    const char* query = R"(
      SELECT
        f1.address AS primary_address,
        f2.address AS secondary_address,
        f1.name AS primary_name,
        f2.name AS secondary_name,
        m.similarity,
        m.confidence,
        m.algorithm,
        m.evaluate,
        m.flags
      FROM function AS f1
      INNER JOIN functionmatch AS m ON f1.id = m.function1id
      INNER JOIN function AS f2 ON f2.id = m.function2id
      ORDER BY m.similarity DESC
    )";

    SqliteStatement stmt = db.StatementOrThrow(query);

    for (stmt.ExecuteOrThrow(); stmt.GotData(); stmt.ExecuteOrThrow()) {
      MatchInfo info;
      std::string primary_name, secondary_name;
      int64_t primary_addr = 0, secondary_addr = 0;
      int algorithm_id = 0, evaluate = 0, flags = 0;

      stmt.Into(&primary_addr)
          .Into(&secondary_addr)
          .Into(&primary_name)
          .Into(&secondary_name)
          .Into(&info.similarity)
          .Into(&info.confidence)
          .Into(&algorithm_id)
          .Into(&evaluate)
          .Into(&flags);

      info.primary_address = static_cast<uint64_t>(primary_addr);
      info.secondary_address = static_cast<uint64_t>(secondary_addr);
      info.primary_name = primary_name;
      info.secondary_name = secondary_name;
      info.algorithm_id = algorithm_id;
      info.is_manual = (evaluate != 0);
      info.flags = flags;

      matches.push_back(std::move(info));
    }
  } catch (...) {
    // Return empty on error
  }

  return matches;
}

// Load statistics from database
StatisticsInfo LoadStatistics(const std::string& database_path) {
  StatisticsInfo stats{};

  try {
    auto db = *SqliteDatabase::Connect(database_path);

    // Get function counts
    {
      SqliteStatement func_stmt = db.StatementOrThrow(
          "SELECT file, COUNT(*) FROM function GROUP BY file ORDER BY file");

      int file_idx = 1;
      for (func_stmt.ExecuteOrThrow(); func_stmt.GotData();
           func_stmt.ExecuteOrThrow()) {
        int file = 0, count = 0;
        func_stmt.Into(&file).Into(&count);
        if (file_idx == 1) {
          stats.primary_function_count = count;
        } else {
          stats.secondary_function_count = count;
        }
        file_idx++;
      }
    }

    // Get matched function count
    {
      SqliteStatement match_stmt =
          db.StatementOrThrow("SELECT COUNT(*) FROM functionmatch");
      match_stmt.ExecuteOrThrow();
      if (match_stmt.GotData()) {
        match_stmt.Into(&stats.matched_function_count);
      }
    }

    // Get basic block counts
    {
      SqliteStatement bb_stmt = db.StatementOrThrow(
          "SELECT file, COUNT(*) FROM basicblock GROUP BY file ORDER BY file");

      int file_idx = 1;
      for (bb_stmt.ExecuteOrThrow(); bb_stmt.GotData();
           bb_stmt.ExecuteOrThrow()) {
        int file = 0, count = 0;
        bb_stmt.Into(&file).Into(&count);
        if (file_idx == 1) {
          stats.primary_basic_block_count = count;
        } else {
          stats.secondary_basic_block_count = count;
        }
        file_idx++;
      }
    }

    // Get matched basic block count
    {
      SqliteStatement bb_match_stmt =
          db.StatementOrThrow("SELECT COUNT(*) FROM basicblockmatch");
      bb_match_stmt.ExecuteOrThrow();
      if (bb_match_stmt.GotData()) {
        bb_match_stmt.Into(&stats.matched_basic_block_count);
      }
    }

    // Get instruction counts
    {
      SqliteStatement inst_stmt = db.StatementOrThrow(
          "SELECT file, COUNT(*) FROM instruction GROUP BY file ORDER BY file");

      int file_idx = 1;
      for (inst_stmt.ExecuteOrThrow(); inst_stmt.GotData();
           inst_stmt.ExecuteOrThrow()) {
        int file = 0, count = 0;
        inst_stmt.Into(&file).Into(&count);
        if (file_idx == 1) {
          stats.primary_instruction_count = count;
        } else {
          stats.secondary_instruction_count = count;
        }
        file_idx++;
      }
    }

    // Get matched instruction count
    {
      SqliteStatement inst_match_stmt =
          db.StatementOrThrow("SELECT COUNT(*) FROM instructionmatch");
      inst_match_stmt.ExecuteOrThrow();
      if (inst_match_stmt.GotData()) {
        inst_match_stmt.Into(&stats.matched_instruction_count);
      }
    }
  } catch (...) {
    // Return zeros on error
  }

  return stats;
}

}  // namespace security::bindiff
