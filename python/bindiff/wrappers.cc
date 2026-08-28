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
#include "third_party/zynamics/bindiff/match/call_graph.h"
#include "third_party/zynamics/bindiff/match/context.h"
#include "third_party/zynamics/bindiff/match/flow_graph.h"
#include "third_party/zynamics/bindiff/reader.h"
#include "python/bindiff/sqlite_throwing.h"

namespace security::bindiff {

using ::security::bindiff::python::ConnectOrThrow;
using ::security::bindiff::python::ThrowingStatement;

// Simple diff function that runs BinDiff on two files
int DiffBinaries(const std::string& primary_path,
                 const std::string& secondary_path,
                 const std::string& output_database) {
  try {
    // Setup variables for diff operation
    const MatchingSteps call_graph_steps = GetDefaultMatchingSteps();
    const MatchingStepsFlowGraph basic_block_steps =
        GetDefaultMatchingStepsBasicBlock();
    Instruction::Cache instruction_cache;
    FlowGraphs flow_graphs1;
    FlowGraphs flow_graphs2;
    CallGraph call_graph1;
    CallGraph call_graph2;
    ScopedCleanup cleanup(&flow_graphs1, &flow_graphs2, &instruction_cache);

    // Read primary binary
    auto status = Read(primary_path, &call_graph1, &flow_graphs1,
                      /*flow_graph_infos=*/nullptr, &instruction_cache);
    if (!status.ok()) {
      return -1;
    }

    // Read secondary binary
    status = Read(secondary_path, &call_graph2, &flow_graphs2,
                 /*flow_graph_infos=*/nullptr, &instruction_cache);
    if (!status.ok()) {
      return -2;
    }

    // Perform diff
    FixedPoints fixed_points;
    MatchingContext context(call_graph1, call_graph2, flow_graphs1,
                           flow_graphs2, fixed_points);
    Diff(&context, call_graph_steps, basic_block_steps);

    // Write results to database
    auto database_writer = DatabaseWriter::Create(output_database);
    if (!database_writer.ok()) {
      return -3;
    }

    status = (*database_writer)->Write(call_graph1, call_graph2, flow_graphs1,
                                       flow_graphs2, fixed_points);
    if (!status.ok()) {
      return -4;
    }

    return 0;  // Success
  } catch (...) {
    return -99;  // Unknown error
  }
}

// Load matches from database
std::vector<MatchInfo> LoadMatches(const std::string& database_path) {
  std::vector<MatchInfo> matches;

  try {
    auto db = ConnectOrThrow(database_path);

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

    ThrowingStatement stmt = db.StatementOrThrow(query);

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
    auto db = ConnectOrThrow(database_path);

    // Get function counts
    {
      ThrowingStatement func_stmt = db.StatementOrThrow(
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
      ThrowingStatement match_stmt =
          db.StatementOrThrow("SELECT COUNT(*) FROM functionmatch");
      match_stmt.ExecuteOrThrow();
      if (match_stmt.GotData()) {
        match_stmt.Into(&stats.matched_function_count);
      }
    }

    // Get basic block counts
    {
      ThrowingStatement bb_stmt = db.StatementOrThrow(
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
      ThrowingStatement bb_match_stmt =
          db.StatementOrThrow("SELECT COUNT(*) FROM basicblockmatch");
      bb_match_stmt.ExecuteOrThrow();
      if (bb_match_stmt.GotData()) {
        bb_match_stmt.Into(&stats.matched_basic_block_count);
      }
    }

    // Get instruction counts
    {
      ThrowingStatement inst_stmt = db.StatementOrThrow(
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
      ThrowingStatement inst_match_stmt =
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
