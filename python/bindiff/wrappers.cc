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

// Simple diff function that runs BinDiff on two files
int DiffBinaries(const std::string& primary_path,
                 const std::string& secondary_path,
                 const std::string& output_database) {
  try {
    // Load call graphs from BinExport files
    ChangeHistory change_history;
    FlowGraphs primary_flow_graphs;
    FlowGraphInfos primary_flow_graph_infos;
    FlowGraphs secondary_flow_graphs;
    FlowGraphInfos secondary_flow_graph_infos;
    InstructionCache instruction_cache;

    FixedPoints fixed_points;
    FlowGraphInfos fixed_point_infos;
    ScopedCleanup cleanup(primary_flow_graphs, secondary_flow_graphs);

    // Read binaries
    CallGraph primary_call_graph;
    auto status = Read(primary_path, &primary_call_graph, &primary_flow_graphs,
                      &primary_flow_graph_infos, &instruction_cache);
    if (!status.ok()) {
      return -1;
    }

    CallGraph secondary_call_graph;
    status = Read(secondary_path, &secondary_call_graph, &secondary_flow_graphs,
                 &secondary_flow_graph_infos, &instruction_cache);
    if (!status.ok()) {
      return -2;
    }

    // Run diff
    MatchingContext context(primary_call_graph, secondary_call_graph,
                           primary_flow_graphs, secondary_flow_graphs,
                           fixed_points);
    Diff(&context, change_history);

    // Write results to database
    DatabaseWriter writer(SqliteDatabase::Connect(output_database).value(),
                         output_database, primary_call_graph.GetFilePath(),
                         secondary_call_graph.GetFilePath());
    Counts counts;
    status = writer.Write(primary_call_graph, secondary_call_graph,
                         primary_flow_graphs, secondary_flow_graphs,
                         fixed_points, &counts);
    if (!status.ok()) {
      return -3;
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
