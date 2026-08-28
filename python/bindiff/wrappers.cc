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

    // In the .BinDiff schema the "function" table *is* the match table: one row
    // per matched pair, holding both addresses and names side by side. There is
    // no separate functionmatch table, and unmatched functions are not stored
    // at all -- consumers recover those by comparing against the .BinExport
    // inputs. See DatabaseWriter::PrepareDatabase() for the schema.
    const char* query = R"(
      SELECT
        f.address1,
        f.address2,
        f.name1,
        f.name2,
        f.similarity,
        f.confidence,
        f.algorithm,
        f.evaluate,
        f.flags,
        COALESCE(a.name, '')
      FROM function AS f
      LEFT JOIN functionalgorithm AS a ON f.algorithm = a.id
      ORDER BY f.similarity DESC
    )";

    ThrowingStatement stmt = db.StatementOrThrow(query);

    for (stmt.ExecuteOrThrow(); stmt.GotData(); stmt.ExecuteOrThrow()) {
      MatchInfo info;
      std::string primary_name, secondary_name;
      int64_t primary_addr = 0, secondary_addr = 0;
      int algorithm_id = 0, evaluate = 0, flags = 0;

      std::string algorithm_name;
      stmt.Into(&primary_addr)
          .Into(&secondary_addr)
          .Into(&primary_name)
          .Into(&secondary_name)
          .Into(&info.similarity)
          .Into(&info.confidence)
          .Into(&algorithm_id)
          .Into(&evaluate)
          .Into(&flags)
          .Into(&algorithm_name);

      info.primary_address = static_cast<uint64_t>(primary_addr);
      info.secondary_address = static_cast<uint64_t>(secondary_addr);
      info.primary_name = primary_name;
      info.secondary_name = secondary_name;
      info.algorithm_id = algorithm_id;
      info.algorithm_name = algorithm_name;
      info.is_manual = (evaluate != 0);
      info.flags = flags;

      matches.push_back(std::move(info));
    }
  } catch (const std::exception& error) {
    // Rethrow rather than returning an empty vector: swallowing here would make
    // an unreadable database look exactly like a diff that found no matches.
    // The Cython declaration is `except +`, so this reaches Python as an
    // ordinary exception.
    throw;
  }

  return matches;
}

// Load statistics from database
StatisticsInfo LoadStatistics(const std::string& database_path) {
  StatisticsInfo stats{};

  auto db = ConnectOrThrow(database_path);

  // Per-input totals live in the "file" table, one row per input, ordered by
  // id: id 1 is the primary, id 2 the secondary. The counts are of everything
  // in that binary, matched or not.
  //
  // Each quantity is split across two columns: "functions" counts only
  // non-library functions and "libfunctions" the rest, so the total is their
  // sum (the CLI prints these as "219 functions ... 117 non-library"). Reading
  // just the first column understates the total, which can leave the matched
  // count looking larger than the number of functions available to match.
  {
    ThrowingStatement file_stmt = db.StatementOrThrow(
        "SELECT functions + libfunctions,"
        "       basicblocks + libbasicblocks,"
        "       instructions + libinstructions,"
        "       edges + libedges "
        "FROM file ORDER BY id");
    int row = 0;
    for (file_stmt.ExecuteOrThrow(); file_stmt.GotData();
         file_stmt.ExecuteOrThrow()) {
      int functions = 0, basic_blocks = 0, instructions = 0, edges = 0;
      file_stmt.Into(&functions)
          .Into(&basic_blocks)
          .Into(&instructions)
          .Into(&edges);
      if (row == 0) {
        stats.primary_function_count = functions;
        stats.primary_basic_block_count = basic_blocks;
        stats.primary_instruction_count = instructions;
        stats.primary_edge_count = edges;
      } else if (row == 1) {
        stats.secondary_function_count = functions;
        stats.secondary_basic_block_count = basic_blocks;
        stats.secondary_instruction_count = instructions;
        stats.secondary_edge_count = edges;
      }
      ++row;
    }
  }

  // Matched counts are row counts of the three match tables. "function" holds
  // matched function pairs, "basicblock" matched basic-block pairs, and
  // "instruction" matched instruction pairs. Matched edges are not stored
  // per-pair; the per-function edge counts sum to the total.
  {
    ThrowingStatement stmt = db.StatementOrThrow(
        "SELECT (SELECT COUNT(*) FROM function),"
        "       (SELECT COUNT(*) FROM basicblock),"
        "       (SELECT COUNT(*) FROM instruction),"
        "       (SELECT COALESCE(SUM(edges), 0) FROM function)");
    stmt.ExecuteOrThrow();
    if (stmt.GotData()) {
      stmt.Into(&stats.matched_function_count)
          .Into(&stats.matched_basic_block_count)
          .Into(&stats.matched_instruction_count)
          .Into(&stats.matched_edge_count);
    }
  }

  return stats;
}

}  // namespace security::bindiff
