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
#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/zynamics/bindiff/comment.h"
#include "third_party/zynamics/bindiff/config.h"
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

namespace {

// Indexes flow graphs by entry point address. FlowGraphs is a std::set ordered
// by address, so a linear scan per lookup would be quadratic over the whole
// match list.
absl::flat_hash_map<Address, FlowGraph*> IndexByEntryPoint(
    const FlowGraphs& flow_graphs) {
  absl::flat_hash_map<Address, FlowGraph*> index;
  index.reserve(flow_graphs.size());
  for (FlowGraph* flow_graph : flow_graphs) {
    index[flow_graph->GetEntryPointAddress()] = flow_graph;
  }
  return index;
}

}  // namespace

int IncrementalDiff(const std::string& primary_path,
                    const std::string& secondary_path,
                    const std::string& existing_database,
                    const std::string& output_database) {
  try {
    const MatchingSteps call_graph_steps = GetDefaultMatchingSteps();
    const MatchingStepsFlowGraph basic_block_steps =
        GetDefaultMatchingStepsBasicBlock();
    Instruction::Cache instruction_cache;
    FlowGraphs flow_graphs1;
    FlowGraphs flow_graphs2;
    CallGraph call_graph1;
    CallGraph call_graph2;
    ScopedCleanup cleanup(&flow_graphs1, &flow_graphs2, &instruction_cache);

    if (!Read(primary_path, &call_graph1, &flow_graphs1,
              /*flow_graph_infos=*/nullptr, &instruction_cache)
             .ok()) {
      return -1;
    }
    if (!Read(secondary_path, &call_graph2, &flow_graphs2,
              /*flow_graph_infos=*/nullptr, &instruction_cache)
             .ok()) {
      return -2;
    }

    FixedPoints fixed_points;
    MatchingContext context(call_graph1, call_graph2, flow_graphs1,
                            flow_graphs2, fixed_points);

    // Seed from the existing result file.
    const auto primary_index = IndexByEntryPoint(flow_graphs1);
    const auto secondary_index = IndexByEntryPoint(flow_graphs2);

    int seeded = 0;
    {
      auto db = ConnectOrThrow(existing_database);
      ThrowingStatement stmt = db.StatementOrThrow(R"(
        SELECT f.address1, f.address2, COALESCE(a.name, '')
        FROM function AS f
        LEFT JOIN functionalgorithm AS a ON f.algorithm = a.id
      )");
      for (stmt.ExecuteOrThrow(); stmt.GotData(); stmt.ExecuteOrThrow()) {
        int64_t primary_address = 0, secondary_address = 0;
        std::string algorithm;
        stmt.Into(&primary_address).Into(&secondary_address).Into(&algorithm);

        auto primary = primary_index.find(static_cast<Address>(primary_address));
        auto secondary =
            secondary_index.find(static_cast<Address>(secondary_address));
        // A match naming a function that is not in these inputs means the
        // result file was produced from different binaries. Skip it rather
        // than fabricate a fixed point against the wrong function.
        if (primary == primary_index.end() ||
            secondary == secondary_index.end()) {
          continue;
        }

        auto added = context.AddFixedPoint(
            primary->second, secondary->second,
            algorithm.empty() ? MatchingStep::kFunctionManualName : algorithm);
        if (!added.second) {
          continue;
        }
        // Recreate the basic block matches for the pair: the fixed point on
        // its own carries no counts, and the writer reports them per match.
        FixedPoint& fixed_point = const_cast<FixedPoint&>(*added.first);
        FindFixedPointsBasicBlock(&fixed_point, &context, basic_block_steps);
        UpdateFixedPointConfidence(fixed_point);
        ++seeded;
      }
    }

    // Every step skips a function that already has a fixed point, so this only
    // considers what the previous diff left over.
    Diff(&context, call_graph_steps, basic_block_steps);

    auto database_writer = DatabaseWriter::Create(output_database);
    if (!database_writer.ok()) {
      return -3;
    }
    if (!(*database_writer)
             ->Write(call_graph1, call_graph2, flow_graphs1, flow_graphs2,
                     fixed_points)
             .ok()) {
      return -4;
    }
    return static_cast<int>(fixed_points.size()) - seeded;
  } catch (...) {
    return -99;
  }
}

std::vector<std::pair<uint64_t, std::string>> LoadComments(
    const std::string& binexport_path) {
  std::vector<std::pair<uint64_t, std::string>> comments;

  Instruction::Cache instruction_cache;
  FlowGraphs flow_graphs;
  CallGraph call_graph;
  ScopedCleanup cleanup(&flow_graphs, /*flow_graphs2=*/nullptr,
                        &instruction_cache);

  auto status = Read(binexport_path, &call_graph, &flow_graphs,
                     /*flow_graph_infos=*/nullptr, &instruction_cache);
  python::ThrowIfError(status, absl::StrCat("reading '", binexport_path, "'"));

  // Keyed by (address, operand); the operand is dropped here because the
  // consumer writes one comment per address.
  for (const auto& [operator_id, comment] : call_graph.comments()) {
    if (!comment.comment.empty()) {
      comments.emplace_back(static_cast<uint64_t>(operator_id.first),
                            comment.comment);
    }
  }
  return comments;
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
      // A match is manual when it was recorded against the "function: manual"
      // algorithm at full confidence -- the same rule FixedPointInfo::IsManual()
      // applies. The `evaluate` column is not that flag: DatabaseWriter always
      // writes 0 to it, so keying off it made is_manual permanently false.
      info.is_manual = info.confidence == 1.0 &&
                       algorithm_name.find("manual") != std::string::npos;
      (void)evaluate;
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

std::string GetConfigJson() {
  return config::AsJsonString(config::Proto());
}

std::string GetDefaultConfigJson() {
  return config::AsJsonString(config::Defaults());
}

void SetConfigJson(const std::string& json) {
  auto loaded = config::LoadFromJson(json);
  python::ThrowIfError(loaded.status(), "parsing configuration");

  // Start from the defaults and merge, so a partial config is a patch rather
  // than a replacement.
  Config merged = config::Defaults();
  config::MergeInto(*loaded, merged);

  // MergeInto cannot shrink the matching step lists, so on its own it can never
  // disable an algorithm. Protobuf's MergeFrom appends to a repeated field, so
  // passing a shorter list yields defaults + additions; MergeInto's guard then
  // sees either a duplicate name or a differing count and restores the original
  // list wholesale. Either way the caller's selection is discarded.
  //
  // For a toggle API that is useless, so a supplied list is authoritative:
  // whatever the caller passes is exactly what runs, in that order. Omit the
  // field entirely to keep the defaults.
  if (loaded->function_matching_size() > 0) {
    *merged.mutable_function_matching() = loaded->function_matching();
  }
  if (loaded->basic_block_matching_size() > 0) {
    *merged.mutable_basic_block_matching() = loaded->basic_block_matching();
  }

  config::Proto() = merged;
  // The matching steps read their confidence from a snapshot of this, so it
  // has to be rebuilt or the new values would not be seen.
  config::RefreshMatchingStepConfidences();
}

}  // namespace security::bindiff
