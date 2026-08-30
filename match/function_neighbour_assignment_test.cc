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
#include <numeric>
#include <random>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace security::bindiff {
namespace {

using ::testing::ElementsAre;
using ::testing::Eq;

double TotalWeight(const std::vector<double>& weights, int rows, int columns,
                   const std::vector<int>& assignment) {
  double total = 0.0;
  for (int row = 0; row < rows; ++row) {
    if (assignment[row] >= 0) {
      total += weights[row * columns + assignment[row]];
    }
  }
  return total;
}

// Exhaustive best, for checking the solver against something that cannot be
// wrong in the same way it is.
//
// Permuting the columns and giving them to rows in order enumerates every
// injective row->column map only while there are at least as many columns as
// rows; otherwise it would always assign the *first* `columns` rows and never
// consider leaving an early row out. So the short side is made the row side
// first, exactly as the solver does.
double BruteForceBest(const std::vector<double>& weights, int rows,
                      int columns) {
  if (rows > columns) {
    std::vector<double> transposed(weights.size());
    for (int row = 0; row < rows; ++row) {
      for (int column = 0; column < columns; ++column) {
        transposed[column * rows + row] = weights[row * columns + column];
      }
    }
    return BruteForceBest(transposed, columns, rows);
  }

  std::vector<int> columns_permutation(columns);
  std::iota(columns_permutation.begin(), columns_permutation.end(), 0);
  double best = 0.0;
  do {
    double total = 0.0;
    for (int row = 0; row < rows; ++row) {
      total += weights[row * columns + columns_permutation[row]];
    }
    best = std::max(best, total);
  } while (std::next_permutation(columns_permutation.begin(),
                                 columns_permutation.end()));
  return best;
}

TEST(SolveAssignmentTest, PicksTheObviousPairing) {
  // Row 0 clearly wants column 1, row 1 clearly wants column 0.
  const std::vector<double> weights = {1.0, 9.0,
                                       8.0, 2.0};
  EXPECT_THAT(SolveAssignment(weights, 2, 2), ElementsAre(1, 0));
}

TEST(SolveAssignmentTest, GivesUpALocalBestForABetterTotal) {
  // This is the whole reason the step exists. Greedy takes (0,0) at 10,
  // leaving row 1 with 1 for a total of 11. The best total is 9 + 9 = 18.
  const std::vector<double> weights = {10.0, 9.0,
                                        9.0, 1.0};
  const std::vector<int> assignment = SolveAssignment(weights, 2, 2);
  EXPECT_THAT(TotalWeight(weights, 2, 2, assignment), Eq(18.0));
  EXPECT_THAT(assignment, ElementsAre(1, 0));
}

TEST(SolveAssignmentTest, LeavesRowsUnassignedWhenColumnsRunOut) {
  const std::vector<double> weights = {5.0,
                                       3.0,
                                       1.0};
  const std::vector<int> assignment = SolveAssignment(weights, 3, 1);
  EXPECT_THAT(std::count(assignment.begin(), assignment.end(), 0), Eq(1));
  EXPECT_THAT(std::count(assignment.begin(), assignment.end(), -1), Eq(2));
  // And it keeps the best of them.
  EXPECT_THAT(assignment[0], Eq(0));
}

TEST(SolveAssignmentTest, HandlesMoreColumnsThanRows) {
  const std::vector<double> weights = {1.0, 7.0, 2.0};
  EXPECT_THAT(SolveAssignment(weights, 1, 3), ElementsAre(1));
}

TEST(SolveAssignmentTest, EmptyInputIsNotAnError) {
  EXPECT_TRUE(SolveAssignment({}, 0, 0).empty());
  EXPECT_TRUE(SolveAssignment({}, 0, 4).empty());
  EXPECT_THAT(SolveAssignment({}, 3, 0), ElementsAre(-1, -1, -1));
}

TEST(SolveAssignmentTest, NeverPicksAColumnTwice) {
  std::mt19937 generator(20260829);
  std::uniform_real_distribution<double> uniform(0.0, 5.0);
  for (int trial = 0; trial < 50; ++trial) {
    const int rows = 1 + static_cast<int>(generator() % 6);
    const int columns = 1 + static_cast<int>(generator() % 6);
    std::vector<double> weights(rows * columns);
    for (double& weight : weights) {
      weight = uniform(generator);
    }
    const std::vector<int> assignment = SolveAssignment(weights, rows, columns);

    ASSERT_THAT(assignment.size(), Eq(static_cast<size_t>(rows)));
    std::vector<int> taken;
    for (int column : assignment) {
      ASSERT_LT(column, columns);
      if (column >= 0) {
        taken.push_back(column);
      }
    }
    std::sort(taken.begin(), taken.end());
    EXPECT_THAT(std::adjacent_find(taken.begin(), taken.end()),
                Eq(taken.end()))
        << "a column was assigned to two rows";
  }
}

TEST(SolveAssignmentTest, MatchesBruteForceOnSmallProblems) {
  // The property that actually matters: it finds the *optimum*, not merely a
  // valid assignment. A subtly wrong Hungarian still returns something
  // plausible, which is exactly how it would go unnoticed.
  std::mt19937 generator(981);
  std::uniform_real_distribution<double> uniform(0.0, 4.0);
  for (int trial = 0; trial < 60; ++trial) {
    const int rows = 1 + static_cast<int>(generator() % 5);
    const int columns = 1 + static_cast<int>(generator() % 5);
    std::vector<double> weights(rows * columns);
    for (double& weight : weights) {
      weight = uniform(generator);
    }

    const std::vector<int> assignment = SolveAssignment(weights, rows, columns);
    EXPECT_NEAR(TotalWeight(weights, rows, columns, assignment),
                BruteForceBest(weights, rows, columns), 1e-9)
        << "rows=" << rows << " columns=" << columns;
  }
}

TEST(SolveAssignmentTest, ZeroWeightsAreStillAValidAssignment) {
  // The dense matrix a component builds is mostly zero, because the candidate
  // graph is sparse. The solver may fill slots with them; the caller discards
  // any pair whose weight is not positive.
  const std::vector<double> weights = {0.0, 0.0,
                                       0.0, 3.0};
  const std::vector<int> assignment = SolveAssignment(weights, 2, 2);
  EXPECT_THAT(TotalWeight(weights, 2, 2, assignment), Eq(3.0));
}

}  // namespace
}  // namespace security::bindiff
