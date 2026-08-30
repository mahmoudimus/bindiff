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

#include "third_party/zynamics/bindiff/sidecar.h"

#include <fstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/status_matchers.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/zynamics/bindiff/bindiff_metadata.pb.h"
#include "third_party/zynamics/bindiff/match/function_feature.h"

namespace security::bindiff {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::NotNull;

constexpr char kFeature[] = "imports/v1";

// Writes `metadata` to a temporary .BinExport's sidecar path and returns the
// .BinExport path it belongs to. The export itself is never read by the loader
// -- only its name is used to find the sidecar -- so it does not need to exist.
std::string WriteSidecar(const std::string& stem,
                         const BinaryMetadata& metadata) {
  const std::string binexport =
      absl::StrCat(::testing::TempDir(), "/", stem, ".BinExport");
  std::ofstream out(SidecarPathFor(binexport), std::ios::binary);
  // Checked rather than ignored: a failed write here would make every
  // assertion in the test meaningless, and protobuf marks this nodiscard.
  EXPECT_TRUE(metadata.SerializeToOstream(&out));
  return binexport;
}

TEST(JaccardSimilarityTest, IdenticalSetsAreOne) {
  EXPECT_THAT(JaccardSimilarity({1, 2, 3}, {1, 2, 3}), Eq(1.0));
}

TEST(JaccardSimilarityTest, DisjointSetsAreZero) {
  EXPECT_THAT(JaccardSimilarity({1, 2, 3}, {4, 5, 6}), Eq(0.0));
}

TEST(JaccardSimilarityTest, PartialOverlap) {
  // |{2,3}| / |{1,2,3,4}|
  EXPECT_THAT(JaccardSimilarity({1, 2, 3}, {2, 3, 4}), Eq(0.5));
}

TEST(JaccardSimilarityTest, EmptySetsAreNotSimilar) {
  // Two functions that call nothing are not thereby the same function. Left as
  // zero rather than the mathematically defensible 1.0 for the empty-empty
  // case, because treating them as identical would pair every leaf function in
  // a binary with every other.
  EXPECT_THAT(JaccardSimilarity({}, {}), Eq(0.0));
  EXPECT_THAT(JaccardSimilarity({1}, {}), Eq(0.0));
}

TEST(JaccardSimilarityTest, IsSymmetric) {
  EXPECT_THAT(JaccardSimilarity({1, 2, 3, 4}, {3, 4, 5}),
              Eq(JaccardSimilarity({3, 4, 5}, {1, 2, 3, 4})));
}

TEST(FeatureIndexTest, LooksUpByFeatureAndAddress) {
  FeatureIndex index;
  index.AddKeySet(kFeature, 0x401000, {10, 20, 30});

  const auto* keys = index.LookupKeySet(kFeature, 0x401000);
  ASSERT_THAT(keys, NotNull());
  EXPECT_THAT(*keys, testing::ElementsAre(10, 20, 30));

  EXPECT_THAT(index.LookupKeySet(kFeature, 0x402000), IsNull());
  EXPECT_THAT(index.LookupKeySet("other/v1", 0x401000), IsNull());
}

TEST(FeatureIndexTest, NormalisesUnsortedInput) {
  // The schema says sorted and deduplicated so the intersection can be linear.
  // A producer that forgot would otherwise cause silently wrong similarities
  // rather than an obvious failure.
  FeatureIndex index;
  index.AddKeySet(kFeature, 0x401000, {30, 10, 20, 10});

  const auto* keys = index.LookupKeySet(kFeature, 0x401000);
  ASSERT_THAT(keys, NotNull());
  EXPECT_THAT(*keys, testing::ElementsAre(10, 20, 30));
}

TEST(FeatureIndexTest, ReportsShapeAndCount) {
  FeatureIndex index;
  EXPECT_TRUE(index.empty());

  index.AddKeySet(kFeature, 0x401000, {1});
  index.AddKeySet(kFeature, 0x402000, {2});
  index.AddExactKey("prototype/v1", 0x401000, 0xabcd);

  EXPECT_FALSE(index.empty());
  EXPECT_THAT(index.Count(kFeature), Eq(2));
  EXPECT_THAT(index.Count("prototype/v1"), Eq(1));
  EXPECT_THAT(index.Count("absent/v1"), Eq(0));

  EXPECT_TRUE(index.HasKeySets(kFeature));
  EXPECT_FALSE(index.HasExactKeys(kFeature));
  EXPECT_TRUE(index.HasExactKeys("prototype/v1"));
  EXPECT_FALSE(index.HasKeySets("prototype/v1"));
}

TEST(LoadSidecarTest, AbsentSidecarIsNotAnError) {
  // The normal case: BinDiff behaves exactly as it does with no metadata.
  const std::string binexport =
      absl::StrCat(::testing::TempDir(), "/no-sidecar-here.BinExport");
  absl::StatusOr<FeatureIndex> index = LoadSidecar(binexport, "any-id");
  ASSERT_THAT(index.status(), IsOk());
  EXPECT_TRUE(index->empty());
}

TEST(LoadSidecarTest, ReadsKeySetsAndExactKeys) {
  BinaryMetadata metadata;
  metadata.set_executable_id("deadbeef");
  auto* function = metadata.add_functions();
  function->set_address(0x401000);
  auto* jaccard = function->add_features();
  jaccard->set_name(kFeature);
  jaccard->set_metric(FEATURE_METRIC_JACCARD);
  for (uint64_t key : {7, 8, 9}) {
    jaccard->mutable_key_set()->add_keys(key);
  }
  auto* exact = function->add_features();
  exact->set_name("prototype/v1");
  exact->set_metric(FEATURE_METRIC_EXACT);
  exact->set_key(0x1234);

  const std::string binexport = WriteSidecar("both-shapes", metadata);
  absl::StatusOr<FeatureIndex> index = LoadSidecar(binexport, "deadbeef");
  ASSERT_THAT(index.status(), IsOk());

  const auto* keys = index->LookupKeySet(kFeature, 0x401000);
  ASSERT_THAT(keys, NotNull());
  EXPECT_THAT(*keys, testing::ElementsAre(7, 8, 9));

  const auto* key = index->LookupExactKey("prototype/v1", 0x401000);
  ASSERT_THAT(key, NotNull());
  EXPECT_THAT(*key, Eq(0x1234));
}

TEST(LoadSidecarTest, RefusesASidecarForADifferentExecutable) {
  // The failure this exists to prevent: metadata silently paired with the
  // wrong binary produces confident, wrong matches, which is worse than having
  // no metadata at all.
  BinaryMetadata metadata;
  metadata.set_executable_id("aaaaaaaa");
  const std::string binexport = WriteSidecar("wrong-executable", metadata);

  EXPECT_THAT(LoadSidecar(binexport, "bbbbbbbb").status(), Not(IsOk()));
}

TEST(LoadSidecarTest, AcceptsWhenEitherSideHasNoId) {
  // An exporter that set no id leaves the weaker guarantee that the sidecar
  // was found at the expected path, which is still worth having.
  BinaryMetadata metadata;
  auto* function = metadata.add_functions();
  function->set_address(0x401000);
  auto* feature = function->add_features();
  feature->set_name(kFeature);
  feature->set_metric(FEATURE_METRIC_JACCARD);
  feature->mutable_key_set()->add_keys(1);

  const std::string binexport = WriteSidecar("no-id", metadata);
  EXPECT_THAT(LoadSidecar(binexport, "some-id").status(), IsOk());
  EXPECT_THAT(LoadSidecar(binexport, "").status(), IsOk());
}

TEST(LoadSidecarTest, SkipsMetricsNothingConsumes) {
  // Fuzzy hashes are still parsed and dropped: nothing compares them yet, and
  // keeping a value per function costs memory for no benefit.
  BinaryMetadata metadata;
  auto* function = metadata.add_functions();
  function->set_address(0x401000);
  auto* feature = function->add_features();
  feature->set_name("fuzzy/v1");
  feature->set_metric(FEATURE_METRIC_HAMMING);
  feature->set_packed("\x01\x02\x03\x04");

  const std::string binexport = WriteSidecar("unconsumed-metric", metadata);
  absl::StatusOr<FeatureIndex> index = LoadSidecar(binexport, "");
  ASSERT_THAT(index.status(), IsOk());
  EXPECT_TRUE(index->empty());
}

TEST(LoadSidecarTest, ReadsEmbeddingsAndNormalisesThem) {
  // The vector arrives with whatever magnitude the model produced; the index
  // stores it unit length so a comparison is a dot product and no consumer has
  // to remember to divide.
  BinaryMetadata metadata;
  auto* function = metadata.add_functions();
  function->set_address(0x401000);
  auto* feature = function->add_features();
  feature->set_name("asm2vec/v1");
  feature->set_metric(FEATURE_METRIC_COSINE);
  for (float value : {3.0f, 4.0f}) {  // norm 5
    feature->mutable_vector()->add_values(value);
  }

  const std::string binexport = WriteSidecar("embedding", metadata);
  absl::StatusOr<FeatureIndex> index = LoadSidecar(binexport, "");
  ASSERT_THAT(index.status(), IsOk());
  EXPECT_TRUE(index->HasVectors("asm2vec/v1"));
  EXPECT_THAT(index->Dimension("asm2vec/v1"), Eq(2));

  const auto* stored = index->LookupVector("asm2vec/v1", 0x401000);
  ASSERT_NE(stored, nullptr);
  EXPECT_NEAR((*stored)[0], 0.6f, 1e-6);
  EXPECT_NEAR((*stored)[1], 0.8f, 1e-6);
}

TEST(LoadSidecarTest, DropsAVectorThatCannotBeCompared) {
  // A width that disagrees with the feature's own, and a vector with no
  // direction. Both are dropped rather than failing the load: one bad function
  // should cost one candidate, not the whole sidecar.
  BinaryMetadata metadata;
  for (const auto& [address, values] :
       std::vector<std::pair<Address, std::vector<float>>>{
           {0x401000, {1.0f, 0.0f}},
           {0x402000, {1.0f, 0.0f, 0.0f}},  // wrong width
           {0x403000, {0.0f, 0.0f}},        // no direction
       }) {
    auto* function = metadata.add_functions();
    function->set_address(address);
    auto* feature = function->add_features();
    feature->set_name("asm2vec/v1");
    feature->set_metric(FEATURE_METRIC_COSINE);
    for (float value : values) {
      feature->mutable_vector()->add_values(value);
    }
  }

  const std::string binexport = WriteSidecar("bad-vectors", metadata);
  absl::StatusOr<FeatureIndex> index = LoadSidecar(binexport, "");
  ASSERT_THAT(index.status(), IsOk());
  EXPECT_THAT(index->Count("asm2vec/v1"), Eq(1));
  EXPECT_NE(index->LookupVector("asm2vec/v1", 0x401000), nullptr);
  EXPECT_EQ(index->LookupVector("asm2vec/v1", 0x402000), nullptr);
  EXPECT_EQ(index->LookupVector("asm2vec/v1", 0x403000), nullptr);
}

TEST(CosineSimilarityTest, MapsOntoTheSameScaleEveryThresholdUses) {
  FeatureIndex index;
  ASSERT_TRUE(index.AddVector("f", 0x1, {1.0f, 0.0f}));
  ASSERT_TRUE(index.AddVector("f", 0x2, {2.0f, 0.0f}));    // same direction
  ASSERT_TRUE(index.AddVector("f", 0x3, {0.0f, 1.0f}));    // orthogonal
  ASSERT_TRUE(index.AddVector("f", 0x4, {-1.0f, 0.0f}));   // opposed

  const auto& a = *index.LookupVector("f", 0x1);
  EXPECT_NEAR(CosineSimilarity(a, *index.LookupVector("f", 0x2)), 1.0, 1e-6);
  EXPECT_NEAR(CosineSimilarity(a, *index.LookupVector("f", 0x3)), 0.5, 1e-6);
  EXPECT_NEAR(CosineSimilarity(a, *index.LookupVector("f", 0x4)), 0.0, 1e-6);
}

TEST(CosineSimilarityTest, RefusesToComparePrefixesOfDifferentWidths) {
  // Comparing the overlap of two different embeddings would produce a
  // confident number about nothing.
  EXPECT_THAT(CosineSimilarity({1.0f, 0.0f}, {1.0f, 0.0f, 0.0f}), Eq(0.0));
  EXPECT_THAT(CosineSimilarity({}, {}), Eq(0.0));
}

TEST(LoadSidecarTest, RejectsAFileThatIsNotASidecar) {
  const std::string binexport =
      absl::StrCat(::testing::TempDir(), "/garbage.BinExport");
  {
    std::ofstream out(SidecarPathFor(binexport), std::ios::binary);
    out << "this is not a protobuf, not even slightly";
  }
  EXPECT_THAT(LoadSidecar(binexport, "").status(), Not(IsOk()));
}

TEST(SidecarPathTest, SitsBesideItsExport) {
  EXPECT_THAT(SidecarPathFor("/tmp/foo.BinExport"),
              Eq("/tmp/foo.BinExport.meta"));
}

TEST(MatchingStepFeatureTest, ConfigNameRoundTrips) {
  const std::string config_name =
      MatchingStepFeature::ConfigNameFor("imports/v1");
  EXPECT_THAT(config_name, Eq("function: feature imports/v1"));
  EXPECT_THAT(MatchingStepFeature::FeatureNameFrom(config_name),
              Eq("imports/v1"));
}

TEST(MatchingStepFeatureTest, IgnoresNamesThatAreNotFeatureSteps) {
  // Every other algorithm's configuration name must fall through to the
  // hardcoded registry rather than being read as a feature name.
  EXPECT_THAT(MatchingStepFeature::FeatureNameFrom("function: hash matching"),
              Eq(""));
  EXPECT_THAT(MatchingStepFeature::FeatureNameFrom(""), Eq(""));
}

TEST(MatchingStepFeatureTest, TakesItsNameFromTheFeature) {
  MatchingStepFeature step("prototype/v1");
  EXPECT_THAT(step.feature_name(), Eq("prototype/v1"));
  EXPECT_THAT(step.name(), Eq("function: feature prototype/v1"));
  EXPECT_THAT(step.display_name(), Eq("Function: Feature prototype/v1"));
}

}  // namespace
}  // namespace security::bindiff
