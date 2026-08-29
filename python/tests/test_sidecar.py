"""Tests for the metadata sidecar: the producer, the file, and the matching.

The sidecar exists to give the engine signals BinExport does not carry. The
first one shipped is the set of imports a function calls, which is recoverable
from the export itself -- so unlike the prototype and frame features, it can be
measured against the checked-in ground truth without a disassembler, which is
what the end-to-end test at the bottom does.
"""

from __future__ import annotations

import os
import sqlite3

import pytest

from bindiff.metadata import (
    FEATURE_IMPORTS,
    METRIC_EXACT,
    METRIC_JACCARD,
    BinaryMetadata,
    Feature,
    FunctionMetadata,
    imports_feature,
    read_sidecar,
    sha256_of_file,
    sidecar_path_for,
    stable_key,
    write_sidecar,
)


class TestImportsFeature:
    def test_is_a_sorted_deduplicated_key_set(self):
        feature = imports_feature(["malloc", "free", "malloc"])
        assert feature.name == FEATURE_IMPORTS
        assert feature.metric == METRIC_JACCARD
        assert list(feature.key_set) == sorted(set(feature.key_set))
        assert len(feature.key_set) == 2

    def test_order_of_the_input_does_not_matter(self):
        """It is a set: two builds will not list their imports in one order."""
        assert (imports_feature(["a", "b", "c"]).key_set
                == imports_feature(["c", "a", "b"]).key_set)

    def test_keys_are_stable_across_processes(self):
        """Not Python's hash(), which is randomised per process -- sidecars
        produced by two runs would not agree and matching would fall apart."""
        assert stable_key("malloc") == stable_key("malloc")
        assert stable_key("malloc") != stable_key("free")
        assert 0 <= stable_key("malloc") < 2 ** 64

    def test_an_empty_import_set_is_allowed_but_empty(self):
        assert list(imports_feature([]).key_set) == []


class TestFeatureValidation:
    def test_jaccard_requires_a_key_set(self):
        with pytest.raises(ValueError, match="carries no set"):
            Feature(name="x/v1", metric=METRIC_JACCARD, key=1)

    def test_exactly_one_value_is_required(self):
        with pytest.raises(ValueError, match="exactly one"):
            Feature(name="x/v1", metric=METRIC_JACCARD, key=1, key_set=[1])
        with pytest.raises(ValueError, match="exactly one"):
            Feature(name="x/v1", metric=METRIC_JACCARD)

    def test_key_set_must_be_sorted_and_deduplicated(self):
        """The schema promises it so the C++ side can intersect linearly."""
        with pytest.raises(ValueError, match="sorted and deduplicated"):
            Feature(name="x/v1", metric=METRIC_JACCARD, key_set=[3, 1, 2])
        with pytest.raises(ValueError, match="sorted and deduplicated"):
            Feature(name="x/v1", metric=METRIC_JACCARD, key_set=[1, 1, 2])


class TestDescriptors:
    def test_counts_functions_per_feature(self):
        metadata = BinaryMetadata(functions=[
            FunctionMetadata(address=0x1000, features=[imports_feature(["a"])]),
            FunctionMetadata(address=0x2000, features=[imports_feature(["b"])]),
            FunctionMetadata(address=0x3000, features=[
                Feature(name="prototype/v1", metric=METRIC_EXACT, key=7)]),
        ])
        by_name = {d["name"]: d for d in metadata.descriptors()}
        assert by_name[FEATURE_IMPORTS]["count"] == 2
        assert by_name["prototype/v1"]["count"] == 1
        # Set sizes vary per function, so a set feature has no fixed dimension.
        assert by_name[FEATURE_IMPORTS]["dimension"] == 0


@pytest.mark.requires_extension
class TestSidecarFile:
    """The generated protobuf bindings are needed from here down."""

    def _export(self, tmp_path, content=b"not really a binexport"):
        path = tmp_path / "sample.BinExport"
        path.write_bytes(content)
        return path

    def test_round_trips_through_the_wire_format(self, tmp_path):
        export = self._export(tmp_path)
        original = BinaryMetadata(executable_id="deadbeef", functions=[
            FunctionMetadata(address=0x401000,
                             features=[imports_feature(["malloc", "free"])],
                             attributes={"imports": "free,malloc"}),
        ])
        write_sidecar(str(export), original)
        restored = read_sidecar(str(export))

        assert restored is not None
        assert restored.executable_id == "deadbeef"
        assert len(restored.functions) == 1
        function = restored.functions[0]
        assert function.address == 0x401000
        assert function.attributes["imports"] == "free,malloc"
        feature = function.feature(FEATURE_IMPORTS)
        assert feature is not None
        assert feature.metric == METRIC_JACCARD
        assert list(feature.key_set) == list(
            original.functions[0].features[0].key_set)

    def test_exact_keys_survive_too(self, tmp_path):
        export = self._export(tmp_path)
        write_sidecar(str(export), BinaryMetadata(functions=[
            FunctionMetadata(address=0x401000, features=[
                Feature(name="prototype/v1", metric=METRIC_EXACT, key=0xabcd)]),
        ]))
        feature = read_sidecar(str(export)).functions[0].feature("prototype/v1")
        assert feature.metric == METRIC_EXACT
        assert feature.key == 0xabcd

    def test_it_sits_beside_its_export(self, tmp_path):
        export = self._export(tmp_path)
        write_sidecar(str(export), BinaryMetadata())
        assert sidecar_path_for(str(export)).endswith(".BinExport.meta")
        assert os.path.isfile(sidecar_path_for(str(export)))

    def test_absent_is_not_an_error(self, tmp_path):
        assert read_sidecar(str(self._export(tmp_path))) is None

    def test_the_digest_is_recorded_not_trusted(self, tmp_path):
        """write_sidecar hashes the file itself, so a sidecar can never claim
        to describe an export it was not built from."""
        export = self._export(tmp_path)
        write_sidecar(str(export), BinaryMetadata(
            binexport_sha256="0" * 64))  # a lie, which must be overwritten
        assert read_sidecar(str(export)).binexport_sha256 == sha256_of_file(
            str(export))

    def test_a_sidecar_for_a_different_export_is_refused(self, tmp_path):
        """The failure this exists to prevent: metadata silently paired with
        the wrong binary produces confident, wrong matches."""
        export = self._export(tmp_path)
        write_sidecar(str(export), BinaryMetadata())
        export.write_bytes(b"a completely different export now")

        with pytest.raises(ValueError, match="different .BinExport"):
            read_sidecar(str(export))


@pytest.mark.requires_extension
class TestProducer:
    def test_reads_import_sets_from_a_real_export(self, insider_pair):
        from bindiff.metadata_binexport import build_sidecar

        primary, _secondary = insider_pair
        metadata = build_sidecar(str(primary))

        assert metadata.functions, "no function carried an import set"
        for function in metadata.functions:
            feature = function.feature(FEATURE_IMPORTS)
            assert feature is not None
            assert len(feature.key_set) >= 2, "min_imports not honoured"

    def test_the_threshold_is_respected(self, insider_pair):
        from bindiff.metadata_binexport import build_sidecar

        primary, _secondary = insider_pair
        few = build_sidecar(str(primary), min_imports=1)
        many = build_sidecar(str(primary), min_imports=8)
        assert len(few.functions) > len(many.functions)

    def test_an_export_with_no_imports_says_so(self, tmp_path, insider_pair):
        """A half-populated sidecar must be recognisable as such rather than
        looking like a binary with genuinely few features."""
        from bindiff.metadata_binexport import build_sidecar

        primary, _secondary = insider_pair
        metadata = build_sidecar(str(primary), min_imports=10_000)
        assert not metadata.functions
        assert metadata.warnings

    def test_rejects_a_file_that_is_not_a_binexport(self, tmp_path):
        from bindiff.metadata_binexport import build_sidecar

        junk = tmp_path / "junk.BinExport"
        junk.write_bytes(b"not a protobuf")
        with pytest.raises(ValueError):
            build_sidecar(str(junk))


@pytest.mark.requires_extension
@pytest.mark.e2e
class TestMatchingAgainstGroundTruth:
    """The measurement that decides whether the feature is worth shipping.

    Runs the same fixture pair twice -- once with the import step, once without
    -- and checks the result against the ground truth the C++ suite uses. Name
    matching is disabled throughout, because both fixtures carry full symbols
    and with the shipped defaults almost everything matches by name; the case
    the feature targets is the stripped one, where name matching has nothing.
    """

    @staticmethod
    def _steps(bindiff_module, with_feature):
        steps = [s for s in bindiff_module.get_default_config()
                 ["function_matching"] if "name hash" not in s["name"]]
        if not with_feature:
            steps = [s for s in steps if "feature imports" not in s["name"]]
        return steps

    @staticmethod
    def _prepare(tmp_path, primary, secondary, with_sidecars):
        """Symlinks the pair into tmp_path, optionally writing sidecars.

        Symlinked rather than copied so the sidecars land in a scratch
        directory instead of the checked-in fixtures, without duplicating a
        megabyte of export on every run.
        """
        from bindiff.metadata import write_sidecar
        from bindiff.metadata_binexport import build_sidecar

        local = []
        for source in (primary, secondary):
            link = tmp_path / source.name
            link.symlink_to(source)
            if with_sidecars:
                write_sidecar(str(link), build_sidecar(str(link)))
            local.append(link)
        return local

    @staticmethod
    def _matches(database):
        def unsigned(value):
            return value + (1 << 64) if value < 0 else value

        connection = sqlite3.connect(str(database))
        try:
            rows = connection.execute(
                "SELECT address1, address2 FROM function").fetchall()
        finally:
            connection.close()
        return {unsigned(a): unsigned(b) for a, b in rows}

    @pytest.fixture(autouse=True)
    def restore_config(self, bindiff_module):
        yield
        bindiff_module.reset_config()

    def test_the_feature_step_is_registered(self, bindiff_module):
        """It is created from the configuration rather than a hardcoded list,
        so its presence in the defaults is what makes it reachable at all."""
        names = [s["name"] for s in
                 bindiff_module.get_default_config()["function_matching"]]
        assert "function: feature imports/v1" in names

    def test_recall_improves_and_nothing_it_matched_is_wrong(
            self, bindiff_module, libssl_pair, ground_truth, tmp_path):
        primary, secondary, truth_path = libssl_pair
        truth = ground_truth(truth_path)
        assert len(truth) > 500, "ground truth looks truncated"

        baseline_dir = tmp_path / "baseline"
        baseline_dir.mkdir()
        base_primary, base_secondary = self._prepare(
            baseline_dir, primary, secondary, with_sidecars=False)
        bindiff_module.set_config(
            {"function_matching": self._steps(bindiff_module, False)})
        baseline_db = tmp_path / "baseline.BinDiff"
        assert bindiff_module.diff(str(base_primary), str(base_secondary),
                                   str(baseline_db)) == 0
        baseline = self._matches(baseline_db)

        feature_dir = tmp_path / "feature"
        feature_dir.mkdir()
        feat_primary, feat_secondary = self._prepare(
            feature_dir, primary, secondary, with_sidecars=True)
        bindiff_module.set_config(
            {"function_matching": self._steps(bindiff_module, True)})
        feature_db = tmp_path / "feature.BinDiff"
        assert bindiff_module.diff(str(feat_primary), str(feat_secondary),
                                   str(feature_db)) == 0
        feature = self._matches(feature_db)

        correct_before = sum(1 for a, b in truth.items()
                             if baseline.get(a) == b)
        correct_after = sum(1 for a, b in truth.items() if feature.get(a) == b)
        wrong_before = sum(1 for a, b in truth.items()
                           if a in baseline and baseline[a] != b)
        wrong_after = sum(1 for a, b in truth.items()
                          if a in feature and feature[a] != b)

        assert correct_after > correct_before, (
            f"the import feature recovered nothing: {correct_after} vs "
            f"{correct_before} of {len(truth)} known pairs")
        assert wrong_after < wrong_before, (
            f"wrong matches did not fall: {wrong_after} vs {wrong_before}")

    def test_every_match_the_step_itself_made_is_correct(
            self, bindiff_module, libssl_pair, ground_truth, tmp_path):
        """Separates the feature's own precision from its knock-on effects.

        Adding an early step reorders everything after it, so some previously
        lucky matches from the weakest heuristics are lost. That is a fair
        trade only if the step's own matches are actually right, which is what
        this asserts -- against the algorithm the engine recorded per match,
        not against the totals.
        """
        primary, secondary, truth_path = libssl_pair
        truth = ground_truth(truth_path)

        work = tmp_path / "attributed"
        work.mkdir()
        local_primary, local_secondary = self._prepare(
            work, primary, secondary, with_sidecars=True)
        bindiff_module.set_config(
            {"function_matching": self._steps(bindiff_module, True)})
        database = tmp_path / "attributed.BinDiff"
        assert bindiff_module.diff(str(local_primary), str(local_secondary),
                                   str(database)) == 0

        def unsigned(value):
            return value + (1 << 64) if value < 0 else value

        connection = sqlite3.connect(str(database))
        try:
            rows = connection.execute("""
                SELECT f.address1, f.address2
                FROM function AS f
                JOIN functionalgorithm AS a ON f.algorithm = a.id
                WHERE a.name = 'function: feature imports/v1'
            """).fetchall()
        finally:
            connection.close()

        attributed = {unsigned(a): unsigned(b) for a, b in rows}
        assert attributed, "the step matched nothing at all"

        covered = {a: b for a, b in attributed.items() if a in truth}
        assert covered, "none of its matches are covered by ground truth"
        wrong = {a: b for a, b in covered.items() if truth[a] != b}
        assert not wrong, (
            f"{len(wrong)} of {len(covered)} matches made by the import step "
            f"contradict ground truth")
