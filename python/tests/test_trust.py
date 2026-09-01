"""The Trust verdict is a plugin-side reading of three numbers the engine
records. These pin the class table and the thresholds so a change to either
is a deliberate edit with a failing test, not drift."""

import pytest

from ida_plugin.trust import (
    BLOCK_COVERAGE_CAVEAT, TRUST_RANK, AlgorithmClass, Trust,
    algorithm_class, assess, explain, found_by)


class TestAlgorithmClass:
    @pytest.mark.parametrize("name,expected", [
        ("function: manual", AlgorithmClass.MANUAL),
        ("function: hash matching", AlgorithmClass.EXACT),
        ("function: name hash matching", AlgorithmClass.EXACT),
        ("function: prime signature matching", AlgorithmClass.EXACT),
        ("function: feature imports/v1", AlgorithmClass.EXACT),
        ("function: feature prototype/v1", AlgorithmClass.EXACT),
        ("function: edges callgraph MD index", AlgorithmClass.STRUCTURAL),
        ("function: MD index matching (flowgraph MD index, top down)",
         AlgorithmClass.STRUCTURAL),
        ("function: call reference matching", AlgorithmClass.STRUCTURAL),
        ("function: loop count matching", AlgorithmClass.STRUCTURAL),
        ("function: call graph neighbour assignment",
         AlgorithmClass.STRUCTURAL),
        ("function: address sequence", AlgorithmClass.POSITIONAL),
        ("function: call sequence matching(exact)", AlgorithmClass.POSITIONAL),
        ("function: call sequence matching(topology)",
         AlgorithmClass.POSITIONAL),
        ("", AlgorithmClass.UNKNOWN),
        ("something else entirely", AlgorithmClass.UNKNOWN),
    ])
    def test_known_steps_are_classed(self, name, expected):
        assert algorithm_class(name) is expected


class TestAssess:
    def test_manual_is_strong_whatever_the_numbers(self):
        assert assess(0.1, 0.1, "function: manual") is Trust.STRONG

    def test_exact_steps_are_strong(self):
        assert assess(1.0, 1.0, "function: hash matching") is Trust.STRONG
        assert assess(0.6, 0.6, "function: prime signature matching") is Trust.STRONG

    def test_anything_below_half_similarity_is_weak(self):
        assert assess(0.49, 1.0, "function: hash matching") is Trust.WEAK
        assert assess(0.3, 0.9, "function: edges callgraph MD index") is Trust.WEAK

    def test_structural_needs_both_numbers_high_to_be_strong(self):
        structural = "function: edges callgraph MD index"
        assert assess(0.9, 0.9, structural) is Trust.STRONG
        assert assess(0.81, 0.9, structural) is Trust.CHECK
        assert assess(0.9, 0.7, structural) is Trust.CHECK

    def test_positional_steps_are_weak_unless_very_similar(self):
        assert assess(0.7, 0.9, "function: address sequence") is Trust.WEAK
        assert assess(0.9, 0.9, "function: address sequence") is Trust.CHECK

    def test_unknown_step_is_never_strong(self):
        assert assess(1.0, 1.0, "") is Trust.CHECK

    def test_rank_orders_weak_to_strong(self):
        assert TRUST_RANK["weak"] < TRUST_RANK["check"] < TRUST_RANK["strong"]


class TestExplain:
    def test_one_sentence_names_the_class(self):
        text = explain(Trust.CHECK, "function: edges callgraph MD index",
                       0.64, 0.91)
        assert text.endswith(".")
        assert "structural" in text.lower()

    def test_weak_says_what_to_do(self):
        text = explain(Trust.WEAK, "function: address sequence", 0.31, 0.5)
        assert "address order" in text or "position" in text.lower()


class TestFoundBy:
    @pytest.mark.parametrize("name,expected", [
        ("function: hash matching", "function hash"),
        ("function: edges callgraph MD index", "call-graph edges"),
        ("function: address sequence", "address order"),
        ("function: prime signature matching", "prime signature"),
        ("function: manual", "by hand"),
        ("function: feature imports/v1", "imports"),
    ])
    def test_known_names_read_plainly(self, name, expected):
        assert found_by(name) == expected

    def test_an_unknown_name_only_loses_its_prefix(self):
        assert found_by("function: brand new step") == "brand new step"
        assert found_by("") == ""

    def test_the_caveat_is_words_not_a_number(self):
        assert "Block coverage" in BLOCK_COVERAGE_CAVEAT
        assert "not" in BLOCK_COVERAGE_CAVEAT
