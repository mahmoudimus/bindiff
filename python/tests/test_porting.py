"""Tests for symbol and comment porting.

The planning half is pure and is tested directly. The applying half takes an
injected writer, so its control flow is testable too -- only the two default
writers actually touch IDA.
"""

import pytest

from ida_plugin.porting import (
    CommentPort,
    SymbolPort,
    apply_comment_ports,
    apply_symbol_ports,
    plan_comment_ports,
    plan_symbol_ports,
)


class _Match:
    def __init__(self, id=1, name_primary="sub_401000",
                 name_secondary="encrypt", similarity=0.9, confidence=0.9,
                 address_primary=0x401000, address_secondary=0x501000):
        self.id = id
        self.name_primary = name_primary
        self.name_secondary = name_secondary
        self.similarity = similarity
        self.confidence = confidence
        self.address_primary = address_primary
        self.address_secondary = address_secondary


class TestSymbolPlanning:
    def test_ports_a_real_name_onto_a_generated_one(self):
        ports = plan_symbol_ports([_Match()])
        assert len(ports) == 1
        assert ports[0].new_name == "encrypt"
        assert ports[0].address == 0x401000

    @pytest.mark.parametrize("generated", [
        "sub_401000", "loc_401000", "nullsub_1", "unknown_libname_3",
        "j_sub_401000", "byte_4010A0", "off_401234", "",
    ])
    def test_generated_secondary_names_carry_nothing(self, generated):
        assert plan_symbol_ports([_Match(name_secondary=generated)]) == []

    def test_a_real_primary_name_is_not_clobbered(self):
        """Overwriting a name someone chose with another is a regression."""
        match = _Match(name_primary="my_analysis", name_secondary="encrypt")
        assert plan_symbol_ports([match]) == []
        assert len(plan_symbol_ports([match], overwrite_existing=True)) == 1

    def test_identical_names_are_not_rewritten(self):
        assert plan_symbol_ports(
            [_Match(name_primary="encrypt", name_secondary="encrypt")]) == []

    def test_thresholds_reject_weak_matches(self):
        weak = _Match(similarity=0.3, confidence=0.3)
        assert plan_symbol_ports([weak], min_similarity=0.5) == []
        assert plan_symbol_ports([weak], min_confidence=0.5) == []
        # And a caller can still ask for everything, deliberately.
        assert len(plan_symbol_ports([weak], min_similarity=0.0,
                                     min_confidence=0.0)) == 1

    def test_a_weak_match_is_refused_by_default(self):
        """This used to default to porting everything.

        Measured on nine pairs of real stripped programs, that copies 1440
        names of which 516 are wrong -- the weakest matching steps pair up
        whatever is left over, and the engine records exactly that in the
        similarity and confidence it stores. A wrong name written into the
        database does not look wrong afterwards; it looks like analysis
        somebody did.
        """
        from ida_plugin.porting import (DEFAULT_PORT_MIN_CONFIDENCE,
                                        DEFAULT_PORT_MIN_SIMILARITY)

        assert DEFAULT_PORT_MIN_SIMILARITY > 0.0
        assert DEFAULT_PORT_MIN_CONFIDENCE > 0.0

        just_below = _Match(similarity=DEFAULT_PORT_MIN_SIMILARITY - 0.01,
                            confidence=1.0)
        assert plan_symbol_ports([just_below]) == []

        low_confidence = _Match(similarity=1.0,
                                confidence=DEFAULT_PORT_MIN_CONFIDENCE - 0.01)
        assert plan_symbol_ports([low_confidence]) == []

        strong = _Match(similarity=1.0, confidence=1.0)
        assert len(plan_symbol_ports([strong])) == 1

    def test_the_old_name_is_recorded(self):
        """A preview, and any undo, needs to know what it replaced."""
        port = plan_symbol_ports([_Match()])[0]
        assert port.old_name == "sub_401000"


class _FakeDatabase:
    def __init__(self, matches, instruction_pairs):
        self._matches = matches
        self._pairs = instruction_pairs

    def matches(self):
        return self._matches

    def instruction_matches_for(self, match_ids=None):
        wanted = None if match_ids is None else set(match_ids)
        grouped = {}
        for match in self.matches():
            if wanted is None or match.id in wanted:
                grouped[match.id] = self.instruction_matches(match.id)
        return grouped

    def instruction_matches(self, match_id=None):
        return self._pairs.get(match_id, [])


class TestCommentPlanning:
    def test_places_comments_on_the_matched_instruction(self):
        db = _FakeDatabase(
            [_Match(id=7)],
            {7: [(0x401000, 0x501000), (0x401004, 0x501004)]})
        ports = plan_comment_ports(db, {0x501004: "the interesting one"})

        assert len(ports) == 1
        assert ports[0].address == 0x401004
        assert ports[0].secondary_address == 0x501004
        assert ports[0].text == "the interesting one"

    def test_addresses_without_a_comment_are_skipped(self):
        db = _FakeDatabase([_Match(id=1)], {1: [(0x401000, 0x501000)]})
        assert plan_comment_ports(db, {}) == []
        assert plan_comment_ports(db, {0x999: "elsewhere"}) == []

    def test_empty_comments_are_not_ported(self):
        db = _FakeDatabase([_Match(id=1)], {1: [(0x401000, 0x501000)]})
        assert plan_comment_ports(db, {0x501000: ""}) == []

    def test_can_be_limited_to_selected_matches(self):
        db = _FakeDatabase(
            [_Match(id=1), _Match(id=2)],
            {1: [(0x401000, 0x501000)], 2: [(0x402000, 0x502000)]})
        comments = {0x501000: "a", 0x502000: "b"}

        assert len(plan_comment_ports(db, comments)) == 2
        only_two = plan_comment_ports(db, comments, match_ids=[2])
        assert len(only_two) == 1 and only_two[0].address == 0x402000

    def test_thresholds_apply(self):
        db = _FakeDatabase([_Match(id=1, similarity=0.2)],
                           {1: [(0x401000, 0x501000)]})
        assert plan_comment_ports(db, {0x501000: "x"}, min_similarity=0.5) == []


class TestApplying:
    def test_counts_successes_and_failures(self):
        ports = [SymbolPort(0x1, "a", "sub_1", 1), SymbolPort(0x2, "b", "sub_2", 2)]
        result = apply_symbol_ports(ports, rename=lambda ea, name: ea == 0x1)

        assert result.applied == 1
        assert result.failed == 1
        assert result.attempted == 2

    def test_one_rejection_does_not_stop_the_rest(self):
        """A name collision partway through a few hundred renames should not
        abandon the remainder."""
        seen = []

        def rename(ea, name):
            seen.append(ea)
            if ea == 0x2:
                raise RuntimeError("name already in use")
            return True

        ports = [SymbolPort(ea, "n", "sub", i) for i, ea in enumerate((1, 2, 3))]
        result = apply_symbol_ports(ports, rename=rename)

        assert seen == [1, 2, 3]
        assert result.applied == 2 and result.failed == 1

    def test_comments_apply_the_same_way(self):
        ports = [CommentPort(0x1, "hello", 0x9, 1)]
        written = {}

        def set_comment(ea, text):
            written[ea] = text
            return True

        assert apply_comment_ports(ports, set_comment=set_comment).applied == 1
        assert written == {0x1: "hello"}

    def test_default_writers_refuse_outside_ida(self):
        """Headless, the defaults must raise rather than pretend to work."""
        result = apply_symbol_ports([SymbolPort(0x1, "a", "sub_1", 1)])
        assert result.failed == 1 and result.applied == 0


class TestExplainingSkips:
    """"renamed 9 function(s)" out of ten selected leaves one unaccounted for,
    and the usual reason is a deliberate refusal rather than a failure."""

    def _match(self, **kw):
        from types import SimpleNamespace
        fields = dict(id=1, similarity=1.0, confidence=1.0,
                      address_primary=0x1000, name_primary="sub_1000",
                      address_secondary=0x2000, name_secondary="real_name")
        fields.update(kw)
        return SimpleNamespace(**fields)

    def test_a_named_primary_is_reported_not_silently_dropped(self):
        from ida_plugin.porting import (explain_symbol_port_skips,
                                        plan_symbol_ports)
        matches = [self._match(name_primary="wiauDbgHelper2_1")]
        assert plan_symbol_ports(matches) == []
        assert explain_symbol_port_skips(matches) == {
            "already named here, and renaming would overwrite it": 1}

    def test_a_weak_match_is_reported(self):
        from ida_plugin.porting import explain_symbol_port_skips
        assert explain_symbol_port_skips([self._match(similarity=0.1)]) == {
            "below the similarity or confidence floor": 1}

    def test_nothing_to_give_is_reported(self):
        from ida_plugin.porting import explain_symbol_port_skips
        assert explain_symbol_port_skips(
            [self._match(name_secondary="sub_2000")]) == {
                "the match has no real name to give": 1}

    def test_a_portable_match_is_not_a_skip(self):
        from ida_plugin.porting import (explain_symbol_port_skips,
                                        plan_symbol_ports)
        matches = [self._match()]
        assert len(plan_symbol_ports(matches)) == 1
        assert explain_symbol_port_skips(matches) == {}

    def test_the_two_agree_on_the_total(self):
        """Every match is either ported or explained -- the property that makes
        the report trustworthy."""
        from ida_plugin.porting import (explain_symbol_port_skips,
                                        plan_symbol_ports)
        matches = [self._match(id=1),
                   self._match(id=2, name_primary="already_named"),
                   self._match(id=3, similarity=0.1),
                   self._match(id=4, name_secondary="sub_2000")]
        ported = len(plan_symbol_ports(matches))
        skipped = sum(explain_symbol_port_skips(matches).values())
        assert ported + skipped == len(matches)


class TestOverwriting:
    """Upstream's only guard is "already has the same name" (ida/results.cc),
    so an explicit import replaces a name that is already there."""

    def _match(self, **kw):
        from types import SimpleNamespace
        fields = dict(id=1, similarity=1.0, confidence=1.0,
                      address_primary=0x1000, name_primary="hand_written",
                      address_secondary=0x2000, name_secondary="from_the_match")
        fields.update(kw)
        return SimpleNamespace(**fields)

    def test_an_existing_name_is_replaced_when_asked(self):
        from ida_plugin.porting import plan_symbol_ports
        ports = plan_symbol_ports([self._match()], overwrite_existing=True)
        assert [(p.old_name, p.new_name) for p in ports] == [
            ("hand_written", "from_the_match")]

    def test_and_is_kept_when_not(self):
        from ida_plugin.porting import plan_symbol_ports
        assert plan_symbol_ports([self._match()]) == []

    def test_identical_names_are_still_not_ported(self):
        """Nothing to do, and it would report work that did not happen."""
        from ida_plugin.porting import plan_symbol_ports
        match = self._match(name_primary="same", name_secondary="same")
        assert plan_symbol_ports([match], overwrite_existing=True) == []

    def test_the_thresholds_still_apply(self):
        """Overwriting is about respecting a name; the floors are about
        trusting a match, and porting at 0.0 wrote 516 wrong names of 1440."""
        from ida_plugin.porting import plan_symbol_ports
        weak = self._match(similarity=0.1)
        assert plan_symbol_ports([weak], overwrite_existing=True) == []


class TestFunctionCommentsFollowTheFunction:
    """A function comment belongs to the function, not to its first
    instruction.

    Routed through matched instruction pairs it is lost whenever the entry
    instruction did not match -- a changed prologue means the first matched
    pair starts a few bytes in, and the comment sits on an address nothing
    points at. Reported by a user on opt_cmp64_valranges_jmp2, whose first
    matched pair began five bytes past the entry.
    """

    class _Database:
        """A .BinDiff with one match whose entry instruction did not match."""

        def __init__(self, pairs):
            self._pairs = pairs

        def matches(self):
            from types import SimpleNamespace
            return [SimpleNamespace(
                id=1, similarity=1.0, confidence=1.0,
                address_primary=0x1000, name_primary="sub_1000",
                address_secondary=0x2000, name_secondary="real")]

        def instruction_matches_for(self, match_ids=None):
            return {1: self._pairs}

        def instruction_matches(self, _match_id):
            return self._pairs

    def _comment(self, text, kind):
        from types import SimpleNamespace
        return SimpleNamespace(text=text, is_function_comment=kind == "function")

    def test_it_is_ported_when_the_entry_did_not_match(self):
        from ida_plugin.porting import plan_comment_ports
        database = self._Database([(0x1005, 0x2005)])
        comments = {0x2000: [self._comment("what it does", "function")]}
        ports = plan_comment_ports(database, comments)
        assert [(p.kind, p.address) for p in ports] == [("function", 0x1000)]

    def test_it_lands_on_the_function_not_the_matched_instruction(self):
        from ida_plugin.porting import plan_comment_ports
        database = self._Database([(0x1005, 0x2005)])
        comments = {0x2000: [self._comment("what it does", "function")],
                    0x2005: [self._comment("a note here", "instruction")]}
        ports = plan_comment_ports(database, comments)
        assert sorted((p.kind, p.address) for p in ports) == [
            ("function", 0x1000), ("instruction", 0x1005)]

    def test_it_is_not_ported_twice_when_the_entry_did_match(self):
        """The entry appearing in the instruction pairs must not plan the
        same comment again."""
        from ida_plugin.porting import plan_comment_ports
        database = self._Database([(0x1000, 0x2000), (0x1005, 0x2005)])
        comments = {0x2000: [self._comment("what it does", "function")]}
        ports = plan_comment_ports(database, comments)
        assert len(ports) == 1
        assert ports[0].kind == "function"


class TestRefusalsAreRecorded:
    """IDA's setters return False rather than raising, so a write the
    database refused has to be recorded or it is indistinguishable from a
    comment that was never planned. That distinction is the whole question
    when one comment goes missing from an import."""

    def _port(self, address, kind="instruction"):
        from ida_plugin.porting import CommentPort
        return CommentPort(address=address, text="note",
                           secondary_address=address, match_id=1, kind=kind)

    def test_a_refused_comment_names_its_address(self):
        from ida_plugin.porting import apply_comment_ports

        result = apply_comment_ports(
            [self._port(0x1000), self._port(0x2000)],
            set_comment=lambda address, text, kind: address != 0x2000)
        assert result.applied == 1
        assert result.failed == 1
        assert result.failed_addresses == [0x2000]

    def test_a_writer_that_raises_is_recorded_too(self):
        from ida_plugin.porting import apply_comment_ports

        def explode(address, text, kind):
            raise RuntimeError("no")

        result = apply_comment_ports([self._port(0x1000)], set_comment=explode)
        assert result.failed_addresses == [0x1000]

    def test_nothing_refused_leaves_the_list_empty(self):
        from ida_plugin.porting import apply_comment_ports

        result = apply_comment_ports(
            [self._port(0x1000)], set_comment=lambda *a: True)
        assert result.applied == 1
        assert result.failed_addresses == []


class TestAppliedMatchesAreAttributed:
    """Counts cannot say *which* matches took something, and that is what the
    result file has to record so the view can show it later."""

    def _symbol(self, match_id, address):
        from ida_plugin.porting import SymbolPort
        return SymbolPort(address=address, new_name="real",
                          old_name="sub_1000", match_id=match_id)

    def test_only_the_matches_that_were_written_are_recorded(self):
        from ida_plugin.porting import apply_symbol_ports

        result = apply_symbol_ports(
            [self._symbol(1, 0x1000), self._symbol(2, 0x2000)],
            rename=lambda address, name: address == 0x1000)
        assert result.applied_matches == {1}
        assert result.failed_addresses == [0x2000]

    def test_a_rename_that_raises_records_neither(self):
        from ida_plugin.porting import apply_symbol_ports

        def explode(address, name):
            raise RuntimeError("no")

        result = apply_symbol_ports([self._symbol(1, 0x1000)], rename=explode)
        assert result.applied_matches == set()
        assert result.failed_addresses == [0x1000]

    def test_comments_attribute_to_their_match_too(self):
        from ida_plugin.porting import CommentPort, apply_comment_ports

        ports = [CommentPort(address=0x1000, text="n", secondary_address=0x1,
                             match_id=7, kind="instruction")]
        result = apply_comment_ports(ports, set_comment=lambda *a: True)
        assert result.applied_matches == {7}
