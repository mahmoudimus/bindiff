"""Tests for symbol and comment porting, and for the Java UI transport.

The planning half is pure and is tested directly. The applying half takes an
injected writer, so its control flow is testable too -- only the two default
writers actually touch IDA.
"""

import socket
import struct
import threading

import pytest

from bindiff.visual_diff import (
    VisualDiffRequest,
    encode_message,
    send_gui_message,
)
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
        assert len(plan_symbol_ports([weak])) == 1

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


class TestVisualDiffTransport:
    def test_message_is_the_format_the_ui_parses(self):
        xml = VisualDiffRequest(
            database="/tmp/a.BinDiff",
            primary_path="/tmp/a.BinExport", primary_address=0x401000,
            secondary_path="/tmp/b.BinExport", secondary_address=0x501000,
        ).to_xml()

        assert xml.startswith('<BinDiffMatch type="flow_graph">')
        assert '<Database path ="/tmp/a.BinDiff"/>' in xml
        assert 'address="4198400"' in xml, "addresses are sent in decimal"
        assert xml.endswith("</BinDiffMatch>")

    def test_call_graph_requests_say_so(self):
        xml = VisualDiffRequest("d", "p", 1, "s", 2, call_graph=True).to_xml()
        assert xml.startswith('<BinDiffMatch type="call_graph">')

    def test_paths_containing_quotes_stay_well_formed(self):
        """Interpolating a path with a quote in it produces XML the UI cannot
        parse, and it would fail silently."""
        import xml.etree.ElementTree as ET

        xml = VisualDiffRequest('/tmp/we"ird.BinDiff', "p", 1, "s", 2).to_xml()
        root = ET.fromstring(xml)
        # The engine emits `<Database path ="...">`. XML permits whitespace
        # between an attribute name and its "=", so the attribute is named
        # "path" -- the trailing space is not part of it.
        assert root.find("Database").get("path") == '/tmp/we"ird.BinDiff'

    def test_frame_is_a_native_order_length_prefix(self):
        """The C++ side writes the length by reinterpreting a uint32_t, so it
        is native order -- not network order."""
        framed = encode_message("hello")
        assert framed[:4] == struct.pack("=I", 5)
        assert framed[4:] == b"hello"

    def test_round_trips_to_a_listening_socket(self):
        received = []

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def accept():
            conn, _ = server.accept()
            with conn:
                header = conn.recv(4)
                length = struct.unpack("=I", header)[0]
                received.append(conn.recv(length).decode("utf-8"))

        thread = threading.Thread(target=accept)
        thread.start()
        try:
            send_gui_message("<BinDiffMatch/>", port=port)
        finally:
            thread.join(timeout=5)
            server.close()

        assert received == ["<BinDiffMatch/>"]

    def test_reports_a_missing_ui_clearly(self):
        # Port 1 is privileged and nothing listens there.
        with pytest.raises(ConnectionError, match="no BinDiff UI listening"):
            send_gui_message("<BinDiffMatch/>", port=1, timeout=1.0)
