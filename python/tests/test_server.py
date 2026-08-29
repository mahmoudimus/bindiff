"""Tests for the resident diffing service and its client.

The service exists to avoid repeating work, so the test that matters most is
the one asserting a second request for the same pair does not re-run the engine
-- and that it says so, rather than quietly looking the same.
"""

from __future__ import annotations

import threading

import pytest

from bindiff.client import (
    BinDiffClient,
    DiffReply,
    Match,
    ServiceError,
    ServiceUnavailable,
)
from bindiff.server import (
    BinDiffService,
    IdleShutdown,
    ExportStore,
    UnknownExport,
    digest_of,
    make_server,
)


class TestExportStore:
    def test_the_id_is_the_digest_of_the_contents(self, tmp_path):
        store = ExportStore(tmp_path)
        content = b"pretend this is a BinExport"
        assert store.add(content) == digest_of(content)

    def test_uploading_the_same_bytes_twice_is_one_file(self, tmp_path):
        """Content addressing is what makes re-uploading free: the client can
        send an export it already sent without the service storing it twice."""
        store = ExportStore(tmp_path)
        first = store.add(b"same")
        second = store.add(b"same")
        assert first == second
        assert len(store.ids()) == 1

    def test_different_bytes_are_different_ids(self, tmp_path):
        store = ExportStore(tmp_path)
        assert store.add(b"one") != store.add(b"two")

    def test_an_unknown_id_is_reported_not_guessed(self, tmp_path):
        with pytest.raises(UnknownExport):
            ExportStore(tmp_path).get("0" * 64)

    def test_no_partial_file_is_left_visible(self, tmp_path):
        """The write goes to a temporary name and is renamed, so a concurrent
        reader never sees a half-written export."""
        store = ExportStore(tmp_path)
        store.add(b"content")
        assert not list(tmp_path.glob("*.partial"))
        assert len(list(tmp_path.glob("*.BinExport"))) == 1

    def test_reports_its_size(self, tmp_path):
        store = ExportStore(tmp_path)
        store.add(b"12345")
        assert store.total_bytes() == 5


class TestServiceBasics:
    def test_upload_rejects_nothing(self, tmp_path):
        service = BinDiffService(tmp_path)
        with pytest.raises(ValueError, match="empty"):
            service.upload(b"")

    def test_health_reports_the_cache(self, tmp_path):
        service = BinDiffService(tmp_path)
        service.upload(b"an export")
        health = service.health()
        assert health["ok"]
        assert health["exports"] == 1
        assert health["uploads"] == 1
        assert health["diffs_run"] == 0

    def test_the_result_path_is_ordered(self, tmp_path):
        """a-vs-b is not b-vs-a: the primary is the side names are ported to,
        so the two directions are different comparisons."""
        service = BinDiffService(tmp_path)
        forward = service.database_for("a" * 64, "b" * 64)
        backward = service.database_for("b" * 64, "a" * 64)
        assert forward != backward


@pytest.fixture
def running_service(tmp_path):
    """A real HTTP server on a port the OS picks, torn down afterwards.

    A short socket timeout so the truncated-body test does not spend the
    production 30 seconds proving the handler gives up.
    """
    service = BinDiffService(tmp_path / "cache")
    server = make_server(service, "127.0.0.1", 0, socket_timeout=2.0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield service, BinDiffClient("127.0.0.1", server.server_address[1],
                                     timeout=600.0)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class TestTransport:
    def test_health_round_trips(self, running_service):
        _service, client = running_service
        assert client.health()["ok"]
        assert client.is_running()

    def test_upload_returns_the_digest(self, running_service):
        _service, client = running_service
        content = b"not a real export, but bytes are bytes"
        assert client.upload(content) == digest_of(content)

    def test_a_large_body_survives_the_round_trip(self, running_service):
        """Uploads are raw bytes rather than base64 in JSON, which matters at
        the sizes a real export reaches."""
        _service, client = running_service
        content = bytes(range(256)) * 8192  # 2 MiB
        assert client.upload(content) == digest_of(content)

    def test_an_unknown_id_is_a_clean_error(self, running_service):
        _service, client = running_service
        with pytest.raises(ServiceError, match="unknown export"):
            client.functions("0" * 64)

    def test_a_diff_without_ids_is_rejected(self, running_service):
        _service, client = running_service
        with pytest.raises(ServiceError):
            client.diff("", "")

    def test_an_unknown_route_is_not_a_crash(self, running_service):
        _service, client = running_service
        with pytest.raises(ServiceError, match="no such route"):
            client._request("GET", "/nope")

    def test_a_client_that_lies_about_its_length_does_not_leak_a_thread(
            self, running_service):
        """A handler blocked forever on rfile.read is a thread leak.

        The server keeps answering other connections, so the symptom is a slow
        leak rather than an outage -- which is exactly why it needs a test
        instead of being noticed in production.
        """
        import socket

        _service, client = running_service
        port = int(client.base_url.rsplit(":", 1)[1])

        connection = socket.create_connection(("127.0.0.1", port))
        try:
            connection.sendall(
                b"POST /upload HTTP/1.1\r\nHost: x\r\n"
                b"Content-Length: 1048576\r\n\r\n0123456789")
            # Comfortably longer than the fixture's 2s handler timeout.
            connection.settimeout(30)
            try:
                data = connection.recv(100)
            except socket.timeout:
                pytest.fail("the handler never gave up on a truncated body")
            # Either an error response or a closed connection is fine; hanging
            # is not.
            assert data == b"" or data.startswith(b"HTTP/1.")
        finally:
            connection.close()

        assert client.health()["ok"], "the server stopped answering"

    def test_no_service_is_distinguishable_from_a_failing_one(self):
        """A client that cannot tell "nothing is listening" from "the service
        said no" cannot give a useful message."""
        client = BinDiffClient("127.0.0.1", 1, timeout=1.0)
        assert not client.is_running()
        with pytest.raises(ServiceUnavailable):
            client.health()


@pytest.mark.requires_extension
@pytest.mark.e2e
class TestAgainstTheRealEngine:
    def test_diffs_a_real_pair_and_caches_it(self, running_service,
                                             insider_pair):
        """The reason the service exists.

        The first request runs the engine; the second must not, and must say
        so. Asserting the flag rather than only the timing: a cache that is
        merely fast is indistinguishable from a fast diff, and the flag is what
        a caller can act on.
        """
        service, client = running_service
        primary, secondary = insider_pair

        first = client.diff_files(str(primary), str(secondary))
        assert isinstance(first, DiffReply)
        assert first.matches, "the engine found nothing"
        assert not first.cached
        assert service.health()["diffs_run"] == 1

        second = client.diff_files(str(primary), str(secondary))
        assert second.cached
        assert service.health()["diffs_run"] == 1, "the engine ran twice"
        assert service.health()["diffs_served_from_cache"] == 1
        assert len(second.matches) == len(first.matches)

    def test_force_re_runs_the_engine(self, running_service, insider_pair):
        service, client = running_service
        primary, secondary = insider_pair
        primary_id = client.upload_file(str(primary))
        secondary_id = client.upload_file(str(secondary))

        client.diff(primary_id, secondary_id)
        assert service.health()["diffs_run"] == 1
        again = client.diff(primary_id, secondary_id, force=True)
        assert not again.cached
        assert service.health()["diffs_run"] == 2

    def test_the_reply_carries_what_a_caller_needs(self, running_service,
                                                   insider_pair):
        _service, client = running_service
        primary, secondary = insider_pair
        reply = client.diff_files(str(primary), str(secondary))

        assert reply.database.endswith(".BinDiff")
        assert 0.0 <= reply.similarity <= 1.0
        assert 0.0 <= reply.confidence <= 1.0
        match = reply.matches[0]
        assert isinstance(match, Match)
        assert match.address_primary > 0 and match.address_secondary > 0
        assert match.algorithm, "a match with no algorithm is unexplainable"

    def test_unmatched_functions_are_reported(self, running_service,
                                              insider_pair):
        """A .BinDiff stores matches only, so anything about what was *not*
        matched has to be recovered from the exports -- which the service is
        holding anyway."""
        _service, client = running_service
        primary, secondary = insider_pair
        reply = client.diff_files(str(primary), str(secondary))

        matched = {m.address_primary for m in reply.matches}
        unmatched = {f["address"] for f in reply.unmatched_primary}
        assert not (matched & unmatched), "a function is both matched and not"

    def test_functions_lists_an_uploaded_export(self, running_service,
                                                insider_pair):
        _service, client = running_service
        primary, _secondary = insider_pair
        functions = client.functions(client.upload_file(str(primary)))
        assert len(functions) > 200
        assert all("address" in f and "name" in f for f in functions)

    def test_concurrent_requests_for_one_pair_run_the_engine_once(
            self, running_service, insider_pair):
        """Two clients asking for the same new pair at the same time should
        cost one diff, not two -- otherwise the busiest case is the one the
        cache does not help."""
        service, client = running_service
        primary, secondary = insider_pair
        primary_id = client.upload_file(str(primary))
        secondary_id = client.upload_file(str(secondary))

        replies = []
        errors = []

        def request():
            try:
                replies.append(client.diff(primary_id, secondary_id))
            except Exception as exc:  # recorded, not swallowed
                errors.append(exc)

        threads = [threading.Thread(target=request) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=600)

        assert not errors, f"concurrent requests failed: {errors}"
        assert len(replies) == 4
        assert service.health()["diffs_run"] == 1, (
            f"the engine ran {service.health()['diffs_run']} times for one pair")
        assert len({len(r.matches) for r in replies}) == 1, (
            "concurrent replies disagree about the match count")


@pytest.mark.requires_extension
def test_a_failed_diff_leaves_no_cache_entry(tmp_path, insider_pair):
    """A partial or failed result must not be served as a hit next time."""
    service = BinDiffService(tmp_path)
    primary, _secondary = insider_pair
    good = service.upload(primary.read_bytes())
    junk = service.upload(b"this is not a BinExport at all")

    with pytest.raises(RuntimeError, match="diff failed"):
        service.diff(good, junk)

    assert not service.database_for(good, junk).is_file()
    assert service.health()["diffs_run"] == 0


class TestAsyncClient:
    """The Qt half: calls must not block the thread that submits them.

    QtCore only -- threads and signals work headlessly, QtWidgets does not, and
    requiring the GUI here would make the async path untestable in CI.
    """

    @staticmethod
    def _qt_or_skip():
        """Skips unless a Qt binding is *already* loaded.

        Not "is Qt installed": importing a binding inside a headless IDA
        process kills the interpreter, so a test that imported one to check
        would take the whole run down. IDA 9.1's headless interpreter happens
        to have PyQt5 loaded and 9.4's does not, so this runs on one leg and
        skips on the other -- which is why the client reads the loaded binding
        directly instead of going through the shim, whose stub has no signals
        outside the GUI.
        """
        from bindiff.client import _loaded_qt_core

        module = _loaded_qt_core()
        if module is None:
            pytest.skip("no Qt binding loaded in this process")
        return module

    def test_it_refuses_to_pretend_without_qt(self, monkeypatch):
        """Without a loaded binding there is no async client, and saying so
        beats handing back something that silently blocks -- or importing a
        binding and killing the process to find out."""
        import bindiff.client as client_module

        # Patches the function _qt actually calls. Patching the public
        # predicate instead silently does nothing, which is how this test
        # passed on one leg and failed on the other after a refactor.
        monkeypatch.setattr(client_module, "_loaded_qt_core", lambda: None)
        with pytest.raises(RuntimeError, match="no Qt binding is loaded"):
            client_module.make_async_client()

    def test_it_never_imports_a_binding_to_decide(self):
        """The check has to be sys.modules, not find_spec and certainly not an
        import: importing Qt headlessly inside IDA takes the interpreter down,
        so a probe would be fatal rather than informative."""
        import sys

        import bindiff.client as client_module

        before = set(sys.modules)
        client_module.qt_already_loaded()
        client_module._loaded_qt_core()
        assert not {m for m in set(sys.modules) - before
                    if m.startswith(("PySide", "PyQt"))}

    def _run_until(self, QtCore, client, timeout_ms=600000):
        """Spins an event loop until the client reports one way or the other."""
        application = (QtCore.QCoreApplication.instance()
                       or QtCore.QCoreApplication([]))
        outcome = {}
        loop = QtCore.QEventLoop()

        client.finished.connect(lambda reply: (outcome.update(reply=reply),
                                               loop.quit()))
        client.failed.connect(lambda message: (outcome.update(error=message),
                                               loop.quit()))
        timer = QtCore.QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        timer.start(timeout_ms)
        loop.exec() if hasattr(loop, "exec") else loop.exec_()
        del application  # keep the reference alive for the loop's lifetime
        return outcome

    @pytest.mark.requires_extension
    @pytest.mark.e2e
    def test_a_diff_completes_off_the_calling_thread(self, running_service,
                                                     insider_pair):
        QtCore = self._qt_or_skip()
        service, client = running_service
        primary, secondary = insider_pair

        from bindiff.client import make_async_client

        host, port = "127.0.0.1", int(client.base_url.rsplit(":", 1)[1])
        AsyncClient = make_async_client(host, port)
        async_client = AsyncClient()
        try:
            stages = []
            async_client.progress.connect(stages.append)
            async_client.submit_diff(str(primary), str(secondary))
            outcome = self._run_until(QtCore, async_client)

            assert "error" not in outcome, outcome.get("error")
            assert "reply" in outcome, "neither signal fired within the timeout"
            assert outcome["reply"].matches
            assert "diffing" in stages, f"no progress reported: {stages}"
        finally:
            async_client.shutdown()

    def test_a_failure_arrives_as_a_signal_not_an_exception(self):
        """A worker that raises into the Qt thread takes the UI with it; the
        contract is that every outcome comes back as a signal."""
        QtCore = self._qt_or_skip()  # noqa: F841 - guards the whole test
        from bindiff.client import make_async_client

        # Port 1 is not going to answer.
        AsyncClient = make_async_client("127.0.0.1", 1)
        async_client = AsyncClient()
        try:
            async_client.submit_diff("/nonexistent/a.BinExport",
                                     "/nonexistent/b.BinExport")
            outcome = self._run_until(QtCore, async_client, timeout_ms=30000)
            assert "error" in outcome, "a doomed request reported success"
            assert "reply" not in outcome
        finally:
            async_client.shutdown()

    def test_shutdown_is_idempotent(self):
        self._qt_or_skip()
        from bindiff.client import make_async_client

        async_client = make_async_client()()
        async_client.shutdown()
        async_client.shutdown()


class TestIdleShutdown:
    """The watchdog, on its own -- no HTTP, no IDA, no waiting."""

    def test_zero_means_never(self):
        """A manually started service should stay up."""
        watchdog = IdleShutdown(ttl=0)
        watchdog._last_request = 0.0  # ancient
        assert not watchdog.should_stop()

    def test_it_stops_once_idle_past_the_ttl(self):
        import time

        watchdog = IdleShutdown(ttl=0.05)
        assert not watchdog.should_stop()
        time.sleep(0.1)
        assert watchdog.should_stop()

    def test_a_request_resets_the_clock(self):
        import time

        watchdog = IdleShutdown(ttl=0.05)
        time.sleep(0.1)
        assert watchdog.should_stop()
        watchdog.touch()
        assert not watchdog.should_stop()

    def test_a_long_call_is_not_idle(self):
        """The subtlety worth having a test for.

        Requests touch the timer when they *arrive*, so a diff running longer
        than the ttl looks idle by the naive measure and would be shut down
        mid-work. Large binaries take minutes, so this is not hypothetical.
        """
        import time

        watchdog = IdleShutdown(ttl=0.05)
        watchdog.set_busy_probe(lambda: True)
        time.sleep(0.1)
        assert not watchdog.should_stop(), "shut down during a running call"

        watchdog.set_busy_probe(lambda: False)
        assert watchdog.should_stop()

    def test_it_fires_the_handler_once(self):
        import time

        watchdog = IdleShutdown(ttl=0.05, poll_interval=0.02)
        fired = []
        watchdog.start(lambda: fired.append(True))
        try:
            deadline = time.monotonic() + 5
            while not fired and time.monotonic() < deadline:
                time.sleep(0.02)
            assert fired, "the watchdog never fired"
            time.sleep(0.1)
            assert len(fired) == 1, "the watchdog fired more than once"
        finally:
            watchdog.stop()

    def test_the_server_exposes_its_watchdog_for_teardown(self, tmp_path):
        """make_server attaches it so a caller can stop it; without that the
        thread keeps polling a server that has been closed."""
        service = BinDiffService(tmp_path)
        server = make_server(service, "127.0.0.1", 0, idle_timeout=60.0)
        try:
            assert getattr(server, "bindiff_watchdog", None) is not None
        finally:
            server.bindiff_watchdog.stop()
            server.server_close()

    def test_no_watchdog_when_the_timeout_is_off(self, tmp_path):
        service = BinDiffService(tmp_path)
        server = make_server(service, "127.0.0.1", 0)
        try:
            assert getattr(server, "bindiff_watchdog", None) is None
        finally:
            server.server_close()

    def test_stop_is_idempotent(self):
        watchdog = IdleShutdown(ttl=0.05)
        watchdog.start(lambda: None)
        watchdog.stop()
        watchdog.stop()


@pytest.mark.requires_extension
def test_the_service_reports_itself_busy_during_a_diff(tmp_path, insider_pair):
    """The busy probe has to be true while the engine is running, or the
    watchdog would kill a long diff."""
    import threading

    service = BinDiffService(tmp_path)
    primary, secondary = insider_pair
    primary_id = service.upload(primary.read_bytes())
    secondary_id = service.upload(secondary.read_bytes())

    assert not service.busy()
    seen = []
    done = threading.Event()

    def watch():
        while not done.is_set():
            if service.busy():
                seen.append(True)
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    service.diff(primary_id, secondary_id)
    done.set()
    watcher.join(timeout=5)

    assert seen, "the service never reported itself busy while diffing"
    assert not service.busy(), "still busy after the diff returned"
