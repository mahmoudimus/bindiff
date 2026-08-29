"""Talking to the diffing service.

Two layers, because the plugin needs both:

* `BinDiffClient` is a plain blocking client over urllib. No third-party HTTP
  library: it runs inside IDA's interpreter, where every added dependency is a
  thing that has to be installed next to a commercial product.
* `AsyncBinDiffClient` runs those calls on a Qt thread and reports back through
  signals, so a diff of a large pair never blocks the UI. That was the original
  complaint about the C++ plugin -- it stalls the database while it works -- and
  a resident service does not help if the client waits on it synchronously.

The pattern for the async half is ida-taskr's: a QObject that owns a QThread,
work executed off the UI thread, results delivered by signal so the handler
runs back on the UI thread where IDA's API is safe to call.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8710


class ServiceError(RuntimeError):
    """The service was reached and said no."""


class ServiceUnavailable(RuntimeError):
    """The service could not be reached at all."""


@dataclass(frozen=True)
class Match:
    address_primary: int
    address_secondary: int
    name_primary: str
    name_secondary: str
    similarity: float
    confidence: float
    algorithm: str

    @classmethod
    def from_json(cls, payload: dict) -> "Match":
        return cls(
            address_primary=payload["address_primary"],
            address_secondary=payload["address_secondary"],
            name_primary=payload.get("name_primary", ""),
            name_secondary=payload.get("name_secondary", ""),
            similarity=payload.get("similarity", 0.0),
            confidence=payload.get("confidence", 0.0),
            algorithm=payload.get("algorithm", ""),
        )


@dataclass(frozen=True)
class DiffReply:
    primary_id: str
    secondary_id: str
    matches: List[Match]
    unmatched_primary: List[dict]
    unmatched_secondary: List[dict]
    similarity: float
    confidence: float
    database: str
    cached: bool
    elapsed_ms: int

    @classmethod
    def from_json(cls, payload: dict) -> "DiffReply":
        return cls(
            primary_id=payload["primary_id"],
            secondary_id=payload["secondary_id"],
            matches=[Match.from_json(m) for m in payload.get("matches", [])],
            unmatched_primary=payload.get("unmatched_primary", []),
            unmatched_secondary=payload.get("unmatched_secondary", []),
            similarity=payload.get("similarity", 0.0),
            confidence=payload.get("confidence", 0.0),
            database=payload.get("database", ""),
            cached=payload.get("cached", False),
            elapsed_ms=payload.get("elapsed_ms", 0),
        )


class BinDiffClient:
    """Blocking client. Safe to share between threads: it holds no state."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 timeout: float = 600.0):
        self.base_url = f"http://{host}:{port}"
        # Generous by default: a first diff of two large binaries is minutes,
        # and a client that gives up before the engine finishes turns a slow
        # answer into no answer plus wasted work.
        self.timeout = timeout

    # -- plumbing ---------------------------------------------------------

    def _request(self, method: str, path: str, body: Optional[bytes] = None,
                 content_type: str = "application/json") -> dict:
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body, method=method)
        if body is not None:
            request.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as reply:
                payload = json.loads(reply.read() or b"{}")
        except urllib.error.HTTPError as exc:
            # The service reports its own errors as JSON; prefer that message
            # over the status line, which says nothing useful.
            try:
                detail = json.loads(exc.read() or b"{}").get("error", "")
            except Exception:
                detail = ""
            raise ServiceError(detail or f"{exc.code} {exc.reason}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ServiceUnavailable(
                f"no diffing service at {self.base_url}: {exc}") from exc
        if not payload.get("ok", True):
            raise ServiceError(payload.get("error", "unknown error"))
        return payload

    # -- operations -------------------------------------------------------

    def health(self) -> dict:
        return self._request("GET", "/health")

    def is_running(self) -> bool:
        try:
            self.health()
            return True
        except (ServiceUnavailable, ServiceError):
            return False

    def upload(self, content: bytes) -> str:
        return self._request("POST", "/upload", content,
                             "application/octet-stream")["id"]

    def upload_file(self, path) -> str:
        """Uploads a .BinExport and returns its id.

        The id is the digest of the contents, so uploading the same export
        twice is free on the second attempt -- the service already has it.
        """
        return self.upload(Path(path).read_bytes())

    def functions(self, export_id: str) -> List[dict]:
        return self._request("GET", f"/functions/{export_id}")["functions"]

    def diff(self, primary_id: str, secondary_id: str,
             force: bool = False) -> DiffReply:
        body = json.dumps({"primary": primary_id, "secondary": secondary_id,
                           "force": force}).encode("utf-8")
        return DiffReply.from_json(self._request("POST", "/diff", body))

    def diff_files(self, primary, secondary, force: bool = False) -> DiffReply:
        """Uploads both exports if needed, then diffs them."""
        return self.diff(self.upload_file(primary), self.upload_file(secondary),
                         force=force)


def start_service(cache_dir=None, host: str = DEFAULT_HOST,
                  port: int = DEFAULT_PORT,
                  interpreter=None,
                  idle_timeout: float = 3600.0) -> subprocess.Popen:
    """Starts a service in the background and waits for it to answer.

    The interpreter matters: the service imports the Cython extension, which is
    built against one specific Python, so it has to be the same one running
    this code -- not whatever `python3` resolves to on PATH.

    `idle_timeout` defaults to an hour rather than forever, because a service
    started from here is a child of whatever started it: if that process is
    IDA and IDA exits, the service keeps running with its port bound and its
    cache open, and nothing ever reaps it. Pass 0 for a service meant to
    outlive its parent.
    """
    from bindiff.headless import find_python_interpreter

    if interpreter is None:
        interpreter = find_python_interpreter()

    command = [str(interpreter), "-m", "bindiff.server",
               "--host", host, "--port", str(port),
               "--idle-timeout", str(idle_timeout)]
    if cache_dir is not None:
        command += ["--cache-dir", str(cache_dir)]

    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    client = BinDiffClient(host, port, timeout=5.0)
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise ServiceUnavailable(
                f"service exited immediately: "
                f"{stderr.decode('utf-8', 'replace')[-2000:]}")
        if client.is_running():
            return process
        time.sleep(0.1)

    process.terminate()
    raise ServiceUnavailable(
        f"service did not answer on {host}:{port} within 30s")


# -- the asynchronous half ------------------------------------------------

def _loaded_qt_core():
    """The QtCore module already imported in this process, or None.

    Read out of sys.modules rather than imported. Importing a Qt binding inside
    a headless IDA process takes the interpreter down -- the process dies, no
    exception -- so the only safe question is whether something else has
    already imported one. See ida_env.qt_core_usable for the same hazard.
    """
    for name in ("PySide6.QtCore", "PyQt5.QtCore"):
        module = sys.modules.get(name)
        if module is not None:
            return module
    return None


def qt_already_loaded() -> bool:
    """True when a usable QtCore is already imported in this process."""
    return _loaded_qt_core() is not None


def _qt():
    """The loaded QtCore and its signal factory, or a refusal explaining why.

    Deliberately not the vendored qt_shim: that returns a stub with no signals
    outside the IDA GUI, and the async client is useful anywhere a binding
    happens to be loaded -- IDA 9.1's headless interpreter has PyQt5 imported,
    for instance. Deliberately not an import either, for the reason above.

    The signal factory is resolved rather than assumed because the two bindings
    spell it differently, and the binding module is left unmodified: adding an
    alias to PyQt5.QtCore would be a global change other plugins can see.
    """
    module = _loaded_qt_core()
    if module is None:
        raise RuntimeError(
            "no Qt binding is loaded in this process. The asynchronous client "
            "needs one already imported -- importing it here would kill a "
            "headless IDA. Use BinDiffClient on your own thread instead")

    signal = getattr(module, "Signal", None) or getattr(module, "pyqtSignal",
                                                        None)
    if signal is None:
        raise RuntimeError(
            f"{module.__name__} has neither Signal nor pyqtSignal; it is not a "
            f"Qt binding this client understands")
    return module, signal


def make_async_client(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                      timeout: float = 600.0):
    """Builds an asynchronous client bound to a Qt event loop.

    Defined inside a factory rather than at module scope because the class has
    to derive from QObject, and importing Qt at module scope would make this
    module unimportable in a headless worker -- which is exactly where the
    blocking client above is meant to be used.

    The returned object exposes:

        finished(object)  - a DiffReply
        failed(str)       - a message
        progress(str)     - a human-readable stage

        submit_diff(primary_path, secondary_path, force=False)
        shutdown()

    Work runs on a worker thread; the signals are delivered on the thread that
    owns the object, so a handler can touch IDA's API directly.
    """
    QtCore, Signal = _qt()

    class _Worker(QtCore.QObject):
        finished = Signal(object)
        failed = Signal(str)
        progress = Signal(str)

        def __init__(self, client):
            super().__init__()
            self._client = client

        def run_diff(self, primary: str, secondary: str, force: bool):
            try:
                self.progress.emit("uploading primary")
                primary_id = self._client.upload_file(primary)
                self.progress.emit("uploading secondary")
                secondary_id = self._client.upload_file(secondary)
                self.progress.emit("diffing")
                reply = self._client.diff(primary_id, secondary_id, force)
            except Exception as exc:
                self.failed.emit(str(exc))
                return
            self.progress.emit(
                "served from cache" if reply.cached else "diffed")
            self.finished.emit(reply)

    class AsyncBinDiffClient(QtCore.QObject):
        finished = Signal(object)
        failed = Signal(str)
        progress = Signal(str)

        _submit = Signal(str, str, bool)

        def __init__(self, parent=None):
            super().__init__(parent)
            self._client = BinDiffClient(host, port, timeout)
            self._thread = QtCore.QThread()
            self._worker = _Worker(self._client)
            self._worker.moveToThread(self._thread)

            # Queued across the thread boundary by Qt, which is what keeps the
            # blocking calls off the UI thread.
            self._submit.connect(self._worker.run_diff)
            self._worker.finished.connect(self.finished)
            self._worker.failed.connect(self.failed)
            self._worker.progress.connect(self.progress)
            self._thread.start()

        def submit_diff(self, primary, secondary, force: bool = False) -> None:
            self._submit.emit(str(primary), str(secondary), bool(force))

        def shutdown(self) -> None:
            """Stops the worker thread. Safe to call more than once."""
            if self._thread.isRunning():
                self._thread.quit()
                self._thread.wait(5000)

    return AsyncBinDiffClient
