"""A resident diffing service, backed by the real engine.

The point is speed, and the speed does not come from faster matching -- it comes
from not repeating work. Diffing a pair costs a parse of both .BinExport files
plus the match itself, and an analyst comparing two binaries asks for the same
pair over and over: reopening the results, re-running after a rename, comparing
against a third build. A resident process that keeps parsed inputs and finished
results answers the second request in the time it takes to read a SQLite file.

The interface is BinDiff-Server's (github, GSoC 2025): upload two exports, get
ids back, ask for a diff of two ids. That project's own matchers are a
reimplementation its commit log measures at ~93% of real BinDiff, so only the
*interface* is taken here; the matching is this repository's engine, through the
Cython bindings.

Transport is stdlib HTTP with JSON bodies, and raw bytes for uploads. No gRPC:
the extension already pins the service to an interpreter with a matching build,
and adding a large binary wheel on top of that -- inside IDA's Python -- buys
nothing when the client is usually on the same machine. The message shapes
mirror the proto, so a gRPC servicer over BinDiffService would be a thin
adapter.

Run it:

    python -m bindiff.server --port 8710 --cache-dir ~/.cache/bindiff-server
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Tuple

logger = logging.getLogger("bindiff.server")

# A .BinExport of a large binary is tens of megabytes. Uploads above this are
# refused rather than buffered: the limit exists so a malformed or hostile
# request cannot exhaust memory, not because bigger inputs are impossible.
MAX_UPLOAD_BYTES = 512 * 1024 * 1024


def digest_of(content: bytes) -> str:
    """The id of an export: the SHA-256 of its bytes.

    The same key the metadata sidecar records, so a cached diff and a sidecar
    are addressable by one id.
    """
    return hashlib.sha256(content).hexdigest()


@dataclass(frozen=True)
class FunctionInfo:
    address: int
    name: str

    def to_json(self) -> dict:
        return {"address": self.address, "name": self.name}


@dataclass
class DiffResult:
    """One completed comparison, as the service reports it."""

    primary_id: str
    secondary_id: str
    matches: List[dict] = field(default_factory=list)
    unmatched_primary: List[FunctionInfo] = field(default_factory=list)
    unmatched_secondary: List[FunctionInfo] = field(default_factory=list)
    similarity: float = 0.0
    confidence: float = 0.0
    #: Path to the .BinDiff, so a caller that wants the full result can open it
    #: rather than receive every basic block over the wire.
    database: str = ""
    #: False when the engine actually ran, True when this came from the cache.
    #: Reported because it is the whole reason the service exists.
    cached: bool = False
    elapsed_ms: int = 0

    def to_json(self) -> dict:
        return {
            "primary_id": self.primary_id,
            "secondary_id": self.secondary_id,
            "matches": self.matches,
            "unmatched_primary": [f.to_json() for f in self.unmatched_primary],
            "unmatched_secondary": [f.to_json() for f in self.unmatched_secondary],
            "similarity": self.similarity,
            "confidence": self.confidence,
            "database": self.database,
            "cached": self.cached,
            "elapsed_ms": self.elapsed_ms,
        }


class UnknownExport(KeyError):
    """Raised when an id was never uploaded, or has been evicted."""


class ExportStore:
    """Content-addressed .BinExport files on disk.

    On disk rather than in memory for two reasons: the engine takes paths, so
    an in-memory copy would have to be written out for every diff anyway, and
    holding several tens of megabytes per binary does not survive a working
    session with a handful of versions open.
    """

    def __init__(self, directory: Path):
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def path_for(self, export_id: str) -> Path:
        return self._directory / f"{export_id}.BinExport"

    def add(self, content: bytes) -> str:
        """Stores `content` and returns its id. Idempotent."""
        export_id = digest_of(content)
        destination = self.path_for(export_id)
        with self._lock:
            if not destination.is_file():
                # Written to a temporary name and renamed, so a reader can
                # never observe a half-written export: rename is atomic within
                # a directory, a write is not.
                temporary = destination.with_suffix(".partial")
                temporary.write_bytes(content)
                os.replace(temporary, destination)
        return export_id

    def get(self, export_id: str) -> Path:
        path = self.path_for(export_id)
        if not path.is_file():
            raise UnknownExport(export_id)
        return path

    def contains(self, export_id: str) -> bool:
        return self.path_for(export_id).is_file()

    def ids(self) -> List[str]:
        return sorted(p.stem for p in self._directory.glob("*.BinExport"))

    def total_bytes(self) -> int:
        return sum(p.stat().st_size
                   for p in self._directory.glob("*.BinExport"))


class BinDiffService:
    """The service, independent of how requests arrive.

    Every method is safe to call from several threads. Diffing holds a lock per
    *pair* rather than one global lock, so unrelated comparisons proceed
    together -- the engine releases the GIL for the duration of a diff, so that
    is real parallelism -- while two requests for the same pair collapse into
    one run instead of racing to write the same file.
    """

    def __init__(self, cache_dir: Path, engine=None):
        self._cache_dir = Path(cache_dir)
        self.exports = ExportStore(self._cache_dir / "exports")
        self._results_dir = self._cache_dir / "results"
        self._results_dir.mkdir(parents=True, exist_ok=True)

        # Injected so the service can be tested without the compiled
        # extension; None means "import bindiff and use the real engine".
        self._engine = engine

        self._pair_locks: Dict[Tuple[str, str], threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._stats = {"diffs_run": 0, "diffs_served_from_cache": 0,
                       "uploads": 0}

    # -- engine access ----------------------------------------------------

    def _bindiff(self):
        if self._engine is not None:
            return self._engine
        import bindiff

        return bindiff

    def _lock_for(self, pair: Tuple[str, str]) -> threading.Lock:
        with self._locks_guard:
            return self._pair_locks.setdefault(pair, threading.Lock())

    # -- operations -------------------------------------------------------

    def upload(self, content: bytes) -> str:
        """Stores an export and returns its id."""
        if not content:
            raise ValueError("empty upload")
        export_id = self.exports.add(content)
        self._stats["uploads"] += 1
        return export_id

    def functions(self, export_id: str) -> List[FunctionInfo]:
        """Every function in an export, matched or not."""
        from bindiff.binexport import read_functions

        path = self.exports.get(export_id)
        return [FunctionInfo(address=f.address, name=f.best_name)
                for f in read_functions(str(path))]

    def database_for(self, primary_id: str, secondary_id: str) -> Path:
        # Ordered: diffing is not symmetric, and the primary is the side whose
        # names and comments get ported, so a-vs-b is not b-vs-a.
        return self._results_dir / f"{primary_id[:16]}_vs_{secondary_id[:16]}.BinDiff"

    def diff(self, primary_id: str, secondary_id: str,
             force: bool = False) -> DiffResult:
        """Compares two uploaded exports, reusing a previous result if there is
        one. `force` re-runs even when a cached result exists, which is what a
        configuration change needs."""
        primary = self.exports.get(primary_id)
        secondary = self.exports.get(secondary_id)
        database = self.database_for(primary_id, secondary_id)

        started = time.monotonic()
        with self._lock_for((primary_id, secondary_id)):
            cached = database.is_file() and not force
            if not cached:
                bindiff = self._bindiff()
                code = bindiff.diff(str(primary), str(secondary), str(database))
                if code != 0:
                    # Never leave a partial result behind to be served as a
                    # cache hit on the next request.
                    database.unlink(missing_ok=True)
                    raise RuntimeError(
                        f"diff failed with code {code} for "
                        f"{primary_id[:16]} vs {secondary_id[:16]}")
                self._stats["diffs_run"] += 1
            else:
                self._stats["diffs_served_from_cache"] += 1

        result = self._read_result(primary_id, secondary_id, database)
        result.cached = cached
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result

    def _read_result(self, primary_id: str, secondary_id: str,
                     database: Path) -> DiffResult:
        from bindiff.binexport import read_functions
        from bindiff.database import BinDiffDatabase

        with BinDiffDatabase.open(str(database)) as db:
            matches = db.matches()
            metadata = db.metadata()

        matched_primary = {m.address_primary for m in matches}
        matched_secondary = {m.address_secondary for m in matches}

        def unmatched(export_id, matched):
            path = self.exports.get(export_id)
            return [FunctionInfo(address=f.address, name=f.best_name)
                    for f in read_functions(str(path))
                    if f.address not in matched and not f.is_library]

        return DiffResult(
            primary_id=primary_id,
            secondary_id=secondary_id,
            matches=[{
                "address_primary": m.address_primary,
                "address_secondary": m.address_secondary,
                "name_primary": m.name_primary,
                "name_secondary": m.name_secondary,
                "similarity": m.similarity,
                "confidence": m.confidence,
                "algorithm": m.algorithm,
            } for m in matches],
            unmatched_primary=unmatched(primary_id, matched_primary),
            unmatched_secondary=unmatched(secondary_id, matched_secondary),
            similarity=metadata.similarity if metadata else 0.0,
            confidence=metadata.confidence if metadata else 0.0,
            database=str(database),
        )

    def health(self) -> dict:
        return {
            "ok": True,
            "exports": len(self.exports.ids()),
            "export_bytes": self.exports.total_bytes(),
            "results": len(list(self._results_dir.glob("*.BinDiff"))),
            **self._stats,
        }


class _Handler(BaseHTTPRequestHandler):
    """Routes requests to the service. One instance per request."""

    protocol_version = "HTTP/1.1"
    service: BinDiffService  # set on the server class

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        logger.info("%s - %s", self.address_string(), format % args)

    # -- helpers ----------------------------------------------------------

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send_json({"ok": False, "error": message}, status)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        if length > MAX_UPLOAD_BYTES:
            raise ValueError(
                f"upload of {length} bytes exceeds the {MAX_UPLOAD_BYTES} "
                f"byte limit")
        return self.rfile.read(length)

    # -- routes -----------------------------------------------------------

    def do_GET(self):  # noqa: N802 - stdlib signature
        service = type(self).service
        try:
            if self.path == "/health":
                self._send_json(service.health())
            elif self.path.startswith("/functions/"):
                export_id = self.path[len("/functions/"):]
                functions = service.functions(export_id)
                self._send_json({"ok": True,
                                 "functions": [f.to_json() for f in functions]})
            elif self.path == "/exports":
                self._send_json({"ok": True, "ids": service.exports.ids()})
            else:
                self._error(404, f"no such route: {self.path}")
        except UnknownExport as exc:
            self._error(404, f"unknown export id: {exc}")
        except Exception as exc:  # surfaced, never swallowed
            logger.exception("GET %s failed", self.path)
            self._error(500, str(exc))

    def do_POST(self):  # noqa: N802 - stdlib signature
        service = type(self).service
        try:
            if self.path == "/upload":
                # Raw bytes rather than JSON: base64 would inflate a
                # thirty-megabyte export by a third for no benefit.
                export_id = service.upload(self._read_body())
                self._send_json({"ok": True, "id": export_id})
            elif self.path == "/diff":
                request = json.loads(self._read_body() or b"{}")
                primary = request.get("primary")
                secondary = request.get("secondary")
                if not primary or not secondary:
                    self._error(400, "both 'primary' and 'secondary' required")
                    return
                result = service.diff(primary, secondary,
                                      force=bool(request.get("force")))
                self._send_json({"ok": True, **result.to_json()})
            else:
                self._error(404, f"no such route: {self.path}")
        except UnknownExport as exc:
            self._error(404, f"unknown export id: {exc}")
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception as exc:
            logger.exception("POST %s failed", self.path)
            self._error(500, str(exc))


def make_server(service: BinDiffService, host: str = "127.0.0.1",
                port: int = 0) -> ThreadingHTTPServer:
    """Builds a server bound to `host:port`.

    Port 0 asks the OS for a free one, which is what tests use; read it back
    from `server.server_address[1]`. Bound to loopback by default: the service
    runs the engine on files a caller names, so it has no business on a public
    interface without a deliberate decision.
    """
    handler = type("BoundHandler", (_Handler,), {"service": service})
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8710)
    parser.add_argument("--cache-dir",
                        default=str(Path.home() / ".cache" / "bindiff-server"))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    service = BinDiffService(Path(args.cache_dir))
    server = make_server(service, args.host, args.port)
    host, port = server.server_address[:2]
    logger.info("bindiff service on http://%s:%s, cache in %s",
                host, port, args.cache_dir)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
