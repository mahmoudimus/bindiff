# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A fork of [google/bindiff](https://github.com/google/bindiff) (structural comparison of executable objects). See `README.md` for upstream docs and `docs/concepts.md` for the matching algorithms.

Working branch is `fork-next`, rebuilt directly on `upstream/main`. The older `fork` / `test` / `python` branches predate the upstream sync and carry patches upstream has since made obsolete — don't build on them.

Local deltas over upstream:

- **Java single-executable.** IDA Pro 9.0+ is 64-bit only and ships one `ida` binary. `IdaHelpers` exposes a single `IDA_EXECUTABLE` and `ExternalAppUtils.getIdaExe()` no longer picks between `ida`/`ida64` by database extension. Upstream fixed this on the C++ side but still carries the 32/64 split in Java.
- **`python/`** — Cython bindings to the engine plus an IDA plugin (`python/ida_plugin/bindiff_plugin.py`), originally PR #2, rebased onto the current API.
- **Metadata sidecar** — an extension mechanism for matching signals, with the first feature (`imports/v1`) shipped. See "Architecture".
- **Test harness** — `docker-compose.yml`, `tools/scripts/run_tests_docker.sh`, `.github/workflows/python.yml`, `ida-plugin.json`.
- **Build/test fixes** in `CMakeLists.txt` and `test_util.h` (see "Gotchas").

Do *not* reintroduce what upstream superseded: the `ida/CMakeLists.txt` plugin-naming patch (upstream renamed `add_ida_plugin` → `ida_add_plugin(... SOURCES ...)` and already emits one plugin), or any encrypted-IDA-SDK CI machinery — BinExport now fetches the public [HexRaysSA/ida-sdk](https://github.com/HexRaysSA/ida-sdk) at `v9.4.0-release`, so `IdaSdk_ROOT_DIR`, `IDASDK_SECRET` and `decrypt_secret.sh` no longer exist.

## Build

BinExport is a **source** dependency, not a package: it is `add_subdirectory`'d and supplies the shared CMake modules, Abseil, Protobuf, GoogleTest and the IDA SDK handling.

```bash
git clone https://github.com/google/binexport ../binexport

cmake -S . -B build/out -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DBINDIFF_BUILD_TESTING=ON \
  -DBINDIFF_BINEXPORT_DIR=../binexport \
  -DBINEXPORT_ENABLE_IDAPRO=OFF        # drop this to build the IDA plugin
cmake --build build/out
```

`BUILD_TESTING` **must be passed explicitly** — `BinDiffOptions.cmake` forces it OFF before `include(CTest)` can default it ON, so no test target compiles otherwise.

Java UI (needs the commercial yFiles 2.x jars; Gradle 6.x, Java 11):

```bash
export YFILES_DIR=<path/to/yfiles_2.17>   # dir containing y.jar and ysvg.jar
cd java && gradle shadowJar               # -> java/ui/build/libs/bindiff-ui-all.jar
```

## Test

```bash
cd build/out && ctest --output-on-failure -R '^[A-Z]'
./build/out/differ_test --gtest_filter='GtTest/GroundtruthTest.Run/insider'
```

### Measuring against ground truth

```bash
tools/scripts/measure_groundtruth.py --compare   # with vs. without the sidecar
tools/scripts/measure_groundtruth.py             # plain recall and headroom
```

`ctest` only checks that results do not get *worse*; this reports how good they
are, which is what decides whether a new matching signal is worth building. It
disables name matching by default (every fixture ships full symbols, so with the
defaults almost everything matches by name and the number means nothing) and
reports each algorithm's own precision separately from its knock-on effects.
Needs `protobuf` but not the Cython extension, so it runs on the host.

`-R '^[A-Z]'` is not cosmetic: BinDiff's own suites start with an uppercase letter, and the other ~250 registered tests are Abseil's.

48 tests, including four end-to-end `GtTest/GroundtruthTest.Run/{insider,libssl_0_9_8g__x86_,minievil,mydoom}` cases that diff the `.BinExport` pairs in `fixtures/` and compare against the checked-in `.truth` files. `differ_test` resolves those paths against `$TEST_SRCDIR`, which its CMake target points at `build/out/src_include/third_party/zynamics` — the configure-time `bindiff` symlink there keeps the paths independent of the checkout directory's name.

`BinDiffEnvironment` (`test_util.h`) installs a test config that **disables name-based matching** — both fixture binaries carry full symbols, so with the shipped defaults everything would match by name and the tests would prove nothing. Build graphs with `test_util.h`'s `FunctionBuilder` / `BasicBlockBuilder` / `InstructionBuilder`.

### Python / IDA tests

The Cython extension is loaded by IDA's own interpreter, so it must be **compiled against that interpreter** — a build from elsewhere will not import. Everything therefore builds inside the IDA image:

```bash
./tools/scripts/run_tests_docker.sh all              # ctest + pytest on IDA 9.4
./tools/scripts/run_tests_docker.sh python -- -k stats
./tools/scripts/run_tests_docker.sh shell --service idapro-tests-9.1
./tools/scripts/run_tests_docker.sh python --with-binexport   # + the export stage
./tools/scripts/run_tests_docker.sh --help
```

`--with-binexport` builds BinExport's IDA plugin (a second CMake tree with
`BINEXPORT_ENABLE_IDAPRO=ON` and the IDA SDK fetched — minutes on a cold run,
then cached under `build/`) and installs it into the image's `/app/ida/plugins`.
Do **not** install it via `IDAUSR`: `/root/.idapro/plugins` is the read-only bind
mount carrying the bindiff package, and overriding `IDAUSR` breaks idalib's
discovery of the installation.

It unlocks the tests that need a `.BinExport` generated at test time.
`python/tests/fixture_builder.py` compiles one generated C source twice (`-O0`
and `-O2`), exports both, and derives ground truth from the symbol names — which
is what makes the IDA-only sidecar features measurable at all. The checked-in
`.idb` fixtures cannot serve: they are 32-bit databases IDA 9.x refuses without
an `upg32` the image does not ship.

9.4 is the primary leg (BinExport pins the IDA SDK to 9.4); 9.1 is a compatibility leg. Images come from `docker-compose.yml`, overridable via `BINDIFF_TEST_IMAGE_94` / `BINDIFF_TEST_IMAGE_91`. Container deps live in `.github/docker-apt-deps.txt` (cmake, ninja — the images ship gcc but no generator) and `.github/docker-deps.txt` (Cython, pytest); CI hashes both for its image cache key.

`python/setup.py` derives its include paths from `compile_commands.json` and its link line by discovering the archives CMake built. Don't reintroduce hand-maintained lists of Abseil libraries — the previous one went stale on every dependency bump and failed one missing `-l` at a time.

## Architecture

Pipeline: a disassembler plugin (BinExport) emits `.BinExport` protobufs → the differ matches them → results land in a `.BinDiff` SQLite file → the Java UI, the C++ IDA plugin, or the Python bindings render them.

**Core engine (repo root + `match/`), namespace `security::bindiff`:**

- `differ.cc` — `Diff()` takes a `MatchingContext` plus an ordered list of matching steps and produces `FixedPoints` (matched function pairs, each holding matched basic-block pairs). `Read()` loads a `.BinExport`; `SetupGraphsFromProto()` does the same from an in-memory proto.
- `call_graph.{h,cc}` / `flow_graph.{h,cc}` — Boost.Graph-backed program representation, built through `FromProto()` / `Create()` factories. `instruction.cc` + `prime_signature.cc` (a ~940 KB generated table) supply instruction-level features.
- `match/` — one file per algorithm, `function_*` (call-graph level) and `basic_block_*` (flow-graph level). `match/call_graph.cc` and `match/flow_graph.cc` are the registries: `GetDefaultMatchingSteps()` / `GetDefaultMatchingStepsBasicBlock()` build the step lists **from the config**, matching `Config::MatchingStep.name()` against hardcoded step objects. Adding an algorithm means: new files in `match/`, add them to `bindiff_shared` in `CMakeLists.txt`, register the step in the relevant registry, **and** add an entry under `function_matching` / `basic_block_matching` in `bindiff.json`. A step absent from the config gets confidence `-1.0` and is silently skipped.
- **Metadata sidecar** (`sidecar.{h,cc}`, `bindiff_metadata.proto`, `python/bindiff/metadata*.py`) — per-function features BinExport does not carry, in an optional `foo.BinExport.meta` beside `foo.BinExport`. Features are *named and self-describing* (`"imports/v1"`, metric `EXACT` or `JACCARD`), so `match/function_feature.cc` is generic over the name: a step is created **from the config** on demand rather than registered in the hardcoded list, keyed on `"function: feature <name>"`. Adding a feature is a producer change plus a config entry, not an engine change. Sidecars are refused when their `executable_id` disagrees with the export's — the engine cannot afford to re-hash, and pairing metadata with the wrong binary produces confident wrong matches. Generated, never checked in.
- Output goes through the `Writer` interface (`writer.h`): `DatabaseWriter` (`.BinDiff` SQLite), `LogWriter` (`.results`), `GroundtruthWriter` (`.truth`); `ChainWriter` runs several. `reader.h` reads results back without re-diffing.
- `change_classifier.cc` classifies *how* a matched pair differs (instructions, operands, branch inversion, loops, calls, entry point).

**The `.BinDiff` schema** (`DatabaseWriter::PrepareDatabase`) is easy to misread, and getting it wrong is silent: `function` **is** the match table — one row per matched pair, carrying `address1`/`name1`/`address2`/`name2` and that pair's counts. Likewise `basicblock` and `instruction` hold matched pairs. There are no `*match` tables. Unmatched functions are **not stored at all**; recovering them means comparing against the `.BinExport` inputs. In `file`, `functions` counts only non-library functions and `libfunctions` holds the rest, so a total is the two summed.

**Configuration** (`config.{h,cc}`, `bindiff_config.proto`, `bindiff.json`): `bindiff.json` is embedded at build time (`file(READ)` → `config_defaults.h.in`) and also parsed into the `Config` proto. `config::Proto()` lazily loads per-user/system config and merges it over the defaults; `config::MergeInto()` special-cases the matching-step lists because order and uniqueness matter. Editing `bindiff.json` needs a rebuild to affect compiled-in defaults.

**Progress and cancellation.** `Diff()` takes an optional `DiffCallback`, called before each matching step and on each round of propagating matches through the call graph — propagation is where a step spends its time, so a callback that only saw step boundaries would go quiet for exactly as long as the work takes. Returning false stops the diff; `ClassifyChanges` still runs, so a cancelled diff yields a smaller *coherent* result rather than nothing. That is worth more here than for a search: the steps run strongest first, so an interrupted diff has the matches worth having.

Exposed as `bindiff.diff(..., progress=callable)`. The callback runs on the diffing thread with the GIL retaken for its duration, so it must be short. Only an explicit `False` cancels — a callback that prints and returns `None` keeps going. An exception cancels and is re-raised to the caller rather than escaping the trampoline into C++ frames. The C boundary uses `int`, not `bool`: Cython's `bint` generates a C `int`, and a pointer to a function returning C++ `bool` is a different type that will not convert.

Unlike [ida-sigmaker](https://github.com/mahmoudimus/ida-sigmaker), which polls every 65536 matches because `user_cancelled()` pumps the UI loop at ~1 ms a call, this callback is inherently coarse — tens of calls over a whole diff — so it needs no stride.

**Progress into the plugin.** The diff runs in a worker process, so the reports have to cross it. `bindiff.headless` puts one JSON object per line on the worker's stdout under a `progress` key — flushed, because stdout is a pipe there and Python block-buffers a pipe, which would deliver every record in one burst at exit. `run_headless(..., on_progress=, cancel=)` reads those lines as they arrive (`Popen`, not `subprocess.run`) and calls the handler on *its* thread; the plugin posts each one to the UI thread with `execute_sync(MFF_FAST)`. stderr is merged into stdout rather than read afterwards: a worker that fills the stderr pipe while the launcher is still reading stdout would deadlock, and idalib is chatty enough to do it. A timeout returns a failing `StageResult` instead of raising — the caller is on a worker thread with nowhere to catch it, and a thread that dies quietly leaves the UI waiting forever. A progress handler that raises is recorded in `details["progress_error"]` and dropped, never allowed to cost a finished diff.

`ida_plugin.panels.DiffProgressForm` renders it: a dockable panel, not `show_wait_box`, which is modal and would give back the responsiveness the whole out-of-process design buys. Exports get Qt's indeterminate bar (`setRange(0, 0)`) because idalib's auto-analysis reports nothing to make a fraction from; the pipeline weights the two exports at 60% of the bar (`_EXPORT_SHARE`) since they are much the slower half. Nothing here calls `processEvents()` — a script doing its work on the UI thread needs that (eidolon's pattern) but the work is in another process, so the UI thread is already free and re-entering the event loop by hand would only invite reentrancy.

**Cancelling asks; it does not kill.** The launcher writes `cancel` on the worker's stdin (`--cancel-on-stdin`, passed only when a `cancel` event was given, so a worker run by hand keeps its stdin). The worker answers with a `cancelling` progress record, returns False from its own engine callback, and the engine's cancel-to-partial writes the matches it already had — which crosses the process boundary as the same `.BinDiff` and the same JSON line a complete run uses. Measured on `fixtures/benchmark`: **13.9s → 0.94s, keeping 729 of 10230 matches**; terminating the worker instead would have kept none. stdin rather than a signal because SIGINT cannot be delivered to one child on Windows.

The acknowledgement is what makes the wait bounded: heard, the worker gets `_CANCEL_GRACE` (300s) to write out; silent for `_CANCEL_ACK_TIMEOUT` (5s) it is terminated, which only happens inside an export, where nothing is listening and a half-finished export holds nothing worth keeping. `details["cancelled"]` is set by the **worker**, and only when the engine was really stopped — not merely when a cancel was requested. Both layers got this wrong first: a short diff finishes between the request and the next callback, and labelling that complete result partial sends the reader hunting for matches that were never missing.

**`main_portable.cc`** is the `bindiff` CLI: `--primary`/`--secondary` (also positional), `--output_dir`, `--output_format=bin,log`, `--export`, `--ls`, `--md_index`, `--print_config`, `--ui`. Invoked as `bindiff_ui` (or with `--ui`) it launches the Java UI via `start_ui.cc` instead of diffing. It is the quickest way to check engine behaviour against what the Python bindings report.

**`ida/` (C++ plugin)** links `bindiff_shared` and drives the engine in-process. `results.{h,cc}` owns diff state; `*_chooser.cc` are the list views; `visual_diff.cc` talks to the Java UI over the socket in `java/.../socketserver/SocketServer.java`; `Results::PortComments()` copies symbols and comments into the primary database, using `names.cc` for IDA's anterior/posterior line comments.

**The service (`python/bindiff/server.py`, `client.py`)** — a resident process that keeps parsed exports and finished diffs, so the same pair is never diffed twice. Interface taken from BinDiff-Server (GSoC 2025; a checkout lives at `~/src/idapro/Bindiff-Server`) — upload two exports, get ids, diff two ids — but backed by *this* engine through the Cython bindings; that project's own matchers are a reimplementation its commit log measures at ~93% of real BinDiff. Ids are the SHA-256 of the export, the same key the metadata sidecar uses. Transport is stdlib HTTP (JSON, raw bytes for uploads), not gRPC: the extension already pins the service to one interpreter, and a large binary wheel inside IDA's Python buys nothing for a same-machine client. Measured cold vs. cached: 74 ms → 1 ms (insider), 3040 ms → 217 ms (a 54 MB pair).

The handler bounds every socket read (`socket_timeout`, 30s) and the server can shut itself down after an idle period (`idle_timeout`, off by default but set by `start_service`). Both were taken from [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) after checking they fixed real gaps here: without the first, a client announcing a large `Content-Length` and then stopping parks a handler thread forever; without the second, a service the plugin starts outlives the IDA that started it. The idle check consults a *busy probe* — requests touch the timer on arrival, so a diff running longer than the TTL would otherwise look idle and be killed mid-work.

`client.py` has two halves. `BinDiffClient` blocks; `make_async_client()` returns a QObject that runs the same calls on a QThread and reports via signals, following ida-taskr's pattern, so the plugin never stalls the database. **The async half requires a Qt binding to be *already imported*** — importing one inside a headless IDA process takes the interpreter down (see `ida_env.qt_core_usable`), so it is checked with `sys.modules`, never `find_spec` and never an import. That is why the live async tests skip headless and run in the GUI harness instead.

**`python/`** — `wrappers.{h,cc}` exposes a narrow C++ surface and `core.pyx` wraps it. (`results_wrapper.{h,cc}` and `ida_plugin.{pxd,pyx}` are gone: the first reimplemented the engine's `Results` over an in-memory vector with its writes unimplemented and its reads querying tables that do not exist. Reading and editing a `.BinDiff` is `bindiff.database`, in plain sqlite3.) `sqlite_throwing.h` restores throwing semantics over the `absl::Status` sqlite API because the Cython entry points are declared `except +`. Don't add a `catch(...)` that returns an empty result — that is exactly what hid the broken queries for so long: a failed read looked identical to a diff that found no matches.

**`java/`** — Gradle multi-project: `zylib` (shared `gui`, `disassembly`, `io`, `system`, `yfileswrap`) and `ui` (the yFiles visual diff, main class `com.google.security.zynamics.bindiff.BinDiff`). Reads `.BinDiff` files via `sqlite-jdbc` and shells out to IDA to re-export IDBs.

## Gotchas

**Include convention.** Sources use Google-internal absolute paths — `#include "third_party/zynamics/bindiff/differ.h"`, `"third_party/absl/..."` — even for files sitting next to each other. These resolve through directory symlinks created at configure time into `${BINDIFF_BINARY_DIR}/src_include` and `gen_include`. Match this in new files; generated headers (`bindiff_config.pb.h`, `version.cc`, `config_defaults.h`) are reachable only this way.

**Error handling** is `absl::Status` / `absl::StatusOr` with Abseil's `ABSL_RETURN_IF_ERROR` / `ABSL_ASSIGN_OR_RETURN`. BinExport's old `NA_*` macros and `util/status_macros.h` are gone. In tests, `ABSL_ASSERT_OK_AND_ASSIGN` is **not** part of open-source Abseil (which ships only `status_matchers.h`: `IsOk`, `IsOkAndHolds`, `StatusIs`); `test_util.h` defines it, guarded so a future Abseil that exports it wins.

**Configure order matters.** `include(BinDiffOptions)` must stay above `add_subdirectory(binexport)` — it forces `BINEXPORT_BUILD_TESTING`, which is what makes BinExport request GoogleTest and Abseil's testing targets. `ABSL_FIND_GOOGLETEST` is forced OFF for the same reason: Abseil defaults it ON and would look for an *installed* GoogleTest instead of aliasing the one BinExport just built — which fails anywhere without a system GoogleTest, and silently links a second unrelated copy anywhere with one.

C++ style is `.clang-format` (Google, `PointerAlignment: Left`), C++20.
