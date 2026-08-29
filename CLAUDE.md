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

**`main_portable.cc`** is the `bindiff` CLI: `--primary`/`--secondary` (also positional), `--output_dir`, `--output_format=bin,log`, `--export`, `--ls`, `--md_index`, `--print_config`, `--ui`. Invoked as `bindiff_ui` (or with `--ui`) it launches the Java UI via `start_ui.cc` instead of diffing. It is the quickest way to check engine behaviour against what the Python bindings report.

**`ida/` (C++ plugin)** links `bindiff_shared` and drives the engine in-process. `results.{h,cc}` owns diff state; `*_chooser.cc` are the list views; `visual_diff.cc` talks to the Java UI over the socket in `java/.../socketserver/SocketServer.java`; `Results::PortComments()` copies symbols and comments into the primary database, using `names.cc` for IDA's anterior/posterior line comments.

**`python/`** — `wrappers.{h,cc}` and `results_wrapper.{h,cc}` expose a narrow C++ surface; `core.pyx` / `ida_plugin.pyx` wrap it. `sqlite_throwing.h` restores throwing semantics over the `absl::Status` sqlite API because the Cython entry points are declared `except +`. Don't add a `catch(...)` that returns an empty result — that is exactly what hid the broken queries for so long: a failed read looked identical to a diff that found no matches.

**`java/`** — Gradle multi-project: `zylib` (shared `gui`, `disassembly`, `io`, `system`, `yfileswrap`) and `ui` (the yFiles visual diff, main class `com.google.security.zynamics.bindiff.BinDiff`). Reads `.BinDiff` files via `sqlite-jdbc` and shells out to IDA to re-export IDBs.

## Gotchas

**Include convention.** Sources use Google-internal absolute paths — `#include "third_party/zynamics/bindiff/differ.h"`, `"third_party/absl/..."` — even for files sitting next to each other. These resolve through directory symlinks created at configure time into `${BINDIFF_BINARY_DIR}/src_include` and `gen_include`. Match this in new files; generated headers (`bindiff_config.pb.h`, `version.cc`, `config_defaults.h`) are reachable only this way.

**Error handling** is `absl::Status` / `absl::StatusOr` with Abseil's `ABSL_RETURN_IF_ERROR` / `ABSL_ASSIGN_OR_RETURN`. BinExport's old `NA_*` macros and `util/status_macros.h` are gone. In tests, `ABSL_ASSERT_OK_AND_ASSIGN` is **not** part of open-source Abseil (which ships only `status_matchers.h`: `IsOk`, `IsOkAndHolds`, `StatusIs`); `test_util.h` defines it, guarded so a future Abseil that exports it wins.

**Configure order matters.** `include(BinDiffOptions)` must stay above `add_subdirectory(binexport)` — it forces `BINEXPORT_BUILD_TESTING`, which is what makes BinExport request GoogleTest and Abseil's testing targets. `ABSL_FIND_GOOGLETEST` is forced OFF for the same reason: Abseil defaults it ON and would look for an *installed* GoogleTest instead of aliasing the one BinExport just built — which fails anywhere without a system GoogleTest, and silently links a second unrelated copy anywhere with one.

C++ style is `.clang-format` (Google, `PointerAlignment: Left`), C++20.
