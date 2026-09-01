# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A fork of [google/bindiff](https://github.com/google/bindiff) (structural comparison of executable objects). See `README.md` for upstream docs and `docs/concepts.md` for the matching algorithms.

Working branch is `fork-next`, rebuilt directly on `upstream/main`. The older `fork` / `test` / `python` branches predate the upstream sync and carry patches upstream has since made obsolete — don't build on them.

Local deltas over upstream:

- **Java single-executable.** IDA Pro 9.0+ is 64-bit only and ships one `ida` binary. `IdaHelpers` exposes a single `IDA_EXECUTABLE` and `ExternalAppUtils.getIdaExe()` no longer picks between `ida`/`ida64` by database extension. Upstream fixed this on the C++ side but still carries the 32/64 split in Java.
- **`python/`** — Cython bindings to the engine plus an IDA plugin (`python/ida_plugin/bindiff_plugin.py`), originally PR #2, rebased onto the current API.
- **Metadata sidecar** — an extension mechanism for matching signals; `imports/v1` and `prototype/v1` ship enabled. See "Architecture".
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

`.github/workflows/python.yml` also carries a **`portable-tests`** leg on macOS, Windows and Linux that installs nothing but pytest and runs the tests needing neither IDA nor the extension (`test_ui_logic`, `test_diff_runner`). It exists because a Windows-only bug shipped: `find_python_interpreter` looked under `prefix/bin/`, which does not exist on Windows, so the launcher reported "no Python interpreter found" with a working interpreter sitting in the prefix — and nothing in CI ran anywhere it could have been noticed. `interpreter_candidates(prefix, windows=)` now takes the platform as an argument so both layouts are checked from Linux; monkeypatching `os.name` is not an alternative, since pathlib reads it to choose PosixPath or WindowsPath and faking it globally crashes the test runner.

The leg is narrow on purpose: anything importing `bindiff.*` pulls in the Cython extension through `bindiff/__init__.py`, which is why `test_headless` — including those very Windows tests — is not in it.

9.4 is the primary leg (BinExport pins the IDA SDK to 9.4); 9.1 is a compatibility leg. Images come from `docker-compose.yml`, overridable via `BINDIFF_TEST_IMAGE_94` / `BINDIFF_TEST_IMAGE_91`. Container deps live in `.github/docker-apt-deps.txt` (cmake, ninja — the images ship gcc but no generator) and `.github/docker-deps.txt` (Cython, pytest); CI hashes both for its image cache key.

**The container does not build into the checkout.** `/work` is a bind mount and
a Python extension has the same filename on every platform, so
`build_ext --inplace` there left a Linux `core.abi3.so` in `python/bindiff/`,
replacing whatever the host had built and leaving the plugin unable to import
in a real IDA -- with nothing to say so, because the name is identical. The
harness builds it to `/opt/bindiff-ext` (objects to `/opt/bindiff-obj`, kept
between runs) and completes the package there with links to the live sources,
so an edit still needs no rebuild. `BINDIFF_PACKAGE_DIR` tells `conftest.py`
to put that directory ahead of `python/`; without it the source directory
answers with a package that has no extension in it.

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

### Which sidecar features are enabled, and why

Measured on 9 pairs of real programs — coreutils, diffutils, findutils across
optimisation levels and versions, from `DeepBinDiff/experiment_data` — with
`tools/scripts/measure_real_corpus.py`. 1799 ground-truth pairs, name matching
off.

| feature | delta | own precision | pairs improved | enabled |
|---|---|---|---|---|
| `imports/v1` | +149 (40.9% → 49.1%) | 254/266 95% | 8/9 | yes |
| `prototype/v1` | +48 (→ 43.5%) | 35/38 92% | **9/9** | yes |
| `frame/v1` | +4 (→ 41.1%) | 78/98 80% | 2/9, hurt 2/9 | **no** |
| `mnemonic-histogram/v1` | +8 (→ 41.3%) | 286/303 94% | 5/9, hurt 4/9 | **no** |

Together: 40.9% → **52.0%**. Order is not cosmetic — imports before prototype is
923 correct, the reverse 907, because the steps run strongest first and an
earlier one claims a pair the later then cannot.

**Embeddings enter through `COSINE`.** `sidecar.cc` reads `FloatVector` values, normalises them on load so a comparison is a dot product, and `match/function_feature.cc` runs the same mutual-best-match rule the set features use. Candidates come from LSH over signed random projections (`kVectorHashBands` × `kVectorHashBits`, fixed seed) — dense vectors share no discrete keys, so the inverted index the set features use has nothing to key on and the search would be all-pairs. The seed is fixed because a matcher whose answers moved between runs would make every regression test a coin flip.

The threshold is **not** comparable to the Jaccard one and was swept separately: a set feature scores unrelated functions at zero, while a dense embedding returns a number for every pair. At 0.9 the mnemonic histogram ran at 70% precision; at 0.98 it reaches 94%, matching `imports/v1`. `kDefaultVectorThreshold` carries the sweep.

`python/bindiff/metadata_embedding.py` is the baseline producer — a TF-IDF bag of mnemonics, no model, no dependencies. It exists to be beaten: a learned producer (asm2vec, jTrans) replaces that one file and changes nothing else, and now has a number to beat. **PyTorch would live there**, in the headless worker, never in IDA's interpreter and never linked into the differ, which only ever reads floats from a file.

It is not enabled by default: 5 pairs improved and 4 got worse. The split is structural, not noise — it is strong on cross-*version* pairs (151/154, 65/70, 55/59) and weak across optimisation levels, because `-O2` rewrites the instruction mix and a version bump barely touches it. Worth revisiting for a workload that is mostly version-to-version.

### Where the wrong matches come from

36% of the engine's judgeable matches disagree with ground truth (523 of 1447
on the nine-pair corpus). Diagnosed rather than assumed, and the answer is not
what the residual analysis suggested:

**The engine already knows.** Wrong matches have median similarity **0.124**
against 0.875 for correct ones, and median confidence 0.269 against 0.933. The
information needed to distrust them is already recorded per match.

**They come from five steps.** `function: call sequence matching(sequence)`
alone produces 342 of the 523, at **88.4% wrong**. With `(topology)`,
`(exact)`, `address sequence` and `loop count matching` it is 433 of 523 — 83%.
Three of those already carry a configured confidence of 0, 0 and 0.1: the
config says they are worthless and they run anyway, pairing up leftovers by
position. The strong steps are clean — `hash matching` and `prime signature`
0% wrong, `imports/v1` 1.6%.

**They are not permutation errors.** Only 2.7% are clean swaps a global
assignment would untangle; 54.5% sit in longer cycles and 34.8% took the
counterpart of a function that has no match at all. This is the same conclusion
the cross-tabulation reached from the other side.

**`function: call sequence matching(sequence)` is disabled by default** — the
one local delta to upstream's ladder. It is wrong on every corpus available:
76.5% on the checked-in fixtures (MinGW vs LCC, MSVC, 32-bit x86, human-
confirmed truth), 88.2% on cross-optimisation pairs, 93.3% on cross-version
ones. Its own configured confidence was already 0.

Removing it is not the recall-for-precision trade it looks like. It is better
on **both** axes:

| | correct | wrong | precision |
|---|---|---|---|
| with the step | 924 | 484 | 65.6% |
| without | **932** | **212** | **81.5%** |

The fixtures agree — baseline 620 → 640 correct and 255 → 184 wrong. Recall
rises because the step was *blocking*: the ladder is re-entered on every
propagation round and on bucket drill-down, so a bad pair taken in one round
denies it to a better step in a later one. A step that runs "last" is not
therefore harmless.

The other four weak steps stay, and the per-pair split is why:
`address sequence` and `loop count matching` are **0% wrong on version pairs**
and only fail across optimisation levels, where address order is meaningless by
construction. They are conditionally valid heuristics, not noise, and
disabling them would break the case they exist for. `measure_real_corpus.py
--drop-steps` makes that measurable for a workload that differs.

Where it is *not* a judgement call is porting. `plan_symbol_ports` and
`plan_comment_ports` defaulted `min_similarity` and `min_confidence` to 0.0,
so every match copied its name — 1440 names of which 516 were wrong, written
silently into the primary database, where a wrong name looks like analysis
somebody did. They now default to 0.5 (93.8% precision, keeping 69% of correct
ports); `DEFAULT_PORT_MIN_SIMILARITY` carries the measurement. A caller can
still pass 0.0, which is a different thing from getting it by default.

**Call reference matching is not a config step.** It is hardcoded in
`differ.cc`, runs after *every* matching step on every fixed point that step
produced, and recurses into its own results. For each matched basic-block pair
whose two sides make the same number of calls, it pairs the call targets **by
position** — first with first — and until recently committed them with no test
of any kind.

It now requires the shorter function to be at least half the longer
(`kMinCallTargetInstructionRatio`). The pairs it got wrong were the ones that
are nothing alike: instruction-count ratio median 0.40 against 0.92 for the
correct ones, with cases like 14 instructions against 1. Corpus 932/212 →
**948/196**, fixtures 686/163 → **691/164**.

A function with *no* instruction count — an import or thunk whose body this
binary does not contain — passes. Rejecting those instead cost **226 of 640**
correct matches on the fixtures, because the recursion means refusing a pair
also refuses everything that pair would have gone on to seed. Absence of
evidence is not evidence here, and this mechanism amplifies whichever it is.

### The learned embedding, and the baseline it did not beat

`python/bindiff/asm2vec.py` is asm2vec's shape — PV-DM over instruction tokens
from random walks on the CFG — and `tools/scripts/train_asm2vec.py` trains it.
**PyTorch is imported lazily by the producer alone**: never in IDA's
interpreter, never linked into the differ, which only reads floats from a file.

**The model must be frozen and shared.** Trained per binary, the two sides of a
diff land in unrelated spaces where every cosine is meaningless *while still
landing in [0, 1]* — a trap, not an error. So it trains once over a corpus and
inference fits only the new binary's function vectors against the fixed tokens.
That also keeps a sidecar a property of one binary, which the content
addressing and `executable_id` check depend on. The model file is a zip of JSON
and a float array, not a torch checkpoint: a checkpoint is a pickle, and
loading one runs whatever it contains.

Trained on 30 binaries **held out** from the measured programs (6324 functions,
482 tokens × 100 dimensions, 105s), measured on the nine stripped pairs:

| producer | separation | best precision | correct at 0.98 |
|---|---|---|---|
| mnemonic histogram | **0.205** | 94.7% @ 0.98 | **306** |
| asm2vec | 0.090 | 91.5% @ 0.98 | 172 |

**The learned model loses to a TF-IDF bag of mnemonics**, which is exactly why
the baseline was built first. Both were diagnosed, not guessed: training loss
plateaued by epoch 2, and inference separation peaks at 60 steps and *degrades*
at 150, so neither is under-trained. The embedding simply separates true pairs
from random ones by 0.09 where the histogram manages 0.205.

What this does *not* say is that asm2vec fails. This is a simplification of it
(plain walks, no selective callee expansion), on a small corpus, untuned, on
the hardest case in the set — O0 against O2 dominates the corpus. It says the
bar is 306 correct at 94.7%, and that a learned producer has to clear it.

`tools/scripts/sweep_embedding_threshold.py` is how both were measured without
rebuilding: it applies the engine's own mutual-best rule to the vectors. Read
the **separation** line first — a feature with a small gap cannot be rescued by
choosing a threshold well.

### Global assignment: dead, then alive once the noise was gone

`match/function_neighbour_assignment.{h,cc}` scores each surviving candidate
pair by how many of their call-graph neighbours are already matched to each
other — the quantity IsoRank propagates and BinSlayer's Hungarian pass scores —
and resolves the result as one global assignment (`SolveAssignment`, an exact
O(n³) Hungarian verified against brute force).

**It was shelved with a measured ceiling of zero.** Recovering a miss needs
neighbour *evidence* and a still-free *counterpart*, and those two conditions
had no overlap at all: 129 had evidence, 104 were free, 0 had both. Enabled, it
took 8 pairs and got none right.

That ceiling was a consequence of the engine, not of the idea. Once
`call sequence matching(sequence)` was disabled and call reference matching
gained its guard, the engine stopped spending counterparts on rubbish and the
same cross-tabulation reads:

| | counterpart free | counterpart taken |
|---|---|---|
| **neighbour evidence** | **246** | 133 |
| no evidence | 219 | 57 |

Enabled now, it is worth about 98 correct matches across both corpora at a
precision indistinguishable from not running it (81.9% against 82.0%). It
requires **three** agreeing neighbours; the header carries the sweep, and the
argument I originally made for one — that a global assignment rescues weak
evidence — is measurably wrong. A global optimum over noise is still noise.

**The general lesson:** a negative result measured against a noisy baseline
expires when the noise is fixed. Both shelved decisions here were taken against
an engine making 616 wrong matches; the others (`frame/v1`,
`mnemonic-histogram/v1`, `asm2vec/v1`) are still shelved on that basis and are
worth re-measuring for the same reason.

### The learned embedding, and the baseline it did not beat

`python/bindiff/asm2vec.py` is asm2vec's shape — PV-DM over instruction tokens
from random walks on the CFG — and `tools/scripts/train_asm2vec.py` trains it.
**PyTorch is imported lazily by the producer alone**: never in IDA's
interpreter, never linked into the differ, which only reads floats from a file.

**The model must be frozen and shared.** Trained per binary, the two sides of a
diff land in unrelated spaces where every cosine is meaningless *while still
landing in [0, 1]* — a trap, not an error. So it trains once over a corpus and
inference fits only the new binary's function vectors against the fixed tokens.
That also keeps a sidecar a property of one binary, which the content
addressing and `executable_id` check depend on. The model file is a zip of JSON
and a float array, not a torch checkpoint: a checkpoint is a pickle, and
loading one runs whatever it contains.

Trained on 30 binaries **held out** from the measured programs (6324 functions,
482 tokens × 100 dimensions, 105s), measured on the nine stripped pairs:

| producer | separation | best precision | correct at 0.98 |
|---|---|---|---|
| mnemonic histogram | **0.205** | 94.7% @ 0.98 | **306** |
| asm2vec | 0.090 | 91.5% @ 0.98 | 172 |

**The learned model loses to a TF-IDF bag of mnemonics**, which is exactly why
the baseline was built first. Both were diagnosed, not guessed: training loss
plateaued by epoch 2, and inference separation peaks at 60 steps and *degrades*
at 150, so neither is under-trained. The embedding simply separates true pairs
from random ones by 0.09 where the histogram manages 0.205.

What this does *not* say is that asm2vec fails. This is a simplification of it
(plain walks, no selective callee expansion), on a small corpus, untuned, on
the hardest case in the set — O0 against O2 dominates the corpus. It says the
bar is 306 correct at 94.7%, and that a learned producer has to clear it.

`tools/scripts/sweep_embedding_threshold.py` is how both were measured without
rebuilding: it applies the engine's own mutual-best rule to the vectors. Read
the **separation** line first — a feature with a small gap cannot be rescued by
choosing a threshold well.

### Global assignment, and why it is not a last step

`match/function_neighbour_assignment.{h,cc}` scores each surviving candidate
pair by how many of their call-graph neighbours are already matched to each
other — the quantity IsoRank propagates and BinSlayer's Hungarian pass scores —
and resolves the result as one global assignment (`SolveAssignment`, an exact
O(n³) Hungarian, verified against brute force in
`match/function_neighbour_assignment_test.cc`). It is **built and not enabled**,
because measuring it produced the clearest negative result in this repository.

Two conditions must hold together to recover a miss: neighbour **evidence**, and
the correct counterpart still being **free**. On the nine-pair corpus:

| | counterpart free | counterpart taken |
|---|---|---|
| **neighbour evidence** | **0** | 129 |
| no evidence | 104 | 152 |

**The overlap is exactly zero.** Where there is evidence, greedy propagation
already used it and spent the counterpart; where the counterpart is free, the
function is isolated and there is nothing to reason from. Enabled, the step took
8 pairs across nine binaries and got none of them right.

Read the margins separately and you get "129 have evidence, 104 are free, so
over a hundred are recoverable" — which is how the first version of
`analyze_residual.py` misled me. It now prints the cross-tabulation and refuses
to report the margins alone.

The conclusion is not that global assignment is useless. It is that it cannot
run *last*: to help it must revise matches other steps committed, which is what
BinSlayer does — it scores everything rather than treating the greedy result as
fixed. `SolveAssignment` is there for that when it is built.

### What a match's confidence actually means

Not what the step that found it is worth. `Count(const FixedPoint&)` puts the
function-level step into the histogram **once**, alongside one entry per matched
basic block, and `GetConfidence` takes the weighted average. For a function with
ten matched blocks the function step carries one eleventh of the number.

That matters for reading a result: the confidence column is dominated by how
well the *basic blocks* matched, not by which function-level algorithm proposed
the pair.

It also means the configured confidences are miscalibrated at the bottom of the
ladder without it mattering. Measured precision against configured value, over
both corpora:

| step | configured | measured |
|---|---|---|
| `hash matching` | 1.00 | 100% |
| `prime signature`, `imports/v1`, `prototype/v1` | 0.90 | 98–100% |
| `edges callgraph MD index` | 0.90 | 89% |
| `call reference matching` | 0.75 | 88% |
| `loop count matching` | 0.60 | 55% |
| `call graph neighbour assignment` | 0.40 | **71%** |
| `address sequence` | 0.40 | 43% |
| `call sequence matching(exact)` | 0.10 | **65%** |
| `call sequence matching(topology)` | 0.00 | **74%** |

The top ten are within ±0.10 — upstream's values check out. The bottom four are
wrong and two are *inverted*, `address sequence` at 43% being trusted more than
`(exact)` at 65%. Recalibrating them was measured and changes nothing: porting
at the 0.5 floor gives 717 ports and 93.3% precision either way, because of the
weighting above. So it was not done. Worth knowing before anyone spends time on
it, and worth revisiting only if something starts consuming the per-step number
directly.

### The weak steps that stayed, and why

After `call sequence matching(sequence)` was removed, the remaining error
sources were measured the same way. Two were kept, on evidence:

| candidate | nine real pairs | four fixtures |
|---|---|---|
| drop `call sequence matching(exact)` | −19 correct, −2 wrong | not run |
| drop `address sequence` | −2 correct, −18 wrong | **−87 correct**, −60 wrong |

`(exact)` gives up 19 correct matches to remove 2. It is 33% wrong on
cross-optimisation pairs and 30% on cross-version ones — bad on both, like its
removed sibling — but unlike that sibling it is also contributing, and a size
guard does not separate it (correct median 0.57, wrong 0.47).

`address sequence` looked like the clearest remaining cut: 25% precision
overall, and 9 wrong removed per correct lost on the real corpus. The fixtures
refused it, losing 87 correct matches — it is load-bearing on cross-toolchain
pairs, where it was 99 correct of 197. **Two corpora that disagree is the only
reason that change did not ship**, and it is the second time in this file that
has been true; the first was the call-reference guard.

A size-ratio guard does help some steps and not others — it separates
`loop count matching` (correct 0.82, wrong 0.44) and `MD index (flowgraph, top
down)` (0.79 against 0.43), and does nothing at all for `address sequence`
(0.96 against 1.00, because pairing leftovers by address order picks functions
that are the same size). Applying one globally would therefore be wrong.

### The shelved features, re-measured

Every shelved decision here was originally taken against an engine making 616
wrong matches, so all three were re-run against the current one — each added to
the shipped `imports/v1` + `prototype/v1` rather than to nothing, which is the
question that actually matters (`--base-features`):

| feature | net | pairs | own precision | verdict |
|---|---|---|---|---|
| `mnemonic-histogram/v1` | **+6** | 4 up, 2 down | 108/119 91% | still shelved |
| `asm2vec/v1` | **−2** | 1 up, 2 down | 66/70 94% | still shelved |
| `frame/v1` | **−5** | 2 up, 3 down | 65/93 70% | still shelved |

All three verdicts held, which is worth knowing: they were *not* artefacts of
the noisy baseline, unlike the global assignment step's ceiling of zero.

`asm2vec/v1` is the interesting one. Its own matches are 94% correct — better
than the histogram's — and the net is still negative. High own-precision with a
negative net means **redundancy, not error**: it finds what other steps already
find, and occasionally takes a pair one of them would have got right. "The
model is weak" and "the model adds nothing the engine lacks" are different
diagnoses, and this is the second.

The headroom these were built for has largely been taken by fixing the matching
noise instead — the baseline they compete against went from 735 to 1027.

**Measure stripped, or do not bother.** The same corpus unstripped says
`prototype/v1` is worth **+795** and 74.9% recall — because those builds carry
`debug_info`, so IDA reads exact signatures out of DWARF. The step fires 1244
times there against 38 stripped, a 33× collapse. Anything measured against
symbols or debug info is measuring the debug info. `--strip` is the mode that
answers the question the default config has to answer.

**Stack variable names** (`stack_names.py`, `stack_names_ida.py`) — upstream
issue #13. BinExport2 has no locals table, which is why this looks impossible;
the names are there anyway, because a stack operand is an `IMMEDIATE_INT`
expression carrying its own `symbol`. Two things are *not* there: the
primary's frame offset, and the frame itself.

**The offset cannot be carried across.** The export records the raw
displacement in the instruction, and the two sides disagree — 987 of 2910
matched operands differed on the hexx64 pair, a third of them. So the name
travels with the *instruction*, through the match, and
`calc_stkvar_struc_offset` resolves the primary's own offset at apply time.
A frame is a `tinfo_t` UDT since IDA 9.0, renamed with `rename_udm`, which
returns `TERR_*` and really does refuse a name already used in that frame —
unlike `set_name`.

Measured on hexx64 9.3 → 9.4: 2354 planned, **14 renamed**, 2060 already
identical, 223 not stack variables in this database, 57 refused as
collisions. The small number is the honest one: IDA derives `Src`, `Str`,
`Block` from its own type libraries on both sides, so most of what looks
portable is already there. The feature earns its keep on a database somebody
has named by hand, not on two builds of the same DLL.

It does not reach the decompiler. Hex-Rays names its own locals in its own
store, the same split as comments.

**Configuration** (`config.{h,cc}`, `bindiff_config.proto`, `bindiff.json`): `bindiff.json` is embedded at build time (`file(READ)` → `config_defaults.h.in`) and also parsed into the `Config` proto. `config::Proto()` lazily loads per-user/system config and merges it over the defaults; `config::MergeInto()` special-cases the matching-step lists because order and uniqueness matter. Editing `bindiff.json` needs a rebuild to affect compiled-in defaults.

**Progress and cancellation.** `Diff()` takes an optional `DiffCallback`, called before each matching step and on each round of propagating matches through the call graph — propagation is where a step spends its time, so a callback that only saw step boundaries would go quiet for exactly as long as the work takes. Returning false stops the diff; `ClassifyChanges` still runs, so a cancelled diff yields a smaller *coherent* result rather than nothing. That is worth more here than for a search: the steps run strongest first, so an interrupted diff has the matches worth having.

Exposed as `bindiff.diff(..., progress=callable)`. The callback runs on the diffing thread with the GIL retaken for its duration, so it must be short. Only an explicit `False` cancels — a callback that prints and returns `None` keeps going. An exception cancels and is re-raised to the caller rather than escaping the trampoline into C++ frames. The C boundary uses `int`, not `bool`: Cython's `bint` generates a C `int`, and a pointer to a function returning C++ `bool` is a different type that will not convert.

Unlike [ida-sigmaker](https://github.com/mahmoudimus/ida-sigmaker), which polls every 65536 matches because `user_cancelled()` pumps the UI loop at ~1 ms a call, this callback is inherently coarse — tens of calls over a whole diff — so it needs no stride.

**Progress into the plugin.** The diff runs in a worker process, so the reports have to cross it. `bindiff.headless` puts one JSON object per line on the worker's stdout under a `progress` key — flushed, because stdout is a pipe there and Python block-buffers a pipe, which would deliver every record in one burst at exit. `run_headless(..., on_progress=, cancel=)` reads those lines as they arrive (`Popen`, not `subprocess.run`) and calls the handler on *its* thread; the plugin posts each one to the UI thread with `execute_sync(MFF_FAST)`. stderr is merged into stdout rather than read afterwards: a worker that fills the stderr pipe while the launcher is still reading stdout would deadlock, and idalib is chatty enough to do it. A timeout returns a failing `StageResult` instead of raising — the caller is on a worker thread with nowhere to catch it, and a thread that dies quietly leaves the UI waiting forever. A progress handler that raises is recorded in `details["progress_error"]` and dropped, never allowed to cost a finished diff.

`ida_plugin/diff_runner.py` holds the sequence between "two files were picked" and "results are on screen", with every IDA and Qt collaborator injected — so the harness drives it (`test_diff_runner.py`) rather than it existing only when IDA does. The plugin supplies the real ones and keeps the thread. The property the split exists for is that **nothing touches the UI except through a post**, which the test asserts by capturing posted actions without running them: a call that skipped one would still land on the fake panel. Progress posts with `MFF_FAST` and the single final call with `MFF_WRITE` — repainting a label must not queue behind a database lock the user's own analysis is holding, and collapsing the two into one shared helper silently loses that.

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

## Releasing

Wheels and the plugin archive go to **GitHub Releases**, not PyPI — this is a
fork and should not claim the name. `.github/workflows/wheels.yml` builds and
verifies; `release.yml` calls it on a `v*` tag and publishes.

**hcli installs a plugin's Python dependencies with pip**, and
`pythonDependencies` in `ida-plugin.json` takes pip-compatible specifications
with **no field for an index** — so `bindiff-ng==8.1.0` would resolve nowhere.
`tools/scripts/plugin_dependencies.py` turns the built wheels into PEP 508
direct references carrying environment markers instead, one per wheel:

    bindiff-ng @ https://.../bindiff_ng-8.1.0-cp313-cp313-macosx_10_15_universal2.whl ;
        sys_platform == 'darwin' and platform_machine == 'arm64'
        and python_version == '3.13'

pip evaluates the markers and fetches the one that fits. The property the whole
approach rests on is that **exactly one applies on any machine** — too few and
the install fails, too many and pip silently takes whichever was listed first.
`test_plugin_dependencies.py` asserts it across every platform in the matrix,
and refuses a wheel set with an overlap.

A PEP 503 index on GitHub Pages would read better for someone running pip by
hand, but it needs `--extra-index-url` and `pythonDependencies` has nowhere to
put one, so hcli could not use it.

Run `wheels.yml` from a branch before tagging. **The Cython step has only ever
run on Linux**: `setup.py` discovers its include paths from
`compile_commands.json` and its link line by walking the CMake tree for
archives, and neither has been exercised with MSVC. `fail-fast` is off so one
platform failing does not hide the rest.

## Gotchas

**Include convention.** Sources use Google-internal absolute paths — `#include "third_party/zynamics/bindiff/differ.h"`, `"third_party/absl/..."` — even for files sitting next to each other. These resolve through directory symlinks created at configure time into `${BINDIFF_BINARY_DIR}/src_include` and `gen_include`. Match this in new files; generated headers (`bindiff_config.pb.h`, `version.cc`, `config_defaults.h`) are reachable only this way.

**Error handling** is `absl::Status` / `absl::StatusOr` with Abseil's `ABSL_RETURN_IF_ERROR` / `ABSL_ASSIGN_OR_RETURN`. BinExport's old `NA_*` macros and `util/status_macros.h` are gone. In tests, `ABSL_ASSERT_OK_AND_ASSIGN` is **not** part of open-source Abseil (which ships only `status_matchers.h`: `IsOk`, `IsOkAndHolds`, `StatusIs`); `test_util.h` defines it, guarded so a future Abseil that exports it wins.

**Configure order matters.** `include(BinDiffOptions)` must stay above `add_subdirectory(binexport)` — it forces `BINEXPORT_BUILD_TESTING`, which is what makes BinExport request GoogleTest and Abseil's testing targets. `ABSL_FIND_GOOGLETEST` is forced OFF for the same reason: Abseil defaults it ON and would look for an *installed* GoogleTest instead of aliasing the one BinExport just built — which fails anywhere without a system GoogleTest, and silently links a second unrelated copy anywhere with one.

**The wheels are abi3.** `setup.py` defines `Py_LIMITED_API=0x030A0000` and
sets `py_limited_api`, so one wheel per platform (`cp310-abi3-*`) serves every
Python from 3.10 up instead of one per interpreter release. Cython supports
this through the preprocessor, not a build flag: defining `Py_LIMITED_API`
turns on `CYTHON_LIMITED_API`, which redefines `__PYX_LIMITED_VERSION_HEX` from
`PY_VERSION_HEX` to `Py_LIMITED_API` so every generated version check targets
3.10 rather than the building interpreter. Without it the module compiles and
then fails to load on anything older, because guards let through calls like
`PyDict_GetItemRef` that exist only in 3.13. The define **must reach the C++
compiler** — `CXXFLAGS`, or `define_macros`, never `CFLAGS`, which setuptools
does not use for C++ and which therefore produces an ordinary version-locked
module that looks like proof the stable ABI does not work. Measured cost on
`fixtures/benchmark`: median 8.049s unlimited against 8.059s limited, +0.12%,
inside a 0.37s run-to-run spread — the work is in C++ and the boundary is
crossed once per diff. `BINDIFF_LIMITED_API=0` opts out; debug builds opt out
automatically, since `CYTHON_TRACE` needs the full API.

**Two extensions in one wheel is silent.** CPython prefers
`core.cpython-313-darwin.so` over `core.abi3.so`, so a stale version-locked
artefact — in the source tree, or in setuptools' `build/lib.*` staging
directory, which `pip wheel` assembles from and nothing clears — gets packaged
and loaded in preference to the module just built. `setup.py` warns and the
wheel job fails on any wheel carrying more than one. `rm -rf python/build
python/bindiff/core.cpython-*` before building locally.

**A stale `build/out` corrupts memory rather than failing.** The extension
compiles against the current headers and links archives built from older
sources, so the two disagree about type layout: absl aborts in
`raw_hash_set` (`cap.IsValid()`), or libmalloc reports a pointer being freed
that it never allocated. Neither names the cause. Check
`build/out/libbindiff_shared.a` against the newest engine source before
trusting any result from a locally built extension.

**Do not symlink the repository into ~/.idapro/plugins.** The build tree
contains `build/out/src_include/third_party/zynamics/bindiff -> <the
repository>`, the configure-time symlink that makes the absolute includes
resolve. Exposing the repository root to IDA's plugin scanner exposes that
loop: IDA descends it, finds a second `ida-plugin.json` and loads a second
copy of the plugin as a separate module. Both copies register the same action
names, the one that answers is whichever registered last, and the symptom is
an edit that appears not to take effect plus a traceback naming a path under
`build/out/src_include/...`. `tools/scripts/install_dev_plugin.sh` links the
manifest and `python/` individually and refuses to finish if more than one
manifest is reachable.

**LTO makes the archives compiler-specific.** `BINDIFF_ENABLE_IPO` is on by
default, so the `.a` files hold LLVM bitcode rather than machine code (`file`
says "LLVM bitcode, wrapper") and only an LLVM at least as new as the producer
can read them back. setuptools does not use CMake's compiler -- it uses the one
the *interpreter* was built with, from `sysconfig` -- so a pyenv Python built
against Homebrew llvm cannot link archives Apple clang produced, and says so
once per object file. `setup.py` warns and prints the fix; the alternatives are
matching `CC`/`CXX`/`LDSHARED`/`LDCXXSHARED` to CMake's compiler or
`-DBINDIFF_ENABLE_IPO=OFF`. This is the same hazard as the mold+LTO duplicate
symbols above: LTO changes what an archive *is*, and nothing else warns.

C++ style is `.clang-format` (Google, `PointerAlignment: Left`), C++20.
