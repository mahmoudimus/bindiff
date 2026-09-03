# Profiling the differ

The method is d810's (`~/src/idapro/d810/PROFILING.md`) and so is the central
lesson: **do not infer a hotspot from reading the code.** Bound one exact
workload, sample the real process, change one dimension at a time. Three
predictions made from reading this engine were wrong before a profiler was
attached, and the profiler disagreed with all of them.

## The capture

`perf` inside the IDA test image, because the differ is pure C++ and needs no
IDA at all -- only a Linux kernel that will let `perf_event_open` through.

```bash
cp <primary>.BinExport <secondary>.BinExport build/profile/   # gitignored, mounted at /work
./tools/scripts/run_tests_docker.sh build                     # installs cmake, builds ./bindiff

docker compose run --rm -T --cap-add PERFMON --cap-add SYS_PTRACE \
  --entrypoint bash idapro-tests -lc '
    apt-get update -qq && apt-get install -y -qq --no-install-recommends linux-perf
    perf record -F 99 -g --call-graph dwarf -o /tmp/perf.data -- \
      /work/build/docker-idapro-tests/bindiff \
        --primary=/work/build/profile/<primary>.BinExport \
        --secondary=/work/build/profile/<secondary>.BinExport \
        --output_dir=/tmp/out
    perf report -i /tmp/perf.data --stdio --no-children -g none --percent-limit 1'
```

`--cap-add PERFMON --cap-add SYS_PTRACE` are required and sufficient;
`--security-opt` is not a flag `docker compose run` accepts. Each
`docker compose run` is a **fresh container**, so anything installed by a
previous one is gone -- install and record in the same invocation, or the
binary silently does not get rebuilt and both arms of an A/B measure the same
thing. That happened here.

A cheaper first pass needs no container at all: `bindiff.diff(..., progress=)`
is called before every matching step, so timing the gaps between callbacks
gives a per-step breakdown with no tooling. It located the right *steps*; it
could not locate the right *function*.

## What it found

42 MB pair (hexx64 9.4 against 9.3), 11,044 vertices, 70,346 call-graph edges:

| step | share |
| --- | --- |
| `function: edges flowgraph MD index` | 39.5% |
| `function: edges callgraph MD index` | 27.4% |
| `function: MD index matching (flowgraph, top down)` | 9.0% |

and flat, by self time:

| symbol | share |
| --- | --- |
| `BaseMatchingStepEdgesMdIndex::FilterResults` | **56.8%** |
| `__introsort_loop<FlowGraph**>` | 7.6% |
| `Neighbours(CallGraph const&, FlowGraph*)` | 5.3% |
| `MatchingStepCallGraphNeighbourAssignment::FindFixedPoints` | 1.8% |

Both hot steps share one base class, which is why the per-step view showed two
hotspots where the flat view shows one. `FilterResults` alone is more than the
next twelve symbols combined.

## Upstream's TODO, settled

`match/call_graph.cc` carries this:

```cpp
// TODO(cblichmann): Understand why this condition got here in the first
//                   place. It is expensive to calculate and at least on the
//                   libssl sample _reduces_ result quality instead of
//                   increasing it.
if (flow_graphs.count(target) == 0 && flow_graphs.count(source) == 0) {
```

Measured both ways on the 42 MB pair, one binary, the arm chosen by an
environment variable:

| | time |
| --- | --- |
| with the condition (as shipped) | 12-13s |
| without it | **did not finish in 10 minutes** |

So it is half right. The condition *is* expensive -- it is inside the 56.8% --
but it is load-bearing for performance: without it every edge feature survives
into the matching, and the work downstream explodes. Whatever it does to
result quality, it cannot simply be deleted.

## Two changes that did nothing

Recorded because a negative result costs the same to rediscover as to write
down.

**Hashing the neighbourhood lookups** in `CallGraph::CalculateProximityMdIndex`
-- replacing `std::binary_search` over a sorted `neighbors` vector with an
`absl::flat_hash_map` -- was **neutral to slightly worse** (that step went
1.20s to 1.32s). The neighbourhood is larger than it looks (median 305, max
14,051, one vertex of degree 11,411 in an 11k-vertex graph), which is why the
change seemed worth making; but a few hundred sorted elements sitting in cache
cost about eight predictable comparisons, and building a hash table over them
costs a few hundred hashes and an allocation, per edge.

**Hashing `flow_graphs`** once per `FilterResults` call, so the two
`std::set::count` walks become O(1) probes, produced **no measurable change**
either -- and it is semantics-preserving (10,164 matches both ways), so the
idea is sound and the cost simply is not there.

The lesson from both: `perf report` attributes *inlined* code to the enclosing
symbol. With LTO on, "56.8% in `FilterResults`" means the whole loop body,
including `GetFlowGraph`, `boost::source`/`target` and the set lookups. It does
not say which line. **`perf annotate` is the next step**, and guessing instead
of running it has now failed three times.

## The constraint any change has to respect

The MD index is a sum of doubles. Changing the order neighbours are visited, or
which edges are admitted, changes the result in the last bits and with it which
pairs match. A rework may replace *lookups* freely; it may not reorder
*iteration*. `ctest -R '^[A-Z]'` includes four ground-truth pairs and is the
cheap check, but it passed for both changes above -- the honest check is the
match count on a real pair, and `tools/scripts/measure_real_corpus.py` for
quality.
