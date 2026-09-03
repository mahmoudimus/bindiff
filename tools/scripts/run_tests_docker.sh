#!/bin/bash
# Run BinDiff's tests inside an IDA Pro Docker image.
# Paths are repo-relative; no host-specific paths.
#
# Usage:
#   ./run_tests_docker.sh build   [OPTIONS]
#   ./run_tests_docker.sh ctest   [OPTIONS] [-- CTEST_ARGS...]
#   ./run_tests_docker.sh python  [OPTIONS] [-- PYTEST_ARGS...]
#   ./run_tests_docker.sh all     [OPTIONS]
#   ./run_tests_docker.sh shell   [OPTIONS]
#   ./run_tests_docker.sh exec    [OPTIONS] -- COMMAND [ARGS...]
#
# Commands:
#   build   Configure and build the C++ tree, then build the Cython extension
#           in place. Everything else runs this first.
#   ctest   Run the C++ suite (ctest -R '^[A-Z]', which selects BinDiff's own
#           tests; every other registered name is an absl_* dependency test).
#   python  Run pytest against the Cython extension inside IDA's interpreter.
#   all     ctest then python.
#   shell   Interactive bash after the build.
#   exec    Run COMMAND after the build.
#
# Why everything builds inside the container: the Cython extension is loaded by
# IDA's own interpreter, so it must be compiled against that interpreter's ABI.
# The C++ static libraries it links are built in the same image to keep the
# toolchain and libstdc++ consistent.
#
# Each invocation gets a fresh container, so cmake/ninja and the Python build
# deps are reinstalled every time (about 20s). The build tree itself lives under
# /work and does persist, so only changed sources recompile. CI avoids the
# reinstall by baking the dependencies into a committed image -- see
# .github/workflows/python.yml.
#
# Options:
#   -s, --service NAME   Compose service to use (default: idapro-tests, IDA 9.4).
#                        Use idapro-tests-9.1 for the 9.1 leg.
#   -j, --jobs N         Parallel build jobs (default: nproc in the container).
#       --rebuild        Discard the existing build tree and configure from scratch.
#       --no-build       Skip the build step; assume a previous run left one behind.
#       --with-binexport Also build BinExport's IDA plugin and install it into
#                        the container's IDA, which lets the export stage and
#                        anything needing a freshly generated .BinExport run.
#                        Off by default: it is a second CMake tree with the IDA
#                        SDK fetched and roughly 560 more objects to compile, so
#                        it adds minutes to a cold run. The tree persists under
#                        /work/build, so only the first run pays for it.
#   --                   Remaining args go to ctest / pytest, or are the exec command.
#
# Environment (host):
#   BINDIFF_TEST_IMAGE_94   Override the IDA 9.4 image (see docker-compose.yml)
#   BINDIFF_TEST_IMAGE_91   Override the IDA 9.1 image
#   BINDIFF_BINEXPORT_DIR   Host path to a BinExport checkout. Default: a
#                           sibling "binexport" directory next to this repo.
#                           BinDiff does not build without it.
#   BINDIFF_DOCKER_MEMORY   Container memory limit (default: 8g), applied via
#                           mem_limit in docker-compose.yml
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SERVICE="idapro-tests"
JOBS=""
REBUILD=""
NO_BUILD=""
WITH_BINEXPORT="${BINDIFF_WITH_BINEXPORT:-}"
EXTRA=()

# Container-side paths. The C++ build tree lives under /work so it survives
# between invocations (the repo is bind-mounted read-write) and is platform-
# tagged by service, so two images do not share one tree.
CONTAINER_BUILD_DIR="/work/build/docker-${SERVICE}"
# The Python extension does NOT: it has the same filename on every platform,
# so building it into the mount replaced whatever the host had built and left
# the plugin unable to import in a real IDA. These live in the container, and
# die with it -- the object files are the only slow part and the container is
# reused, so nothing is paid twice.
# Scoped by service: the extension links against the C++ archives from that
# service's build tree, and the two images are not the same IDA.
CONTAINER_EXT_DIR="/opt/bindiff-ext/${SERVICE}"
CONTAINER_OBJ_DIR="/opt/bindiff-obj/${SERVICE}"
IDA_PYTHON="/app/ida/.venv/bin/python3"

CMD="${1:-}"
shift || true
case "$CMD" in
  build|ctest|python|all|shell|exec) ;;
  -h|--help)
    sed -n '2,/^set -euo pipefail$/p' "$0" | sed '$d'
    exit 0
    ;;
  *)
    echo "Usage: $0 build|ctest|python|all|shell|exec [OPTIONS] [-- ARGS...]" >&2
    echo "Run with --help for full help." >&2
    exit 1
    ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    -s|--service) SERVICE="$2"; shift 2 ;;
    -j|--jobs)    JOBS="$2"; shift 2 ;;
    --rebuild)    REBUILD=1; shift ;;
    --no-build)   NO_BUILD=1; shift ;;
    --with-binexport) WITH_BINEXPORT=1; shift ;;
    --)           shift; EXTRA=("$@"); break ;;
    *)            echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

CONTAINER_BUILD_DIR="/work/build/docker-${SERVICE}"
CONTAINER_EXT_DIR="/opt/bindiff-ext/${SERVICE}"
CONTAINER_OBJ_DIR="/opt/bindiff-obj/${SERVICE}"

# BinExport is a source dependency: BinDiff add_subdirectory()s it and takes
# Abseil, Protobuf, GoogleTest and the IDA SDK handling from it.
BINEXPORT_DIR="${BINDIFF_BINEXPORT_DIR:-$(cd "$REPO_ROOT/.." && pwd)/binexport}"
if [ ! -f "$BINEXPORT_DIR/CMakeLists.txt" ]; then
  echo "ERROR: BinExport not found at $BINEXPORT_DIR" >&2
  echo "Clone it next to this repo, or set BINDIFF_BINEXPORT_DIR:" >&2
  echo "  git clone https://github.com/google/binexport $BINEXPORT_DIR" >&2
  exit 1
fi

echo "$0 plan:"
echo "  command:   $CMD"
echo "  service:   $SERVICE"
echo "  binexport: $BINEXPORT_DIR -> /binexport"
echo "  build dir: $CONTAINER_BUILD_DIR"
[ ${#EXTRA[@]} -gt 0 ] && echo "  args:      ${EXTRA[*]}"
echo ""

# printf %q so an argument containing whitespace (e.g. -k "A or B") survives
# being re-parsed by the shell inside the container.
quote_args() {
  local out="" arg
  for arg in "$@"; do out+="$(printf '%q ' "$arg")"; done
  printf '%s' "$out"
}

# Provision the toolchain the images lack, then build. Both steps are
# idempotent: apt-get and pip are skipped once the marker file is present, so
# repeated runs against a warm container only re-run cmake and setup.py.
read -r -d '' SETUP_CMD <<EOF || true
set -e
export BINDIFF_BUILD_DIR="$CONTAINER_BUILD_DIR"
export BINDIFF_PACKAGE_DIR="$CONTAINER_EXT_DIR"
export BINDIFF_BINEXPORT_DIR=/binexport
if [ ! -f /tmp/.bindiff-deps-installed ]; then
  echo "[setup] installing build dependencies"
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    \$(sed 's/#.*//' /work/.github/docker-apt-deps.txt | tr '\n' ' ')
  $IDA_PYTHON -m pip install --quiet --disable-pip-version-check \
    \$(sed 's/#.*//' /work/.github/docker-deps.txt | tr '\n' ' ')
  touch /tmp/.bindiff-deps-installed
else
  echo "[setup] build dependencies already present"
fi
EOF

read -r -d '' BUILD_CMD <<EOF || true
set -e
export BINDIFF_PACKAGE_DIR="$CONTAINER_EXT_DIR"
JOBS="\${JOBS:-\$(nproc)}"
if [ -n "$REBUILD" ]; then rm -rf "$CONTAINER_BUILD_DIR"; fi
echo "[build] configuring"
cmake -S /work -B "$CONTAINER_BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON \
  -DBINDIFF_BUILD_TESTING=ON \
  -DBINDIFF_BINEXPORT_DIR=/binexport \
  -DBINEXPORT_ENABLE_IDAPRO=OFF \
  -DBINEXPORT_ENABLE_BINARYNINJA=OFF
echo "[build] compiling with \$JOBS jobs"
cmake --build "$CONTAINER_BUILD_DIR" -j "\$JOBS"
echo "[build] generating Python protobuf bindings"
# Reading .BinExport from Python needs binexport2_pb2; the metadata sidecar
# needs its own. Generated rather than checked in, using the protoc the CMake
# build already produced, so the bindings always match the schema in the tree.
PROTOC="$CONTAINER_BUILD_DIR/_deps/protobuf-build/protoc"
mkdir -p /work/python/bindiff/_pb
touch /work/python/bindiff/_pb/__init__.py
"\$PROTOC" --proto_path=/binexport --python_out=/work/python/bindiff/_pb \
  binexport2.proto
"\$PROTOC" --proto_path=/work --python_out=/work/python/bindiff/_pb \
  bindiff_metadata.proto

echo "[build] building the Cython extension against IDA's interpreter"
# Built outside the checkout. /work is a bind mount, so an in-place build
# left this container's Linux .so at python/bindiff/core.abi3.so, where it
# replaced the host's and stopped the plugin importing in a real IDA -- and
# nothing said so, because the file has the same name on both platforms.
# --build-temp keeps the object files out too, and keeps them between runs.
rm -rf "$CONTAINER_EXT_DIR"
mkdir -p "$CONTAINER_EXT_DIR"
cd /work/python && $IDA_PYTHON setup.py build_ext \
  --build-lib "$CONTAINER_EXT_DIR" --build-temp "$CONTAINER_OBJ_DIR"

# build_ext writes only the extension, so the package is completed with links
# to the live sources: an edit needs no rebuild, and a file added since the
# last run is picked up by this one.
for entry in /work/python/bindiff/*; do
  name=\$(basename "\$entry")
  [ -e "$CONTAINER_EXT_DIR/bindiff/\$name" ] || \
    ln -s "\$entry" "$CONTAINER_EXT_DIR/bindiff/\$name"
done
ln -sfn /work/python/ida_plugin "$CONTAINER_EXT_DIR/ida_plugin"

# A leftover from when this did build in place. Removed only when it is this
# platform's: a Mach-O file here belongs to the host and is none of our
# business.
leftover=/work/python/bindiff/core.abi3.so
if [ -f "\$leftover" ] && head -c 4 "\$leftover" | grep -qa ELF; then
  echo "[build] removing a stale in-tree extension from an earlier run"
  rm -f "\$leftover"
fi
rm -rf /work/python/build
EOF

# BinExport's IDA plugin, in its own tree because it needs
# BINEXPORT_ENABLE_IDAPRO=ON and the IDA SDK, neither of which the main build
# wants. Installed into the image's own plugin directory rather than IDAUSR:
# /root/.idapro/plugins is the read-only bind mount carrying the bindiff
# package, and overriding IDAUSR breaks idalib's discovery of the installation.
read -r -d '' BINEXPORT_CMD <<EOF || true
set -e
BE_BUILD_DIR="$CONTAINER_BUILD_DIR-binexport"
if [ ! -f "\$BE_BUILD_DIR/ida/binexport12_ida.so" ]; then
  echo "[binexport] configuring (fetches the IDA SDK on first use)"
  cmake -S /work -B "\$BE_BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DBINDIFF_BINEXPORT_DIR=/binexport \
    -DBINEXPORT_ENABLE_IDAPRO=ON \
    -DBINEXPORT_ENABLE_BINARYNINJA=OFF >/dev/null
  echo "[binexport] compiling the IDA plugin"
  cmake --build "\$BE_BUILD_DIR" -j "\${JOBS:-\$(nproc)}" --target binexport12_ida
else
  echo "[binexport] plugin already built"
fi
cp -f "\$BE_BUILD_DIR/ida/binexport12_ida.so" /app/ida/plugins/
echo "[binexport] installed into /app/ida/plugins"
EOF

if [ -z "$WITH_BINEXPORT" ]; then
  BINEXPORT_CMD="echo '[binexport] not requested (pass --with-binexport)'"
fi

if [ -n "$NO_BUILD" ]; then
  BUILD_CMD="echo '[build] skipped (--no-build)'"
fi

JOBS_ENV=""
[ -n "$JOBS" ] && JOBS_ENV="-e JOBS=$JOBS"

run_in_container() {
  local inner="$1"
  local tty_flags="${2:-}"
  # shellcheck disable=SC2086
  docker compose run --rm $tty_flags \
    $JOBS_ENV \
    -v "$BINEXPORT_DIR:/binexport" \
    --entrypoint bash \
    "$SERVICE" -lc "$inner"
}

case "$CMD" in
  build)
    run_in_container "$SETUP_CMD"$'\n'"$BUILD_CMD"$'\n'"$BINEXPORT_CMD" -T
    ;;
  ctest)
    # -R '^[A-Z]': BinDiff's own gtest suites start with an uppercase letter;
    # the ~250 other registered tests are Abseil's and are not ours to run.
    run_in_container "$SETUP_CMD"$'\n'"$BUILD_CMD"$'\n'"$BINEXPORT_CMD"$'\n'"cd $CONTAINER_BUILD_DIR && ctest --output-on-failure -R '^[A-Z]' $(quote_args "${EXTRA[@]}")" -T
    ;;
  python)
    run_in_container "$SETUP_CMD"$'\n'"$BUILD_CMD"$'\n'"$BINEXPORT_CMD"$'\n'"cd /work && $IDA_PYTHON -m pytest python/tests -v -p no:cacheprovider $(quote_args "${EXTRA[@]}")" -T
    ;;
  all)
    run_in_container "$SETUP_CMD"$'\n'"$BUILD_CMD"$'\n'"$BINEXPORT_CMD"$'\n'"cd $CONTAINER_BUILD_DIR && ctest --output-on-failure -R '^[A-Z]'"$'\n'"cd /work && $IDA_PYTHON -m pytest python/tests -v -p no:cacheprovider" -T
    ;;
  shell)
    run_in_container "$SETUP_CMD"$'\n'"$BUILD_CMD"$'\n'"$BINEXPORT_CMD"$'\n'"exec bash"
    ;;
  exec)
    if [ ${#EXTRA[@]} -eq 0 ]; then
      echo "ERROR: exec requires a command after -- (e.g. $0 exec -- python3 -c 'print(1)')" >&2
      exit 1
    fi
    run_in_container "$SETUP_CMD"$'\n'"$BUILD_CMD"$'\n'"$BINEXPORT_CMD"$'\n'"$(quote_args "${EXTRA[@]}")" -T
    ;;
esac
