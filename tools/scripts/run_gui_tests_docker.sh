#!/bin/bash
# Run the plugin's GUI checks against a real IDA GUI, headless.
#
#   ./run_gui_tests_docker.sh [-s|--service NAME] [--keep]
#
# Everything else in this repository's test suite is headless, which leaves the
# Qt widgets, the action handlers and the graph view unexercised -- and those
# are the parts that cannot be reasoned about from the model alone. This starts
# a real IDA GUI on a virtual X display inside the container and drives the
# plugin through its own action IDs, the way d810's run_ida_gui_docker.sh does.
#
# The difference from that script: it forwards X11 to XQuartz on the host, so it
# needs a Mac with XQuartz running and cannot go in CI. Xvfb inside the
# container needs nothing on the host and runs anywhere, at the cost of not
# being able to watch it happen.
#
# The IDA image ships no Xvfb, so it is installed on first use, exactly as
# cmake and ninja are for the main harness.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SERVICE="idapro-tests"
KEEP=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s|--service) SERVICE="$2"; shift 2 ;;
    --keep)       KEEP=1; shift ;;         # leave the report for inspection
    -h|--help)    sed -n '2,/^set -euo pipefail$/p' "$0" | sed '$d'; exit 0 ;;
    *)            echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

BINEXPORT_DIR="${BINDIFF_BINEXPORT_DIR:-$(cd "$REPO_ROOT/.." && pwd)/binexport}"
REPORT_HOST="$REPO_ROOT/.tmp/gui-report.json"
mkdir -p "$REPO_ROOT/.tmp"
rm -f "$REPORT_HOST"

echo "$0 plan:"
echo "  service:  $SERVICE"
echo "  report:   $REPORT_HOST"
echo ""

# A real database to open: the .idb fixtures are old 32-bit databases that need
# an upgrade tool the image does not ship, so a fresh binary is compiled instead.
read -r -d '' SCRIPT <<'CONTAINER' || true
set -e

if [ ! -f /tmp/.bindiff-gui-deps ]; then
  echo "[gui] installing Xvfb"
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends xvfb >/dev/null
  touch /tmp/.bindiff-gui-deps
fi

echo "[gui] building a sample binary to open"
cat > /tmp/sample.c <<'SRC'
#include <stdio.h>
int helper(int x) { return x * 3; }
int branchy(int x) {
    if (x > 10) { return helper(x); }
    else if (x > 5) { return x - 1; }
    return 0;
}
int looper(int n) { int t = 0; for (int i = 0; i < n; i++) t += branchy(i); return t; }
int main(void) { printf("%d\n", looper(20)); return 0; }
SRC
gcc -O0 -o /tmp/sample /tmp/sample.c

echo "[gui] starting Xvfb"
Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
XVFB_PID=$!
trap 'kill $XVFB_PID 2>/dev/null || true' EXIT
sleep 2

export DISPLAY=:99
export MODE=x11
export LIBGL_ALWAYS_SOFTWARE=1
export QT_QPA_PLATFORM=xcb
export BINDIFF_GUI_REPORT=/tmp/gui-report.json
export PYTHONPATH=/work/python:/app/ida/python

rm -f /tmp/gui-report.json
echo "[gui] launching IDA"
# -A: autonomous, so no dialog can block a headless run.
# -S: the driver script, which defers its work to a timer and quits.
# IDA is started in the background and killed once the report appears, rather
# than waited on: qexit() from inside a timer callback does not actually bring
# the process down, so waiting for it means burning the whole timeout on every
# run -- and a real shutdown hang would then be indistinguishable from success.
/app/ida/ida -A -S/work/python/tests/gui/gui_driver.py /tmp/sample \
  >/tmp/ida-gui.log 2>&1 &
IDA_PID=$!

for _ in $(seq 1 120); do
  [ -f /tmp/gui-report.json ] && break
  kill -0 "$IDA_PID" 2>/dev/null || break   # died without reporting
  sleep 1
done
kill "$IDA_PID" 2>/dev/null || true
wait "$IDA_PID" 2>/dev/null || true

echo "[gui] IDA log tail:"
tail -25 /tmp/ida-gui.log 2>/dev/null || echo "(no log)"
if [ ! -f /tmp/gui-report.json ]; then
  echo "[gui] no report produced"
  exit 1
fi
cp /tmp/gui-report.json /work/.tmp/gui-report.json
CONTAINER

docker compose run --rm -T \
  -v "$BINEXPORT_DIR:/binexport" \
  --entrypoint bash "$SERVICE" -lc "$SCRIPT"

if [ ! -f "$REPORT_HOST" ]; then
  echo "no report produced" >&2
  exit 1
fi

python3 - "$REPORT_HOST" <<'REPORT'
import json
import sys

with open(sys.argv[1]) as handle:
    report = json.load(handle)

width = max((len(r["name"]) for r in report["results"]), default=10)
for result in report["results"]:
    mark = "PASS" if result["ok"] else "FAIL"
    detail = f"  {result['detail']}" if result["detail"] else ""
    print(f"  [{mark}] {result['name']:<{width}}{detail}")

passed = sum(1 for r in report["results"] if r["ok"])
print(f"\n{passed}/{len(report['results'])} GUI checks passed")
sys.exit(0 if report["ok"] else 1)
REPORT
status=$?

[ -n "$KEEP" ] || rm -f "$REPORT_HOST"
exit $status
