#!/usr/bin/env bash
# Installs the plugin into ~/.idapro/plugins for development.
#
# Not a symlink to the repository root, which is the obvious thing and is
# wrong. The CMake build tree contains
#
#   build/out/src_include/third_party/zynamics/bindiff -> <the repository>
#
# the configure-time symlink that makes the Google-style absolute includes
# resolve. Exposing the repository root to IDA's plugin scanner exposes that
# loop: IDA descends it, finds a second ida-plugin.json, and loads a second
# copy of the plugin as a separate module. Two copies register the same
# action names, and the one that answers is whichever registered last -- so
# edits appear not to take effect, and a traceback names a path nobody chose.
#
# Linking the manifest and python/ individually keeps the build tree out of
# reach. python/ has no symlinks of its own.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
plugins="${IDAUSR:-$HOME/.idapro}/plugins"
name="${1:-bindiff-ng}"
target="$plugins/$name"

[ -f "$repo/ida-plugin.json" ] || { echo "no ida-plugin.json in $repo" >&2; exit 1; }

rm -rf "$target"
mkdir -p "$target"
ln -s "$repo/ida-plugin.json" "$target/ida-plugin.json"
ln -s "$repo/python" "$target/python"

# Stale bytecode outlives an edit and is indistinguishable from one that did
# not take effect.
find "$repo/python" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

reachable=$(find -L "$target" -maxdepth 6 -name ida-plugin.json 2>/dev/null | wc -l | tr -d ' ')
if [ "$reachable" != "1" ]; then
  echo "error: IDA can reach $reachable ida-plugin.json files under $target;" >&2
  echo "       exactly one is required or it will load the plugin twice" >&2
  find -L "$target" -maxdepth 6 -name ida-plugin.json >&2
  exit 1
fi

echo "installed $name -> $repo"
echo "  manifests reachable: $reachable"
echo "restart IDA to pick it up"
