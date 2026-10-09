#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Route table IDs must remain positive on MT7621's 32-bit Go int.
PATCH="$PWD/patches/sing-tun-32bit-route-table.patch"
SOURCE="$PWD/build/core-source/submodules/sing-tun"
if git -C "$SOURCE" apply --check "$PATCH" 2>/dev/null; then
 git -C "$SOURCE" apply "$PATCH"
else
 git -C "$SOURCE" apply --reverse --check "$PATCH"
fi
