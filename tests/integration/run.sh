#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PREFIX=$(mktemp -d)
BUILD_LIB=$(mktemp -d)
BUILD_TEST=$(mktemp -d)

cleanup() { rm -rf "$PREFIX" "$BUILD_LIB" "$BUILD_TEST"; }
trap cleanup EXIT

echo "=== Building and installing mdnspp ==="
cmake -S "$ROOT_DIR" -B "$BUILD_LIB" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_LIB"
cmake --install "$BUILD_LIB"

echo "=== Configuring downstream project ==="
cmake -S "$SCRIPT_DIR" -B "$BUILD_TEST" \
    -DCMAKE_PREFIX_PATH="$PREFIX" \
    -DCMAKE_BUILD_TYPE=Release

echo "=== Building downstream project ==="
cmake --build "$BUILD_TEST"

echo "=== Running integration test ==="
"$BUILD_TEST/integration_test"

echo "=== Integration test PASSED ==="
