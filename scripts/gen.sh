#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Cleaning generated code..."
rm -rf "$REPO_ROOT/backend/internal/gen"
rm -rf "$REPO_ROOT/frontend/src/gen"

mkdir -p "$REPO_ROOT/backend/internal/gen"
mkdir -p "$REPO_ROOT/frontend/src/gen"

echo "==> Running buf generate..."
cd "$REPO_ROOT/proto"
buf generate

echo "==> Done."
