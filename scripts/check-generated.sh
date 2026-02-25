#!/usr/bin/env bash
set -euo pipefail

# Check that generated code is up-to-date.
# Run this in CI after `buf generate` to catch stale generated files.

if [ -n "$(git diff --name-only -- backend/internal/gen/ frontend/src/gen/)" ]; then
  echo "ERROR: Generated code is out of date. Run 'make gen' and commit the changes."
  git diff --stat -- backend/internal/gen/ frontend/src/gen/
  exit 1
fi

echo "Generated code is up to date."
