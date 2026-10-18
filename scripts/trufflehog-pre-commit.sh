#!/usr/bin/env bash
# Check *only* the staged patch that would become the next commit.
set -euo pipefail
if ! command -v trufflehog >/dev/null 2>&1; then
  echo 'TruffleHog is required: install from https://github.com/trufflesecurity/trufflehog' >&2
  exit 1
fi
# Pre-commit runs before a commit exists, so scanning HEAD would miss new secrets.
# TruffleHog filesystem stdin scans only the staged patch, not repository history.
patch=$(mktemp)
trap 'rm -f "$patch"' EXIT
git diff --cached --binary --no-ext-diff -- . ':(exclude)poetry.lock' > "$patch"
if [ ! -s "$patch" ]; then
  exit 0
fi
trufflehog filesystem --no-update --no-verification --fail --json "$patch"
