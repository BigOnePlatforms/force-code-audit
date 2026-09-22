#!/usr/bin/env bash
# Rulepack regression check.
#
# `semgrep --validate` only proves the YAML parses into rules — it says nothing
# about whether they match. Both bugs found while writing this pack were of the
# second kind: a case-sensitive exclusion that flagged `secretName`, and rules
# that validated but fired on interoperability-mandated SHA-1. So this asserts
# behaviour in both directions: every rule fires on violations.ts, and clean.ts
# produces nothing at all.
#
# Usage: actions/force-code-audit/verify-rulepack.sh [path-to-semgrep]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEMGREP="${1:-semgrep}"
PACK="$HERE/rulepack/force-compliance.yml"
EXPECTED_RULES=9   # rules exercised by violations.ts

"$SEMGREP" --validate --config "$PACK"

fired=$("$SEMGREP" scan --config "$PACK" "$HERE/fixtures/violations.ts" --json --no-error -q \
  | python3 -c 'import json,sys; print(len({r["check_id"] for r in json.load(sys.stdin)["results"]}))')
if [ "$fired" -lt "$EXPECTED_RULES" ]; then
  echo "FAIL: only $fired/$EXPECTED_RULES rules fired on violations.ts" >&2
  exit 1
fi

noise=$("$SEMGREP" scan --config "$PACK" "$HERE/fixtures/clean.ts" --json --no-error -q \
  | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["results"]))')
if [ "$noise" -ne 0 ]; then
  echo "FAIL: $noise false positive(s) on clean.ts" >&2
  "$SEMGREP" scan --config "$PACK" "$HERE/fixtures/clean.ts" --no-error -q >&2 || true
  exit 1
fi

echo "OK: $fired rules fired on violations.ts, 0 findings on clean.ts"
