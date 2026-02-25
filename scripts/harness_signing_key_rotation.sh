#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
ROTATION_TOKEN="${OIDC_SIGNING_KEY_ROTATION_TOKEN:-dev-signing-key-rotation-token}"
ROTATE_PATH="${ROTATE_PATH:-/oauth2/admin/rotate-signing-key}"

failures=0

info() {
  echo "[INFO] $*"
}

pass() {
  echo "[PASS] $*"
}

fail() {
  echo "[FAIL] $*"
  failures=$((failures + 1))
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[ERROR] required command not found: $1" >&2
    exit 2
  fi
}

fetch() {
  local url="$1"
  local output_file="$2"
  local http_code
  http_code="$(curl -sS -m "$TIMEOUT_SECONDS" -o "$output_file" -w "%{http_code}" "$url" || true)"
  if [[ ! "$http_code" =~ ^[0-9]{3}$ ]]; then
    http_code="000"
  fi
  printf "%s" "$http_code"
}

require_cmd curl
require_cmd jq

info "BASE_URL=$BASE_URL"
info "ROTATE_PATH=$ROTATE_PATH"

jwks_before="$(mktemp)"
jwks_after="$(mktemp)"
unauthorized_body="$(mktemp)"
invalid_body="$(mktemp)"
rotate_body="$(mktemp)"

jwks_status="$(fetch "$BASE_URL/oauth2/jwks" "$jwks_before")"
if [[ "$jwks_status" == "200" ]]; then
  pass "jwks endpoint status is 200"
else
  fail "jwks endpoint status is $jwks_status"
fi

if jq -e '.keys | arrays and (length > 0)' "$jwks_before" >/dev/null 2>&1; then
  pass "jwks has non-empty keys array before rotation"
else
  fail "jwks must have non-empty keys array before rotation"
fi

before_len="$(jq -r '.keys | length' "$jwks_before" 2>/dev/null || printf "0")"
before_active_kid="$(jq -r '.keys[0].kid // empty' "$jwks_before" 2>/dev/null || true)"
if [[ -n "$before_active_kid" ]]; then
  pass "jwks has active kid before rotation"
else
  fail "jwks active kid is empty before rotation"
fi

unauthorized_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$unauthorized_body" -w "%{http_code}" \
    -X POST "$BASE_URL$ROTATE_PATH" || true
)"
if [[ "$unauthorized_status" == "401" ]]; then
  pass "rotation endpoint rejects missing bearer token with 401"
else
  fail "rotation endpoint missing bearer token status is $unauthorized_status"
fi
if jq -e '.error == "unauthorized"' "$unauthorized_body" >/dev/null 2>&1; then
  pass "missing bearer token returns unauthorized error"
else
  fail "missing bearer token must return unauthorized error"
fi

invalid_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$invalid_body" -w "%{http_code}" \
    -X POST "$BASE_URL$ROTATE_PATH" \
    -H "Authorization: Bearer invalid-token" || true
)"
if [[ "$invalid_status" == "401" ]]; then
  pass "rotation endpoint rejects invalid token with 401"
else
  fail "rotation endpoint invalid token status is $invalid_status"
fi
if jq -e '.error == "unauthorized"' "$invalid_body" >/dev/null 2>&1; then
  pass "invalid bearer token returns unauthorized error"
else
  fail "invalid bearer token must return unauthorized error"
fi

rotate_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$rotate_body" -w "%{http_code}" \
    -X POST "$BASE_URL$ROTATE_PATH" \
    -H "Authorization: Bearer $ROTATION_TOKEN" || true
)"
if [[ "$rotate_status" == "200" ]]; then
  pass "rotation endpoint accepts valid token"
elif [[ "$rotate_status" == "404" ]]; then
  fail "rotation endpoint is disabled (set OIDC_ENABLE_SIGNING_KEY_ROTATION_API=true)"
else
  fail "rotation endpoint status is $rotate_status"
fi

rotated_kid="$(jq -r '.kid // empty' "$rotate_body")"
if [[ -n "$rotated_kid" ]]; then
  pass "rotation response includes kid"
else
  fail "rotation response must include kid"
fi
if [[ -n "$before_active_kid" && "$rotated_kid" != "$before_active_kid" ]]; then
  pass "rotated kid differs from previous active kid"
else
  fail "rotated kid must differ from previous active kid"
fi

jwks_after_status="$(fetch "$BASE_URL/oauth2/jwks" "$jwks_after")"
if [[ "$jwks_after_status" == "200" ]]; then
  pass "jwks endpoint status is 200 after rotation"
else
  fail "jwks endpoint status after rotation is $jwks_after_status"
fi

after_len="$(jq -r '.keys | length' "$jwks_after" 2>/dev/null || printf "0")"
if (( before_len < 2 )); then
  expected_len=$((before_len + 1))
else
  expected_len=2
fi
if [[ "$after_len" == "$expected_len" ]]; then
  pass "jwks key count matches expected rotation window"
else
  fail "jwks key count mismatch after rotation: got=$after_len want=$expected_len"
fi

after_active_kid="$(jq -r '.keys[0].kid // empty' "$jwks_after" 2>/dev/null || true)"
if [[ -n "$after_active_kid" && -n "$rotated_kid" && "$after_active_kid" == "$rotated_kid" ]]; then
  pass "jwks active kid matches rotated kid"
else
  fail "jwks active kid mismatch after rotation"
fi

if jq -e --arg kid "$rotated_kid" '.keys | map(.kid) | index($kid) != null' "$jwks_after" >/dev/null 2>&1; then
  pass "jwks contains rotated kid"
else
  fail "jwks must contain rotated kid"
fi

if jq -e --arg kid "$before_active_kid" '.keys | map(.kid) | index($kid) != null' "$jwks_after" >/dev/null 2>&1; then
  pass "jwks retains previous active kid during grace window"
else
  fail "jwks must retain previous active kid during grace window"
fi

if jq -e '(.keys | map(.kid)) as $kids | ($kids | length) == ($kids | unique | length)' "$jwks_after" >/dev/null 2>&1; then
  pass "jwks has unique kids"
else
  fail "jwks kids must be unique"
fi

rm -f "$jwks_before" "$jwks_after" "$unauthorized_body" "$invalid_body" "$rotate_body"

if (( failures > 0 )); then
  printf "\nSigning key rotation harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nSigning key rotation harness passed.\n"
