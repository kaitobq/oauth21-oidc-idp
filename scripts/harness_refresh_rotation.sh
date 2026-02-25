#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_DEV_CLIENT_ID:-local-dev-client}"
REDIRECT_URI="${OIDC_DEV_REDIRECT_URI:-http://localhost:3000/callback}"
SCOPE="${SCOPE:-openid offline_access}"
STATE="${STATE:-refresh-rotation-state}"
CODE_VERIFIER="${CODE_VERIFIER:-refresh-rotation-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"

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

urlencode() {
  jq -rn --arg v "$1" '$v|@uri'
}

extract_query_param() {
  local raw_url="$1"
  local key="$2"
  local query

  query="${raw_url#*\?}"
  if [[ "$query" == "$raw_url" ]]; then
    return 1
  fi

  IFS='&' read -r -a pairs <<< "$query"
  for pair in "${pairs[@]}"; do
    local k="${pair%%=*}"
    local v="${pair#*=}"
    if [[ "$k" == "$key" ]]; then
      printf "%s" "$v"
      return 0
    fi
  done

  return 1
}

require_cmd curl
require_cmd jq
require_cmd openssl

code_challenge="$(
  printf "%s" "$CODE_VERIFIER" \
    | openssl dgst -binary -sha256 \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
)"

info "BASE_URL=$BASE_URL"
info "CLIENT_ID=$CLIENT_ID"
info "REDIRECT_URI=$REDIRECT_URI"

auth_headers="$(mktemp)"
auth_body="$(mktemp)"
token_body="$(mktemp)"
refresh_body="$(mktemp)"
reuse_body="$(mktemp)"

authorize_url="$BASE_URL/oauth2/authorize?response_type=code&client_id=$(urlencode "$CLIENT_ID")&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=$(urlencode "$SCOPE")&state=$(urlencode "$STATE")&code_challenge=$(urlencode "$code_challenge")&code_challenge_method=S256"

auth_status="$(curl -sS -m "$TIMEOUT_SECONDS" -o "$auth_body" -D "$auth_headers" -w "%{http_code}" "$authorize_url" || true)"
if [[ "$auth_status" == "302" ]]; then
  pass "authorize endpoint status is 302"
else
  fail "authorize endpoint status is $auth_status"
fi

location="$(
  awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/^Location:[[:space:]]*/,""); print}' "$auth_headers" \
    | tr -d '\r' \
    | tail -n 1
)"
code="$(extract_query_param "$location" "code" || true)"
if [[ -n "$code" ]]; then
  pass "authorize redirect has code"
else
  fail "authorize redirect missing code"
fi

token_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$token_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" || true
)"
if [[ "$token_status" == "200" ]]; then
  pass "authorization_code exchange status is 200"
else
  fail "authorization_code exchange status is $token_status"
fi

refresh_token="$(jq -r '.refresh_token // empty' "$token_body")"
if [[ -n "$refresh_token" ]]; then
  pass "authorization_code exchange returns refresh_token"
else
  fail "authorization_code exchange must return refresh_token"
fi

refresh_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$refresh_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode "client_id=$CLIENT_ID" || true
)"
if [[ "$refresh_status" == "200" ]]; then
  pass "refresh_token exchange status is 200"
else
  fail "refresh_token exchange status is $refresh_status"
fi

rotated_refresh_token="$(jq -r '.refresh_token // empty' "$refresh_body")"
if [[ -n "$rotated_refresh_token" ]]; then
  pass "refresh_token exchange returns rotated refresh_token"
else
  fail "refresh_token exchange must return rotated refresh_token"
fi

if [[ "$rotated_refresh_token" != "$refresh_token" ]]; then
  pass "refresh_token is rotated"
else
  fail "refresh_token must be rotated"
fi

reuse_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$reuse_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode "client_id=$CLIENT_ID" || true
)"
if [[ "$reuse_status" == "400" ]]; then
  pass "reusing old refresh_token is rejected with 400"
else
  fail "reusing old refresh_token status is $reuse_status"
fi

if jq -e '.error == "invalid_grant"' "$reuse_body" >/dev/null 2>&1; then
  pass "refresh token reuse error is invalid_grant"
else
  fail "refresh token reuse error must be invalid_grant"
fi

rm -f "$auth_headers" "$auth_body" "$token_body" "$refresh_body" "$reuse_body"

if (( failures > 0 )); then
  printf "\nRefresh token rotation harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nRefresh token rotation harness passed.\n"
