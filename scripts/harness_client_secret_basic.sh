#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_CONFIDENTIAL_CLIENT_ID:-local-confidential-client}"
CLIENT_SECRET="${OIDC_CONFIDENTIAL_CLIENT_SECRET:-local-confidential-secret}"
REDIRECT_URI="${OIDC_CONFIDENTIAL_REDIRECT_URI:-http://localhost:3000/callback}"
SCOPE="${SCOPE:-openid profile}"
STATE="${STATE:-harness-confidential-state}"
CODE_VERIFIER="${CODE_VERIFIER:-harness-confidential-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"

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

auth_header="Basic $(printf "%s" "$CLIENT_ID:$CLIENT_SECRET" | openssl base64 -A)"
invalid_auth_header="Basic $(printf "%s" "$CLIENT_ID:invalid-secret" | openssl base64 -A)"

info "BASE_URL=$BASE_URL"
info "CLIENT_ID=$CLIENT_ID"
info "REDIRECT_URI=$REDIRECT_URI"

auth_headers="$(mktemp)"
auth_body="$(mktemp)"
token_body="$(mktemp)"
invalid_body="$(mktemp)"

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

invalid_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$invalid_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Authorization: $invalid_auth_header" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" || true
)"
if [[ "$invalid_status" == "401" ]]; then
  pass "invalid basic credentials are rejected with 401"
else
  fail "invalid basic credentials status is $invalid_status"
fi
if jq -e '.error == "invalid_client"' "$invalid_body" >/dev/null 2>&1; then
  pass "invalid basic credentials return invalid_client"
else
  fail "invalid basic credentials must return invalid_client"
fi

token_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$token_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Authorization: $auth_header" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" || true
)"
if [[ "$token_status" == "200" ]]; then
  pass "valid basic credentials return 200"
else
  fail "valid basic credentials status is $token_status"
fi

if jq -e '.access_token | strings and length > 0' "$token_body" >/dev/null 2>&1; then
  pass "token response has access_token"
else
  fail "token response missing access_token"
fi

if jq -e '.id_token | strings and length > 0' "$token_body" >/dev/null 2>&1; then
  pass "token response has id_token"
else
  fail "token response missing id_token"
fi

rm -f "$auth_headers" "$auth_body" "$token_body" "$invalid_body"

if (( failures > 0 )); then
  printf "\nClient Secret Basic harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nClient Secret Basic harness passed.\n"
