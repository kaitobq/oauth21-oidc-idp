#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
PUBLIC_CLIENT_ID="${OIDC_DEV_CLIENT_ID:-local-dev-client}"
PUBLIC_REDIRECT_URI="${OIDC_DEV_REDIRECT_URI:-http://localhost:3000/callback}"
CONFIDENTIAL_CLIENT_ID="${OIDC_CONFIDENTIAL_CLIENT_ID:-local-confidential-client}"
CONFIDENTIAL_CLIENT_SECRET="${OIDC_CONFIDENTIAL_CLIENT_SECRET:-local-confidential-secret}"
CONFIDENTIAL_REDIRECT_URI="${OIDC_CONFIDENTIAL_REDIRECT_URI:-http://localhost:3000/callback}"
CODE_VERIFIER="${CODE_VERIFIER:-harness-token-error-contract-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"
STATE="${STATE:-harness-token-error-contract-state}"

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

oauth_error_contract() {
  local file="$1"
  local expected_error="$2"
  jq -e --arg expected_error "$expected_error" '
    (.error == $expected_error)
    and (.error_description | strings and (length > 0))
  ' "$file" >/dev/null 2>&1
}

error_description_safe() {
  local file="$1"
  jq -e '
    (.error_description | strings) as $d
    | ($d | ascii_downcase) as $ld
    | ($ld | contains("panic") or contains("stack") or contains("internal")) | not
  ' "$file" >/dev/null 2>&1
}

require_cmd curl
require_cmd jq
require_cmd openssl
require_cmd awk

info "BASE_URL=$BASE_URL"

code_challenge="$(
  printf "%s" "$CODE_VERIFIER" \
    | openssl dgst -binary -sha256 \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
)"

auth_headers="$(mktemp)"
auth_body="$(mktemp)"
invalid_client_body="$(mktemp)"
invalid_grant_body="$(mktemp)"
unsupported_grant_body="$(mktemp)"

authorize_url="$BASE_URL/oauth2/authorize?response_type=code&client_id=$(urlencode "$CONFIDENTIAL_CLIENT_ID")&redirect_uri=$(urlencode "$CONFIDENTIAL_REDIRECT_URI")&scope=$(urlencode "openid")&state=$(urlencode "$STATE")&code_challenge=$(urlencode "$code_challenge")&code_challenge_method=S256"

auth_status="$(curl -sS -m "$TIMEOUT_SECONDS" -o "$auth_body" -D "$auth_headers" -w "%{http_code}" "$authorize_url" || true)"
if [[ "$auth_status" == "302" ]]; then
  pass "authorize for confidential client returns 302"
else
  fail "authorize for confidential client status is $auth_status"
fi

location="$(
  awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/^Location:[[:space:]]*/,""); print}' "$auth_headers" \
    | tr -d '\r' \
    | tail -n 1
)"
code="$(extract_query_param "$location" "code" || true)"
if [[ -n "$code" ]]; then
  pass "authorize redirect includes code"
else
  fail "authorize redirect must include code"
fi

invalid_client_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$invalid_client_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Authorization: Basic $(printf "%s:%s" "$CONFIDENTIAL_CLIENT_ID" "wrong-secret" | openssl base64 -A)" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$CONFIDENTIAL_REDIRECT_URI" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" || true
)"
if [[ "$invalid_client_status" == "401" ]]; then
  pass "invalid basic credentials return 401"
else
  fail "invalid basic credentials status is $invalid_client_status"
fi
if oauth_error_contract "$invalid_client_body" "invalid_client"; then
  pass "invalid basic credentials return oauth error contract"
else
  fail "invalid basic credentials must return error + error_description"
fi
if error_description_safe "$invalid_client_body"; then
  pass "invalid basic credentials error_description does not expose internals"
else
  fail "invalid basic credentials error_description exposes internals"
fi

invalid_grant_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$invalid_grant_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=invalid-code" \
    --data-urlencode "redirect_uri=$PUBLIC_REDIRECT_URI" \
    --data-urlencode "client_id=$PUBLIC_CLIENT_ID" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" || true
)"
if [[ "$invalid_grant_status" == "400" ]]; then
  pass "invalid authorization code returns 400"
else
  fail "invalid authorization code status is $invalid_grant_status"
fi
if oauth_error_contract "$invalid_grant_body" "invalid_grant"; then
  pass "invalid authorization code returns oauth error contract"
else
  fail "invalid authorization code must return error + error_description"
fi
if error_description_safe "$invalid_grant_body"; then
  pass "invalid authorization code error_description does not expose internals"
else
  fail "invalid authorization code error_description exposes internals"
fi

unsupported_grant_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$unsupported_grant_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=$PUBLIC_CLIENT_ID" || true
)"
if [[ "$unsupported_grant_status" == "400" ]]; then
  pass "unsupported grant_type returns 400"
else
  fail "unsupported grant_type status is $unsupported_grant_status"
fi
if oauth_error_contract "$unsupported_grant_body" "unsupported_grant_type"; then
  pass "unsupported grant_type returns oauth error contract"
else
  fail "unsupported grant_type must return error + error_description"
fi
if error_description_safe "$unsupported_grant_body"; then
  pass "unsupported grant_type error_description does not expose internals"
else
  fail "unsupported grant_type error_description exposes internals"
fi

rm -f "$auth_headers" "$auth_body" "$invalid_client_body" "$invalid_grant_body" "$unsupported_grant_body"

if (( failures > 0 )); then
  printf "\nToken error contract harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nToken error contract harness passed.\n"
