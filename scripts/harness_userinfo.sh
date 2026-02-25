#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_DEV_CLIENT_ID:-local-dev-client}"
REDIRECT_URI="${OIDC_DEV_REDIRECT_URI:-http://localhost:3000/callback}"
OPENID_SCOPE="${OPENID_SCOPE:-openid profile email}"
NO_OPENID_SCOPE="${NO_OPENID_SCOPE:-profile}"
STATE="${STATE:-userinfo-state}"
CODE_VERIFIER="${CODE_VERIFIER:-userinfo-code-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"

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
userinfo_headers="$(mktemp)"
userinfo_body="$(mktemp)"
token_no_openid_body="$(mktemp)"
userinfo_no_openid_headers="$(mktemp)"
userinfo_no_openid_body="$(mktemp)"

authorize_openid_url="$BASE_URL/oauth2/authorize?response_type=code&client_id=$(urlencode "$CLIENT_ID")&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=$(urlencode "$OPENID_SCOPE")&state=$(urlencode "$STATE")&code_challenge=$(urlencode "$code_challenge")&code_challenge_method=S256"

auth_status="$(curl -sS -m "$TIMEOUT_SECONDS" -o "$auth_body" -D "$auth_headers" -w "%{http_code}" "$authorize_openid_url" || true)"
if [[ "$auth_status" == "302" ]]; then
  pass "authorize endpoint status is 302 for openid scope"
else
  fail "authorize endpoint status is $auth_status for openid scope"
fi

location="$(
  awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/^Location:[[:space:]]*/,""); print}' "$auth_headers" \
    | tr -d '\r' \
    | tail -n 1
)"
code="$(extract_query_param "$location" "code" || true)"
if [[ -n "$code" ]]; then
  pass "authorize redirect has code for openid scope"
else
  fail "authorize redirect missing code for openid scope"
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
  pass "token endpoint status is 200 for openid scope"
else
  fail "token endpoint status is $token_status for openid scope"
fi

access_token="$(jq -r '.access_token // empty' "$token_body")"
if [[ -n "$access_token" ]]; then
  pass "token response has access_token for openid scope"
else
  fail "token response missing access_token for openid scope"
fi

userinfo_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$userinfo_body" -D "$userinfo_headers" -w "%{http_code}" \
    -H "Authorization: Bearer $access_token" \
    "$BASE_URL/oauth2/userinfo" || true
)"
if [[ "$userinfo_status" == "200" ]]; then
  pass "userinfo status is 200 with valid openid token"
else
  fail "userinfo status is $userinfo_status with valid openid token"
fi

if jq -e '.sub | strings and length > 0' "$userinfo_body" >/dev/null 2>&1; then
  pass "userinfo response includes sub"
else
  fail "userinfo response missing sub"
fi
if jq -e '.name | strings and length > 0' "$userinfo_body" >/dev/null 2>&1; then
  pass "userinfo response includes name for profile scope"
else
  fail "userinfo response missing name for profile scope"
fi
if jq -e '.email | strings and length > 0' "$userinfo_body" >/dev/null 2>&1; then
  pass "userinfo response includes email for email scope"
else
  fail "userinfo response missing email for email scope"
fi

invalid_userinfo_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$userinfo_body" -D "$userinfo_headers" -w "%{http_code}" \
    -H "Authorization: Bearer invalid-access-token" \
    "$BASE_URL/oauth2/userinfo" || true
)"
if [[ "$invalid_userinfo_status" == "401" ]]; then
  pass "userinfo rejects invalid access token with 401"
else
  fail "userinfo invalid token status is $invalid_userinfo_status"
fi
if jq -e '.error == "invalid_token"' "$userinfo_body" >/dev/null 2>&1; then
  pass "userinfo invalid token error is invalid_token"
else
  fail "userinfo invalid token error must be invalid_token"
fi
if grep -qi '^WWW-Authenticate: Bearer ' "$userinfo_headers"; then
  pass "userinfo invalid token response has WWW-Authenticate Bearer header"
else
  fail "userinfo invalid token response missing WWW-Authenticate Bearer header"
fi

authorize_no_openid_url="$BASE_URL/oauth2/authorize?response_type=code&client_id=$(urlencode "$CLIENT_ID")&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=$(urlencode "$NO_OPENID_SCOPE")&state=$(urlencode "$STATE-no-openid")&code_challenge=$(urlencode "$code_challenge")&code_challenge_method=S256"
auth_status_no_openid="$(curl -sS -m "$TIMEOUT_SECONDS" -o "$auth_body" -D "$auth_headers" -w "%{http_code}" "$authorize_no_openid_url" || true)"
if [[ "$auth_status_no_openid" == "302" ]]; then
  pass "authorize endpoint status is 302 for no-openid scope"
else
  fail "authorize endpoint status is $auth_status_no_openid for no-openid scope"
fi
location_no_openid="$(
  awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/^Location:[[:space:]]*/,""); print}' "$auth_headers" \
    | tr -d '\r' \
    | tail -n 1
)"
code_no_openid="$(extract_query_param "$location_no_openid" "code" || true)"

token_no_openid_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$token_no_openid_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code_no_openid" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" || true
)"
if [[ "$token_no_openid_status" == "200" ]]; then
  pass "token endpoint status is 200 for no-openid scope"
else
  fail "token endpoint status is $token_no_openid_status for no-openid scope"
fi

no_openid_access_token="$(jq -r '.access_token // empty' "$token_no_openid_body")"
userinfo_no_openid_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$userinfo_no_openid_body" -D "$userinfo_no_openid_headers" -w "%{http_code}" \
    -H "Authorization: Bearer $no_openid_access_token" \
    "$BASE_URL/oauth2/userinfo" || true
)"
if [[ "$userinfo_no_openid_status" == "403" ]]; then
  pass "userinfo rejects token without openid scope with 403"
else
  fail "userinfo no-openid scope status is $userinfo_no_openid_status"
fi
if jq -e '.error == "insufficient_scope"' "$userinfo_no_openid_body" >/dev/null 2>&1; then
  pass "userinfo no-openid scope error is insufficient_scope"
else
  fail "userinfo no-openid scope error must be insufficient_scope"
fi
if grep -qi '^WWW-Authenticate: Bearer ' "$userinfo_no_openid_headers"; then
  pass "userinfo insufficient scope response has WWW-Authenticate Bearer header"
else
  fail "userinfo insufficient scope response missing WWW-Authenticate Bearer header"
fi

rm -f \
  "$auth_headers" "$auth_body" "$token_body" "$userinfo_headers" "$userinfo_body" \
  "$token_no_openid_body" "$userinfo_no_openid_headers" "$userinfo_no_openid_body"

if (( failures > 0 )); then
  printf "\nUserInfo harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nUserInfo harness passed.\n"
