#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_PRIVATE_JWT_CLIENT_ID:-local-private-jwt-client}"
REDIRECT_URI="${OIDC_PRIVATE_JWT_REDIRECT_URI:-http://localhost:3000/callback}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIVATE_KEY_PATH="${OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH:-$SCRIPT_DIR/../harness/keys/dev/private_jwt_client_private.pem}"
SCOPE="${SCOPE:-openid profile}"
STATE="${STATE:-harness-private-jwt-state}"
CODE_VERIFIER="${CODE_VERIFIER:-harness-private-jwt-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"
CLIENT_ASSERTION_TYPE="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

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

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

create_client_assertion() {
  local audience="$1"
  local now exp header payload signing_input signature jti
  now="$(date +%s)"
  exp="$((now + 300))"
  jti="$(openssl rand -hex 16)"

  header='{"alg":"RS256","typ":"JWT"}'
  payload="$(
    jq -cn \
      --arg iss "$CLIENT_ID" \
      --arg sub "$CLIENT_ID" \
      --arg aud "$audience" \
      --arg iat "$now" \
      --arg exp "$exp" \
      --arg jti "$jti" \
      '{iss:$iss,sub:$sub,aud:$aud,iat:($iat|tonumber),exp:($exp|tonumber),jti:$jti}'
  )"

  signing_input="$(printf "%s" "$header" | base64url).$(printf "%s" "$payload" | base64url)"
  signature="$(
    printf "%s" "$signing_input" \
      | openssl dgst -binary -sha256 -sign "$private_key_file" \
      | base64url
  )"
  printf "%s.%s" "$signing_input" "$signature"
}

require_cmd curl
require_cmd jq
require_cmd openssl

if [[ ! -f "$PRIVATE_KEY_PATH" ]]; then
  echo "[ERROR] private key file not found: $PRIVATE_KEY_PATH" >&2
  exit 2
fi
private_key_file="$PRIVATE_KEY_PATH"

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

invalid_assertion="$(create_client_assertion "http://invalid.example/token")"
invalid_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$invalid_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" \
    --data-urlencode "client_assertion_type=$CLIENT_ASSERTION_TYPE" \
    --data-urlencode "client_assertion=$invalid_assertion" || true
)"
if [[ "$invalid_status" == "401" ]]; then
  pass "invalid private_key_jwt assertion is rejected with 401"
else
  fail "invalid private_key_jwt assertion status is $invalid_status"
fi
if jq -e '.error == "invalid_client"' "$invalid_body" >/dev/null 2>&1; then
  pass "invalid private_key_jwt assertion returns invalid_client"
else
  fail "invalid private_key_jwt assertion must return invalid_client"
fi

valid_assertion="$(create_client_assertion "$BASE_URL/oauth2/token")"
token_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$token_body" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" \
    --data-urlencode "client_assertion_type=$CLIENT_ASSERTION_TYPE" \
    --data-urlencode "client_assertion=$valid_assertion" || true
)"
if [[ "$token_status" == "200" ]]; then
  pass "valid private_key_jwt assertion returns 200"
else
  fail "valid private_key_jwt assertion status is $token_status"
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
  printf "\nPrivate Key JWT harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nPrivate Key JWT harness passed.\n"
