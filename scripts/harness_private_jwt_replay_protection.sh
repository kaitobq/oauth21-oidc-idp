#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_PRIVATE_JWT_CLIENT_ID:-local-private-jwt-client}"
REDIRECT_URI="${OIDC_PRIVATE_JWT_REDIRECT_URI:-http://localhost:3000/callback}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIVATE_KEY_PATH="${OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH:-$SCRIPT_DIR/../harness/keys/local/private_jwt_client_private.pem}"
SCOPE="${SCOPE:-openid profile}"
STATE_PREFIX="${STATE_PREFIX:-harness-private-jwt-replay}"
CODE_VERIFIER="${CODE_VERIFIER:-harness-private-jwt-replay-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"
CLIENT_ASSERTION_TYPE="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

failures=0
state_counter=0

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

create_client_assertion_with_jti() {
  local private_key_file="$1"
  local audience="$2"
  local jti="$3"
  local now exp header payload signing_input signature
  now="$(date +%s)"
  exp="$((now + 300))"

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

authorize_code() {
  local state="$STATE_PREFIX-$state_counter"
  state_counter=$((state_counter + 1))
  local code_challenge authorize_url auth_headers auth_body auth_status location code

  code_challenge="$(
    printf "%s" "$CODE_VERIFIER" \
      | openssl dgst -binary -sha256 \
      | openssl base64 -A \
      | tr '+/' '-_' \
      | tr -d '='
  )"
  authorize_url="$BASE_URL/oauth2/authorize?response_type=code&client_id=$(urlencode "$CLIENT_ID")&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=$(urlencode "$SCOPE")&state=$(urlencode "$state")&code_challenge=$(urlencode "$code_challenge")&code_challenge_method=S256"

  auth_headers="$(mktemp)"
  auth_body="$(mktemp)"
  auth_status="$(curl -sS -m "$TIMEOUT_SECONDS" -o "$auth_body" -D "$auth_headers" -w "%{http_code}" "$authorize_url" || true)"
  if [[ "$auth_status" != "302" ]]; then
    rm -f "$auth_headers" "$auth_body"
    return 1
  fi

  location="$(
    awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/^Location:[[:space:]]*/,""); print}' "$auth_headers" \
      | tr -d '\r' \
      | tail -n 1
  )"
  code="$(extract_query_param "$location" "code" || true)"
  rm -f "$auth_headers" "$auth_body"
  if [[ -z "$code" ]]; then
    return 1
  fi
  printf "%s" "$code"
}

token_exchange() {
  local code="$1"
  local assertion="$2"
  local output_file="$3"

  curl -sS -m "$TIMEOUT_SECONDS" -o "$output_file" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$REDIRECT_URI" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "code_verifier=$CODE_VERIFIER" \
    --data-urlencode "client_assertion_type=$CLIENT_ASSERTION_TYPE" \
    --data-urlencode "client_assertion=$assertion" || true
}

require_cmd curl
require_cmd jq
require_cmd openssl
require_cmd awk

if [[ ! -f "$PRIVATE_KEY_PATH" ]]; then
  echo "[ERROR] private key file not found: $PRIVATE_KEY_PATH" >&2
  echo "[ERROR] run: make gen-private-jwt-dev-keys" >&2
  exit 2
fi

info "BASE_URL=$BASE_URL"
info "CLIENT_ID=$CLIENT_ID"
info "REDIRECT_URI=$REDIRECT_URI"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

token_first="$tmpdir/token_first.json"
token_replay="$tmpdir/token_replay.json"

code1="$(authorize_code || true)"
code2="$(authorize_code || true)"
if [[ -n "$code1" && -n "$code2" ]]; then
  pass "issued two authorization codes for replay check"
else
  fail "failed to issue authorization codes for replay check"
fi

assertion_jti="replay-jti-$(openssl rand -hex 12)"
shared_assertion="$(create_client_assertion_with_jti "$PRIVATE_KEY_PATH" "$BASE_URL/oauth2/token" "$assertion_jti")"

first_status="$(token_exchange "$code1" "$shared_assertion" "$token_first")"
if [[ "$first_status" == "200" ]]; then
  pass "first private_key_jwt assertion usage succeeds"
else
  fail "first private_key_jwt assertion usage status is $first_status"
fi

replay_status="$(token_exchange "$code2" "$shared_assertion" "$token_replay")"
if [[ "$replay_status" == "401" ]]; then
  pass "replayed private_key_jwt assertion is rejected with 401"
else
  fail "replayed private_key_jwt assertion status is $replay_status"
fi
if jq -e '.error == "invalid_client"' "$token_replay" >/dev/null 2>&1; then
  pass "replayed private_key_jwt assertion returns invalid_client"
else
  fail "replayed private_key_jwt assertion must return invalid_client"
fi

if (( failures > 0 )); then
  printf "\nPrivate JWT replay protection harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nPrivate JWT replay protection harness passed.\n"
