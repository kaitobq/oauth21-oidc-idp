#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_PRIVATE_JWT_CLIENT_ID:-local-private-jwt-client}"
REDIRECT_URI="${OIDC_PRIVATE_JWT_REDIRECT_URI:-http://localhost:3000/callback}"
ROTATION_TOKEN="${OIDC_PRIVATE_JWT_KEY_ROTATION_TOKEN:-dev-private-jwt-key-rotation-token}"
ROTATE_PATH="${ROTATE_PATH:-/oauth2/admin/rotate-private-jwt-client-key}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_PRIVATE_KEY_PATH="${OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH:-$SCRIPT_DIR/../harness/keys/local/private_jwt_client_private.pem}"
SCOPE="${SCOPE:-openid profile}"
STATE_PREFIX="${STATE_PREFIX:-harness-private-jwt-key-rotation}"
CODE_VERIFIER="${CODE_VERIFIER:-harness-private-jwt-key-rotation-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"
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

create_client_assertion() {
  local private_key_file="$1"
  local audience="$2"
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

token_exchange_with_private_key() {
  local private_key_file="$1"
  local output_file="$2"
  local code assertion status

  code="$(authorize_code || true)"
  if [[ -z "$code" ]]; then
    printf "000"
    return 0
  fi
  assertion="$(create_client_assertion "$private_key_file" "$BASE_URL/oauth2/token")"

  status="$(
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
  )"
  printf "%s" "$status"
}

generate_key_pair() {
  local private_key_file="$1"
  local public_key_file="$2"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$private_key_file" >/dev/null 2>&1
  openssl pkey -in "$private_key_file" -pubout -out "$public_key_file" >/dev/null 2>&1
}

rotate_private_jwt_key() {
  local public_key_file="$1"
  local output_file="$2"
  local payload

  payload="$(
    jq -cn \
      --arg client_id "$CLIENT_ID" \
      --arg public_key_pem "$(cat "$public_key_file")" \
      '{client_id:$client_id, public_key_pem:$public_key_pem}'
  )"
  curl -sS -m "$TIMEOUT_SECONDS" -o "$output_file" -w "%{http_code}" \
    -X POST "$BASE_URL$ROTATE_PATH" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ROTATION_TOKEN" \
    --data "$payload" || true
}

require_cmd curl
require_cmd jq
require_cmd openssl
require_cmd awk

if [[ ! -f "$BASELINE_PRIVATE_KEY_PATH" ]]; then
  echo "[ERROR] baseline private key file not found: $BASELINE_PRIVATE_KEY_PATH" >&2
  echo "[ERROR] run: make gen-private-jwt-dev-keys" >&2
  exit 2
fi

info "BASE_URL=$BASE_URL"
info "CLIENT_ID=$CLIENT_ID"
info "REDIRECT_URI=$REDIRECT_URI"
info "ROTATE_PATH=$ROTATE_PATH"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

token_body="$tmpdir/token.json"
rotate_body="$tmpdir/rotate.json"
unauthorized_rotate_body="$tmpdir/rotate_unauthorized.json"
key2_private="$tmpdir/key2_private.pem"
key2_public="$tmpdir/key2_public.pem"
key3_private="$tmpdir/key3_private.pem"
key3_public="$tmpdir/key3_public.pem"

baseline_status="$(token_exchange_with_private_key "$BASELINE_PRIVATE_KEY_PATH" "$token_body")"
if [[ "$baseline_status" == "200" ]]; then
  pass "baseline private_key_jwt assertion succeeds"
else
  fail "baseline private_key_jwt assertion status is $baseline_status"
fi

unauthorized_rotate_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$unauthorized_rotate_body" -w "%{http_code}" \
    -X POST "$BASE_URL$ROTATE_PATH" \
    -H "Content-Type: application/json" \
    --data '{"client_id":"'"$CLIENT_ID"'","public_key_pem":"invalid"}' || true
)"
if [[ "$unauthorized_rotate_status" == "401" ]]; then
  pass "rotate endpoint rejects missing bearer token with 401"
else
  fail "rotate endpoint missing bearer token status is $unauthorized_rotate_status"
fi

generate_key_pair "$key2_private" "$key2_public"
rotate_status="$(rotate_private_jwt_key "$key2_public" "$rotate_body")"
if [[ "$rotate_status" == "200" ]]; then
  pass "first private_jwt key rotation succeeds"
elif [[ "$rotate_status" == "404" ]]; then
  fail "rotate endpoint is disabled (set OIDC_ENABLE_PRIVATE_JWT_KEY_ROTATION_API=true)"
else
  fail "first private_jwt key rotation status is $rotate_status"
fi
if jq -e '.kid | strings and length > 0' "$rotate_body" >/dev/null 2>&1; then
  pass "first private_jwt key rotation returns kid"
else
  fail "first private_jwt key rotation must return kid"
fi

new_key_status="$(token_exchange_with_private_key "$key2_private" "$token_body")"
if [[ "$new_key_status" == "200" ]]; then
  pass "new private_jwt key is accepted after first rotation"
else
  fail "new private_jwt key status after first rotation is $new_key_status"
fi

old_key_grace_status="$(token_exchange_with_private_key "$BASELINE_PRIVATE_KEY_PATH" "$token_body")"
if [[ "$old_key_grace_status" == "200" ]]; then
  pass "previous private_jwt key remains valid during grace window"
else
  fail "previous private_jwt key status during grace window is $old_key_grace_status"
fi

generate_key_pair "$key3_private" "$key3_public"
second_rotate_status="$(rotate_private_jwt_key "$key3_public" "$rotate_body")"
if [[ "$second_rotate_status" == "200" ]]; then
  pass "second private_jwt key rotation succeeds"
else
  fail "second private_jwt key rotation status is $second_rotate_status"
fi

latest_key_status="$(token_exchange_with_private_key "$key3_private" "$token_body")"
if [[ "$latest_key_status" == "200" ]]; then
  pass "latest private_jwt key is accepted after second rotation"
else
  fail "latest private_jwt key status after second rotation is $latest_key_status"
fi

prev_key_status="$(token_exchange_with_private_key "$key2_private" "$token_body")"
if [[ "$prev_key_status" == "200" ]]; then
  pass "immediately previous private_jwt key remains valid after second rotation"
else
  fail "immediately previous private_jwt key status after second rotation is $prev_key_status"
fi

evicted_key_status="$(token_exchange_with_private_key "$BASELINE_PRIVATE_KEY_PATH" "$token_body")"
if [[ "$evicted_key_status" == "401" ]]; then
  pass "oldest private_jwt key is rejected after exceeding rotation window"
else
  fail "oldest private_jwt key status after second rotation is $evicted_key_status"
fi
if jq -e '.error == "invalid_client"' "$token_body" >/dev/null 2>&1; then
  pass "rejected oldest key returns invalid_client"
else
  fail "rejected oldest key must return invalid_client"
fi

if (( failures > 0 )); then
  printf "\nPrivate JWT key rotation harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nPrivate JWT key rotation harness passed.\n"
