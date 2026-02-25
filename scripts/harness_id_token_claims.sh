#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_DEV_CLIENT_ID:-local-dev-client}"
REDIRECT_URI="${OIDC_DEV_REDIRECT_URI:-http://localhost:3000/callback}"
SCOPE="${SCOPE:-openid offline_access}"
STATE="${STATE:-id-token-claims-state}"
NONCE="${NONCE:-id-token-claims-nonce-123}"
CODE_VERIFIER="${CODE_VERIFIER:-id-token-claims-verifier-1234567890abcdefghijklmnopqrstuvwxyz}"

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

decode_base64url() {
  local input="$1"
  local b64="${input//-/+}"
  b64="${b64//_/\/}"

  case $(( ${#b64} % 4 )) in
    0) ;;
    2) b64="${b64}==" ;;
    3) b64="${b64}=" ;;
    1) return 1 ;;
  esac

  printf "%s" "$b64" | openssl base64 -d -A
}

jwt_payload() {
  local jwt="$1"
  local payload

  IFS='.' read -r _ payload _ <<< "$jwt"
  if [[ -z "${payload:-}" ]]; then
    return 1
  fi
  decode_base64url "$payload"
}

access_token_hash() {
  local token="$1"
  printf "%s" "$token" \
    | openssl dgst -binary -sha256 \
    | head -c 16 \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
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
info "NONCE=$NONCE"

auth_headers="$(mktemp)"
auth_body="$(mktemp)"
token_body="$(mktemp)"
refresh_body="$(mktemp)"

authorize_url="$BASE_URL/oauth2/authorize?response_type=code&client_id=$(urlencode "$CLIENT_ID")&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=$(urlencode "$SCOPE")&state=$(urlencode "$STATE")&nonce=$(urlencode "$NONCE")&code_challenge=$(urlencode "$code_challenge")&code_challenge_method=S256"

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

access_token="$(jq -r '.access_token // empty' "$token_body")"
id_token="$(jq -r '.id_token // empty' "$token_body")"
refresh_token="$(jq -r '.refresh_token // empty' "$token_body")"
if [[ -n "$access_token" ]]; then
  pass "authorization_code exchange returns access_token"
else
  fail "authorization_code exchange must return access_token"
fi
if [[ -n "$id_token" ]]; then
  pass "authorization_code exchange returns id_token"
else
  fail "authorization_code exchange must return id_token"
fi
if [[ -n "$refresh_token" ]]; then
  pass "authorization_code exchange returns refresh_token"
else
  fail "authorization_code exchange must return refresh_token"
fi

id_claims_file="$(mktemp)"
if jwt_payload "$id_token" > "$id_claims_file"; then
  pass "id_token payload decoded"
else
  fail "id_token payload decode failed"
fi
if jq -e --arg nonce "$NONCE" '.nonce == $nonce' "$id_claims_file" >/dev/null 2>&1; then
  pass "id_token includes nonce"
else
  fail "id_token nonce mismatch"
fi
if jq -e '.auth_time | numbers' "$id_claims_file" >/dev/null 2>&1; then
  pass "id_token includes numeric auth_time"
else
  fail "id_token missing numeric auth_time"
fi
expected_at_hash="$(access_token_hash "$access_token")"
if jq -e --arg at_hash "$expected_at_hash" '.at_hash == $at_hash' "$id_claims_file" >/dev/null 2>&1; then
  pass "id_token includes valid at_hash"
else
  fail "id_token at_hash mismatch"
fi

auth_time="$(jq -r '.auth_time // empty' "$id_claims_file")"

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

refresh_access_token="$(jq -r '.access_token // empty' "$refresh_body")"
refresh_id_token="$(jq -r '.id_token // empty' "$refresh_body")"
if [[ -n "$refresh_access_token" ]]; then
  pass "refresh_token exchange returns access_token"
else
  fail "refresh_token exchange must return access_token"
fi
if [[ -n "$refresh_id_token" ]]; then
  pass "refresh_token exchange returns id_token"
else
  fail "refresh_token exchange must return id_token"
fi

refresh_claims_file="$(mktemp)"
if jwt_payload "$refresh_id_token" > "$refresh_claims_file"; then
  pass "refresh id_token payload decoded"
else
  fail "refresh id_token payload decode failed"
fi
if jq -e 'has("nonce") | not' "$refresh_claims_file" >/dev/null 2>&1; then
  pass "refresh id_token does not include nonce"
else
  fail "refresh id_token must not include nonce"
fi
if jq -e --arg auth_time "$auth_time" '.auth_time | tostring == $auth_time' "$refresh_claims_file" >/dev/null 2>&1; then
  pass "refresh id_token preserves auth_time"
else
  fail "refresh id_token auth_time mismatch"
fi
expected_refresh_at_hash="$(access_token_hash "$refresh_access_token")"
if jq -e --arg at_hash "$expected_refresh_at_hash" '.at_hash == $at_hash' "$refresh_claims_file" >/dev/null 2>&1; then
  pass "refresh id_token includes valid at_hash"
else
  fail "refresh id_token at_hash mismatch"
fi

rm -f "$auth_headers" "$auth_body" "$token_body" "$refresh_body" "$id_claims_file" "$refresh_claims_file"

if (( failures > 0 )); then
  printf "\nID Token claims harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nID Token claims harness passed.\n"
