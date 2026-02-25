#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"

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

json_has_field() {
  local file="$1"
  local field="$2"
  jq -e --arg field "$field" 'has($field)' "$file" >/dev/null 2>&1
}

json_array_contains() {
  local file="$1"
  local field="$2"
  local value="$3"
  jq -e --arg field "$field" --arg value "$value" '(.[$field] | arrays) and ((.[$field] | index($value)) != null)' "$file" >/dev/null 2>&1
}

require_cmd curl
require_cmd jq

info "BASE_URL=$BASE_URL"

discovery_body="$(mktemp)"
status="$(fetch "$BASE_URL/.well-known/openid-configuration" "$discovery_body")"

if [[ "$status" == "200" ]]; then
  pass "discovery endpoint status is 200"
else
  fail "discovery endpoint status is $status"
fi

if jq -e . "$discovery_body" >/dev/null 2>&1; then
  pass "discovery response is valid JSON"
else
  fail "discovery response is not valid JSON"
fi

for field in issuer jwks_uri authorization_endpoint token_endpoint response_types_supported grant_types_supported code_challenge_methods_supported; do
  if json_has_field "$discovery_body" "$field"; then
    pass "discovery has field: $field"
  else
    fail "discovery missing field: $field"
  fi
done

if json_array_contains "$discovery_body" "token_endpoint_auth_methods_supported" "none"; then
  pass "token_endpoint_auth_methods_supported includes none"
else
  fail "token_endpoint_auth_methods_supported must include none"
fi

if json_array_contains "$discovery_body" "token_endpoint_auth_methods_supported" "client_secret_basic"; then
  pass "token_endpoint_auth_methods_supported includes client_secret_basic"
else
  fail "token_endpoint_auth_methods_supported must include client_secret_basic"
fi

if json_array_contains "$discovery_body" "token_endpoint_auth_methods_supported" "private_key_jwt"; then
  pass "token_endpoint_auth_methods_supported includes private_key_jwt"
else
  fail "token_endpoint_auth_methods_supported must include private_key_jwt"
fi

if json_array_contains "$discovery_body" "grant_types_supported" "authorization_code"; then
  pass "grant_types_supported includes authorization_code"
else
  fail "grant_types_supported must include authorization_code"
fi

if json_array_contains "$discovery_body" "code_challenge_methods_supported" "S256"; then
  pass "code_challenge_methods_supported includes S256"
else
  fail "code_challenge_methods_supported must include S256"
fi

if json_array_contains "$discovery_body" "grant_types_supported" "password"; then
  fail "grant_types_supported must not include password"
else
  pass "grant_types_supported does not include password"
fi

if json_array_contains "$discovery_body" "response_types_supported" "token"; then
  fail "response_types_supported must not include implicit token"
else
  pass "response_types_supported does not include implicit token"
fi

if json_array_contains "$discovery_body" "response_types_supported" "id_token"; then
  fail "response_types_supported must not include implicit id_token"
else
  pass "response_types_supported does not include implicit id_token"
fi

if json_array_contains "$discovery_body" "scopes_supported" "openid"; then
  pass "scopes_supported includes openid"
else
  fail "scopes_supported must include openid"
fi

jwks_uri="$(jq -r '.jwks_uri // empty' "$discovery_body")"
if [[ -z "$jwks_uri" ]]; then
  fail "jwks_uri is empty"
else
  pass "jwks_uri is present"
fi

jwks_body="$(mktemp)"
if [[ -n "$jwks_uri" ]]; then
  jwks_status="$(fetch "$jwks_uri" "$jwks_body")"
  if [[ "$jwks_status" == "200" ]]; then
    pass "jwks endpoint status is 200"
  else
    fail "jwks endpoint status is $jwks_status"
  fi

  if jq -e '.keys | arrays and (length > 0)' "$jwks_body" >/dev/null 2>&1; then
    pass "jwks has non-empty keys array"
  else
    fail "jwks must have non-empty keys array"
  fi
fi

rm -f "$discovery_body" "$jwks_body"

if (( failures > 0 )); then
  printf "\nSmoke harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nSmoke harness passed.\n"
