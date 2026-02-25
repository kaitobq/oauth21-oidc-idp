#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
ADMIN_JWT_SECRET="${OIDC_ADMIN_JWT_HS256_SECRET:-dev-admin-jwt-secret}"
ADMIN_JWT_ISS="${OIDC_ADMIN_JWT_ISS:-harness-admin}"
ADMIN_JWT_AUD="${OIDC_ADMIN_JWT_AUD:-oidc-admin}"

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

b64url_encode() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

sign_hs256() {
  local input="$1"
  printf "%s" "$input" \
    | openssl dgst -binary -sha256 -hmac "$ADMIN_JWT_SECRET" \
    | b64url_encode
}

build_jwt() {
  local scope="$1"
  local exp
  exp=$(( $(date +%s) + 300 ))
  local jti
  jti="harness-admin-$(date +%s)-$(openssl rand -hex 8)-${scope//[^a-zA-Z0-9]/_}"

  local header payload header_enc payload_enc signing_input signature
  header='{"alg":"HS256","typ":"JWT"}'
  payload="$(jq -cn \
    --arg iss "$ADMIN_JWT_ISS" \
    --arg aud "$ADMIN_JWT_AUD" \
    --arg scope "$scope" \
    --arg jti "$jti" \
    --argjson exp "$exp" \
    '{iss:$iss,aud:$aud,scope:$scope,jti:$jti,exp:$exp}')"

  header_enc="$(printf "%s" "$header" | b64url_encode)"
  payload_enc="$(printf "%s" "$payload" | b64url_encode)"
  signing_input="${header_enc}.${payload_enc}"
  signature="$(sign_hs256 "$signing_input")"
  printf "%s.%s" "$signing_input" "$signature"
}

require_cmd curl
require_cmd jq
require_cmd openssl
require_cmd date

info "BASE_URL=$BASE_URL"
info "ADMIN_JWT_ISS=$ADMIN_JWT_ISS"
info "ADMIN_JWT_AUD=$ADMIN_JWT_AUD"

invalid_scope_body="$(mktemp)"
invalid_scope_headers="$(mktemp)"
valid_body="$(mktemp)"
valid_headers="$(mktemp)"

invalid_scope_token="$(build_jwt "oidc.admin.rotate_private_jwt_client_key")"
invalid_scope_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$invalid_scope_body" -D "$invalid_scope_headers" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/admin/rotate-signing-key" \
    -H "Authorization: Bearer $invalid_scope_token" || true
)"
if [[ "$invalid_scope_status" == "403" ]]; then
  pass "admin JWT with insufficient scope is rejected with 403"
else
  fail "admin JWT with insufficient scope status is $invalid_scope_status"
fi
if jq -e '.error == "forbidden"' "$invalid_scope_body" >/dev/null 2>&1; then
  pass "insufficient scope returns error=forbidden"
else
  fail "insufficient scope must return error=forbidden"
fi

valid_token="$(build_jwt "oidc.admin.rotate_signing_key")"
valid_status="$(
  curl -sS -m "$TIMEOUT_SECONDS" -o "$valid_body" -D "$valid_headers" -w "%{http_code}" \
    -X POST "$BASE_URL/oauth2/admin/rotate-signing-key" \
    -H "Authorization: Bearer $valid_token" || true
)"
if [[ "$valid_status" == "200" ]]; then
  pass "admin JWT with rotate_signing_key scope is accepted"
else
  fail "admin JWT with rotate_signing_key scope status is $valid_status"
fi
if jq -e '.kid | strings and length > 0' "$valid_body" >/dev/null 2>&1; then
  pass "rotate-signing-key returns kid"
else
  fail "rotate-signing-key response missing kid"
fi

rm -f "$invalid_scope_body" "$invalid_scope_headers" "$valid_body" "$valid_headers"

if (( failures > 0 )); then
  printf "\nAdmin JWT auth harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nAdmin JWT auth harness passed.\n"
