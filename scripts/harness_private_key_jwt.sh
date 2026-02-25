#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLIENT_ID="${OIDC_PRIVATE_JWT_CLIENT_ID:-local-private-jwt-client}"
REDIRECT_URI="${OIDC_PRIVATE_JWT_REDIRECT_URI:-http://localhost:3000/callback}"
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

private_key_file="$(mktemp)"
cat > "$private_key_file" <<'EOF'
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC0qNCu6+wFHoKW
3vdWz8mu8ebY7tA/z9ukz4b5UOqkC178phzD5vMD7DOb/vnWN1ShxX5l7i/3LBo8
dMD2Rnimnh8GM1dz2uUoZm8fRJSHNJgF4qTViOCefaZZs2zwnK8ZZ0LrmK4Szu4a
cdK2NU/tl3lh3Idm55WTtaWwbQhHGwbECULZPRHwelcrPwH+FLR3Iz1S0AuVSrbh
rOC3jhdkT4QZTHGuRbQT+qMlK9EuQSlsA2PGh0GKqSrPt5G6GIUXD5y7hs8/uMcP
+LgcgTQKh3StSXoFMpVOZzbJtseJyOwurAD/MbyME/eH2WStpKACuZuLKNe0t4pW
sEWA4W5PAgMBAAECggEAD0bvTrt4m/42gNeeBuNPZNHj+ZhIV/0Vz9wUx+SF0xV7
FNZfPFm9VymUO67WJb1MFNoElE4OFFLQbShaYPkYns5kRTv2Oz/ZfQ8ceoJsJPrX
mDfQRJZsmDp75L39imNVk0peKFoi7kg9blMNxIbBmY/jndjuQk93IKSNvFucBZco
vDbP2Y5Fqa/OP01q7Y1gWZ9CJDDPwEQT66B2HLVhrcmui4/E6qIo1Id/zjs5TMm/
NTbV3E2Y4jsjaAKmz5sLEFoQmW+HGoUL2K/4FmB7Ym+WfxD7fLWxFsODZjloCOq4
HUFUHnVXTJWwe02qtYXKBmw5FruRgDNpLwN3GJUwoQKBgQD4lAlXX7/YgnXe74U2
ASoJGQqg84N8wElMzu7nf32d+3F5B7nxBaTpN57YHOtpefD+ZgfEa3+q8L+5uQLH
58MwpffF1PCqJR3IO3SMCBzwHolL61gs+IGous5nGm+3Fgs5TvUs6EtL+mnsHQX9
Ut/xk7+0XAfDyhCDS97iPepRtwKBgQC6Dac6E9wMQVPU7+SPhekCz3icNoNYXgVg
2SsXvpnVXxqh+A8zZ+iZxbV73tC7lvqG5wgjIxGyI9egzISeHIaKVJYWHYzKAnxm
IRzB0ghaVEBDnIzx4R+EzoLQ5dcUx3/wCMJQLEQhNp5yeTsm6C/2NQoALSikgq0+
6nP7JBhoKQKBgQDjNHwtTqlNvkD6mjdKG1pOooLihnHCjwbwm5wmIJOy2Obo1zUP
pjcLq/kWU6ig6gJqpNuonxE8L30uxnpSOfZg+vIz8uRewDoukJmAfNHmcCLSL7SS
tjnc/ZI3DyTZVd7AbPkQKOrZ8XLri8OzvhJO/tsUgaHfRUw+lhSM+ka4lQKBgQCT
jsqHJEMMMS+UnSIPtivEP9mvQwjOp9rqIbKspU0KTeAofz1HDu0KMCSsdl3juW0+
WrM4ctLRDt4wOKQhZgxKX6WdKpiDio8wzKgrDDH1ugYx2VJrb5l40fQsS21WnJba
P4gk38a09MWbkoyYYePQB+bDlw051C4kzPtpPgphaQKBgQD1mrOH6LrSogKR8F4h
slXGSdUuRgQ04Xx7yuINDGg9BNsk0/WCYQRHk5i4wdbX+KF5VXlFn/4y247SdM6D
oXwN7iwKj3XeiEQ1VZ9VOyF40bEJYi8crBx+gUIVSMcprL69Eej9m8ZrIJZU7ZuV
cweQ8NEor3To+VWCEMpkqZLHtA==
-----END PRIVATE KEY-----
EOF

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

rm -f "$private_key_file" "$auth_headers" "$auth_body" "$token_body" "$invalid_body"

if (( failures > 0 )); then
  printf "\nPrivate Key JWT harness failed: %s check(s) failed.\n" "$failures"
  exit 1
fi

printf "\nPrivate Key JWT harness passed.\n"
