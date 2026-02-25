#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PRIVATE_KEY_PATH="${OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH:-$ROOT_DIR/harness/keys/local/private_jwt_client_private.pem}"
PUBLIC_KEY_PATH="${OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PATH:-$ROOT_DIR/backend/config/keys/local/private_jwt_client_public.pem}"
FORCE_REGENERATE="${FORCE_REGENERATE:-false}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[ERROR] required command not found: $1" >&2
    exit 2
  fi
}

bool_true() {
  case "$(printf "%s" "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

require_cmd openssl

mkdir -p "$(dirname "$PRIVATE_KEY_PATH")" "$(dirname "$PUBLIC_KEY_PATH")"

if [[ -f "$PRIVATE_KEY_PATH" && -f "$PUBLIC_KEY_PATH" ]] && ! bool_true "$FORCE_REGENERATE"; then
  echo "[INFO] private_key_jwt dev key pair already exists"
  echo "[INFO] private: $PRIVATE_KEY_PATH"
  echo "[INFO] public : $PUBLIC_KEY_PATH"
  exit 0
fi

tmp_private="$(mktemp)"
tmp_public="$(mktemp)"
cleanup() {
  rm -f "$tmp_private" "$tmp_public"
}
trap cleanup EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp_private" >/dev/null 2>&1
openssl pkey -in "$tmp_private" -pubout -out "$tmp_public" >/dev/null 2>&1

mv "$tmp_private" "$PRIVATE_KEY_PATH"
mv "$tmp_public" "$PUBLIC_KEY_PATH"
chmod 600 "$PRIVATE_KEY_PATH"
chmod 644 "$PUBLIC_KEY_PATH"

echo "[INFO] generated private_key_jwt dev key pair"
echo "[INFO] private: $PRIVATE_KEY_PATH"
echo "[INFO] public : $PUBLIC_KEY_PATH"
