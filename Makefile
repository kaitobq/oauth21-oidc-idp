.PHONY: bootstrap gen-private-jwt-dev-keys harness-smoke harness-auth-code-pkce harness-refresh-rotation harness-id-token-claims harness-client-secret-basic harness-private-key-jwt harness-private-jwt-replay-protection harness-token-error-contract harness-private-jwt-key-rotation harness-signing-key-rotation setup gen lint-proto check test run-backend run-frontend clean

bootstrap:
	chmod +x scripts/harness_smoke.sh
	chmod +x scripts/harness_auth_code_pkce.sh
	chmod +x scripts/harness_refresh_rotation.sh
	chmod +x scripts/harness_id_token_claims.sh
	chmod +x scripts/harness_client_secret_basic.sh
	chmod +x scripts/harness_private_key_jwt.sh
	chmod +x scripts/harness_private_jwt_replay_protection.sh
	chmod +x scripts/harness_token_error_contract.sh
	chmod +x scripts/harness_private_jwt_key_rotation.sh
	chmod +x scripts/harness_signing_key_rotation.sh
	chmod +x scripts/generate_private_jwt_dev_keys.sh
	OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH=$${OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH:-harness/keys/local/private_jwt_client_private.pem} \
	OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PATH=$${OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PATH:-backend/config/keys/local/private_jwt_client_public.pem} \
	scripts/generate_private_jwt_dev_keys.sh
	@echo "bootstrap complete"

gen-private-jwt-dev-keys:
	OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH=$${OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH:-harness/keys/local/private_jwt_client_private.pem} \
	OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PATH=$${OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PATH:-backend/config/keys/local/private_jwt_client_public.pem} \
	scripts/generate_private_jwt_dev_keys.sh

harness-smoke:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_smoke.sh

harness-auth-code-pkce:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_auth_code_pkce.sh

harness-refresh-rotation:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_refresh_rotation.sh

harness-id-token-claims:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_id_token_claims.sh

harness-client-secret-basic:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_client_secret_basic.sh

harness-private-key-jwt:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_private_key_jwt.sh

harness-private-jwt-replay-protection:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_private_jwt_replay_protection.sh

harness-token-error-contract:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_token_error_contract.sh

harness-private-jwt-key-rotation:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_private_jwt_key_rotation.sh

harness-signing-key-rotation:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_signing_key_rotation.sh

# ── Setup ──────────────────────────────────────────────
setup: setup-backend setup-frontend setup-proto

setup-backend:
	cd backend && go mod download

setup-frontend:
	cd frontend && pnpm install

setup-proto:
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest

# ── Code Generation ───────────────────────────────────
gen:
	./scripts/gen.sh

check-generated:
	./scripts/check-generated.sh

# ── Lint ──────────────────────────────────────────────
lint-proto:
	cd proto && buf lint

lint-backend:
	cd backend && go vet ./...

lint-frontend:
	cd frontend && pnpm lint

lint: lint-proto lint-backend lint-frontend

# ── Test ──────────────────────────────────────────────
test-backend:
	cd backend && go test ./...

test-frontend:
	cd frontend && pnpm test

test: test-backend test-frontend

# ── Check ─────────────────────────────────────────────
check: lint test check-generated

# ── Run ───────────────────────────────────────────────
run-backend:
	cd backend && go run ./cmd/server

run-frontend:
	cd frontend && pnpm dev

# ── Clean ─────────────────────────────────────────────
clean:
	rm -rf backend/internal/gen frontend/src/gen
	rm -rf frontend/node_modules frontend/dist
