.PHONY: bootstrap harness-smoke harness-auth-code-pkce setup gen lint-proto check test run-backend run-frontend clean

bootstrap:
	chmod +x scripts/harness_smoke.sh
	chmod +x scripts/harness_auth_code_pkce.sh
	@echo "bootstrap complete"

harness-smoke:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_smoke.sh

harness-auth-code-pkce:
	BASE_URL=$${BASE_URL:-http://localhost:8080} scripts/harness_auth_code_pkce.sh

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
