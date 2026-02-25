# OAuth 2.1 / OIDC Identity Provider

OAuth 2.1 と OpenID Connect に準拠した Identity Provider。
まずは IDP core（Discovery/JWKS）から実装し、Authorization Code + PKCE へ段階的に進めます。

## Architecture

- **Frontend**: [Vinext](https://github.com/cloudflare/vinext) (Vite + Next.js API surface on Cloudflare Workers)
- **Backend**: Go + [Connect RPC](https://connectrpc.com/)
- **Schema**: Protocol Buffers (single source of truth for types)
- **Build**: [Buf](https://buf.build/) for proto management and code generation

### Backend Layering (DDD + Onion)

- `handler/`: Connect handler, proto <-> VO conversion, facade delegation
- `application/`: command/query use cases
- `domain/`: entity, value object, repository interface
- `infra/`: MySQL/authz implementation

Dependency direction is fixed as `handler -> application -> domain` and `infra -> domain`.
`domain` must not import `infra`.

### Current Scope

- default enabled:
  - OIDC Discovery: `/.well-known/openid-configuration`
  - JWKS: `/oauth2/jwks`
  - Authorization Endpoint (Auth Code + PKCE): `/oauth2/authorize`
  - Token Endpoint (`authorization_code` / `refresh_token`): `/oauth2/token`
- optional:
  - `organization` API (`ENABLE_ORGANIZATION_API=true` のときのみ有効)

### API Contract Policy

- `.proto` is the single source of truth
- Generated code is committed (`backend/internal/gen`, `frontend/src/gen`)
- Any `.proto` change must run `make gen`

### AI Collaboration Guardrails

- Humans decide architecture, domain modeling, and authorization policy
- AI assists with implementation inside established type/layer boundaries
- Review is done per package/layer (domain, application, infra, handler)

## Directory Structure

```
proto/          # Protocol Buffers definitions (single source of truth)
backend/        # Go backend (Connect RPC server)
frontend/       # Vinext frontend (TypeScript)
scripts/        # Build and generation scripts
```

## Prerequisites

- Go 1.23+
- Node.js 22+ / pnpm 9+
- [Buf CLI](https://buf.build/docs/installation)
- [Protoc](https://grpc.io/docs/protoc-installation/)

## Getting Started

```bash
# one-time bootstrap
make bootstrap

# Run backend
make run-backend

# Validate core endpoints
BASE_URL=http://localhost:8080 make harness-smoke

# Validate auth code + PKCE flow
BASE_URL=http://localhost:8080 make harness-auth-code-pkce

# Validate refresh token rotation flow
BASE_URL=http://localhost:8080 make harness-refresh-rotation

# Validate id_token claims (nonce/auth_time/at_hash/acr/amr)
BASE_URL=http://localhost:8080 make harness-id-token-claims
```

### Local Dev Client

`/oauth2/authorize` と `/oauth2/token` は開発用の公開クライアント1件を事前登録しています。
`offline_access` scope を付けると `refresh_token` が発行されます。
`nonce` を `authorize` に指定すると、`id_token` に `nonce` と `auth_time` を含めます。
`id_token` 発行時は `access_token` 由来の `at_hash` も含めます。
`acr_values` を `authorize` に指定すると、`id_token` に `acr` と `amr` を含めます。

- `OIDC_DEV_CLIENT_ID`（default: `local-dev-client`）
- `OIDC_DEV_REDIRECT_URI`（default: `http://localhost:3000/callback`）

## Development

```bash
# Run all checks
make check

# Run tests
make test

# Lint proto files
make lint-proto
```
