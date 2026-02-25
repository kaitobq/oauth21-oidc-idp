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
  - UserInfo Endpoint: `/oauth2/userinfo`
- optional:
  - `organization` API (`ENABLE_ORGANIZATION_API=true` のときのみ有効)
  - 署名鍵ローテーション API (`OIDC_ENABLE_SIGNING_KEY_ROTATION_API=true` のときのみ有効)
  - private_key_jwt クライアント鍵ローテーション API (`OIDC_ENABLE_PRIVATE_JWT_KEY_ROTATION_API=true` のときのみ有効)

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

# Validate id_token claims (nonce/auth_time/at_hash/azp/sid/acr/amr)
BASE_URL=http://localhost:8080 make harness-id-token-claims

# Validate userinfo endpoint (success / invalid_token / insufficient_scope)
BASE_URL=http://localhost:8080 make harness-userinfo

# Validate confidential client auth (client_secret_basic)
BASE_URL=http://localhost:8080 make harness-client-secret-basic

# Validate private_key_jwt client auth
BASE_URL=http://localhost:8080 make harness-private-key-jwt

# Validate private_key_jwt assertion replay protection (jti reuse)
BASE_URL=http://localhost:8080 make harness-private-jwt-replay-protection

# Validate token endpoint error contract
BASE_URL=http://localhost:8080 make harness-token-error-contract

# Validate private_key_jwt client key rotation
BASE_URL=http://localhost:8080 OIDC_PRIVATE_JWT_KEY_ROTATION_TOKEN=dev-private-jwt-key-rotation-token make harness-private-jwt-key-rotation

# Validate signing key rotation API + JWKS reflection
BASE_URL=http://localhost:8080 OIDC_SIGNING_KEY_ROTATION_TOKEN=dev-signing-key-rotation-token make harness-signing-key-rotation
```

### Local Clients

`/oauth2/authorize` と `/oauth2/token` は開発用の公開クライアント（`none`）と confidential client（`client_secret_basic` / `private_key_jwt`）を事前登録しています。
`offline_access` scope を付けると `refresh_token` が発行されます。
`nonce` を `authorize` に指定すると、`id_token` に `nonce` と `auth_time` を含めます。
`id_token` 発行時は `access_token` 由来の `at_hash` も含めます。
`id_token` には認可済みクライアントを示す `azp` を含めます。
`id_token` にはセッション識別子 `sid` を含め、refresh 後も同一 `sid` を維持します。
`acr_values` を `authorize` に指定すると、`id_token` に `acr` と `amr` を含めます。

- `OIDC_DEV_CLIENT_ID`（default: `local-dev-client`）
- `OIDC_DEV_REDIRECT_URI`（default: `http://localhost:3000/callback`）
- `OIDC_CONFIDENTIAL_CLIENT_ID`（default: `local-confidential-client`）
- `OIDC_CONFIDENTIAL_CLIENT_SECRET`（default: `local-confidential-secret`）
- `OIDC_CONFIDENTIAL_REDIRECT_URI`（default: `http://localhost:3000/callback`）
- `OIDC_PRIVATE_JWT_ENABLED`（default: `true`）
- `OIDC_PRIVATE_JWT_CLIENT_ID`（default: `local-private-jwt-client`）
- `OIDC_PRIVATE_JWT_REDIRECT_URI`（default: `http://localhost:3000/callback`）
- `OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PATH`（default: `config/keys/local/private_jwt_client_public.pem`）
- `OIDC_PRIVATE_JWT_CLIENT_PUBLIC_KEY_PEM`（任意。設定時は `*_PATH` より優先）
- `OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH`（harness 用。default: `harness/keys/local/private_jwt_client_private.pem`）
- `OIDC_ENABLE_PRIVATE_JWT_KEY_ROTATION_API`（default: `false`）
- `OIDC_PRIVATE_JWT_KEY_ROTATION_TOKEN`（default: `dev-private-jwt-key-rotation-token`）
- `OIDC_ENABLE_SIGNING_KEY_ROTATION_API`（default: `false`）
- `OIDC_SIGNING_KEY_ROTATION_TOKEN`（default: `dev-signing-key-rotation-token`）

`make bootstrap` は `private_key_jwt` 用の開発鍵ペアをローカルに自動生成します。

### Audit Log

`/oauth2/authorize`・`/oauth2/token`・管理API（鍵ローテーション）は JSON Lines の監査ログを標準出力へ出力します。
例: `{"kind":"audit","event":"oidc.token","result":"success","grant_type":"authorization_code","client_id":"...","timestamp":"..."}`

## Development

```bash
# Run all checks
make check

# Run tests
make test

# Lint proto files
make lint-proto
```
