# Specification: IDP Core Requirements

## Goal
OAuth 2.1 / OIDC の基本要件を満たす IDP を実装し、相互運用性と安全性を確保する。

## Normative Baseline
- OAuth 2.1 draft（IETF OAuth WG）
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0

## Functional Requirements

### 0. Scope Boundary
1. `organization` などのマルチテナント機能は IDP core の必須要件に含めない。
2. まず OAuth/OIDC の最小相互運用性（discovery, jwks, auth code + pkce）を優先する。

### 1. Authorization Flow
1. `authorization_code` grant を実装する。
2. Public Client には PKCE (`S256`) を必須にする。
3. `implicit` grant と `password` grant は提供しない。

### 2. Token Endpoint
1. `client_secret_basic` または `private_key_jwt` をサポートする。
2. アクセストークン期限切れ時は標準エラー形式で応答する。
3. Refresh Token は Rotation を前提に設計する。

### 3. OIDC Requirements
1. `/.well-known/openid-configuration` を提供する。
2. `jwks_uri` で署名検証可能な公開鍵を提供する。
3. ID Token に最低限以下を含める。
   - `iss`
   - `sub`
   - `aud`
   - `exp`
   - `iat`
4. `nonce` が認可リクエストで与えられた場合、ID Token に `nonce` を含める。
5. ID Token に `auth_time` を含める。
6. ID Token と同時に Access Token を返す場合、ID Token に `at_hash` を含める。
7. ID Token に `acr` / `amr` を含める。
8. ID Token に `azp` を含める。

### 4. Security & Operations
1. 署名鍵ローテーション手順を定義する。
2. 認可・トークン発行イベントを監査ログに記録する。
3. harness で discovery/JWKS/基本フローの回帰検証を継続する。

## Definition of Done (Phase 1)
- discovery endpoint が 200 を返し、必須メタデータを含む。
- JWKS endpoint が有効な `keys` 配列を返す。
- Authorization Code + PKCE の最小シナリオが harness で通過する。
