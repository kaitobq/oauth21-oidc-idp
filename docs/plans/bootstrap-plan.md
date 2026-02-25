# Bootstrap Plan

## Current Phase
- 2026-02-25: Phase 0（repo + docs + harness scaffold）
- 2026-02-25: Phase 1 完了（OIDC discovery + JWKS + Auth Code + PKCE 最小実装）
- 2026-02-25: Phase 2 進行中（refresh token rotation 最小実装）
- 2026-02-25: Phase 2 進行中（id_token claim: nonce/auth_time 追加）
- 2026-02-25: Phase 2 進行中（id_token claim: at_hash 追加）
- 2026-02-25: Phase 2 進行中（id_token claim: acr/amr 追加）
- 2026-02-25: Phase 2 進行中（id_token claim: azp 追加）
- 2026-02-25: Phase 2 進行中（id_token claim: sid 追加）
- 2026-02-25: Phase 2 進行中（userinfo endpoint 追加）
- 2026-02-25: Phase 2 進行中（token endpoint client auth: client_secret_basic 追加）
- 2026-02-25: Phase 2 進行中（token endpoint client auth: private_key_jwt 追加）
- 2026-02-25: Phase 2 進行中（private_key_jwt 鍵管理を設定駆動へ移行）
- 2026-02-25: Phase 2 進行中（IDP署名鍵ローテーションAPI + JWKS反映 + harness 追加）
- 2026-02-25: Phase 2 進行中（private_key_jwt クライアント鍵ローテーションAPI + harness 追加）
- 2026-02-25: Phase 2 進行中（token endpoint error contract harness 追加）
- 2026-02-25: Phase 2 進行中（private_key_jwt assertion replay protection 追加）
- 2026-02-25: Phase 2 進行中（authorize/token/admin API の監査ログ追加）
- 2026-02-25: Phase 2 進行中（管理 API 認可を JWT + scope へ拡張）
- 2026-02-25: Phase 2 進行中（OIDC client registry の file 永続化を追加）
- 2026-02-25: Phase 2 進行中（管理 API JWT の `jti` リプレイ防止を追加）
- 2026-02-25: Phase 2 進行中（監査ログの連続失敗検知 `audit_alert` を追加）
- 2026-02-25: Phase 2 進行中（organization API の scope 認可を追加）

## Implementation Plan

### Phase 0: Harness-First Scaffold
- リポジトリ雛形作成
- `docs/` 正本化
- `harness/scenarios` と smoke script 作成

### Phase 1: Core Endpoints
- OIDC discovery endpoint
- JWKS endpoint
- Authorization Code + PKCE
  - `authorize` / `token` 最小フロー（公開クライアント + S256 + single-use code）

### Phase 2: Hardening
- Refresh Token Rotation
- 署名鍵ローテーション
- 監査ログと失敗ケースの充実

## Acceptance Gates
- Gate A: `BASE_URL=<idp> make harness-smoke` が discovery/JWKS で成功
- Gate B: PKCE 未指定リクエストを拒否できる
- Gate C: 主要フロー変更時に harness シナリオが更新される

## Next Actions
1. organization API の認可方式をヘッダ暫定から正式な管理者トークン検証へ移行
2. OIDCエンドユーザー認証（ログイン/同意/アカウント管理）を導入
3. client registry 永続化先を MySQL/KV へ拡張しマルチインスタンス運用へ対応
