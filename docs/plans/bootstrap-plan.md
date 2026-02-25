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
- 2026-02-25: Phase 2 進行中（token endpoint client auth: client_secret_basic 追加）
- 2026-02-25: Phase 2 進行中（token endpoint client auth: private_key_jwt 追加）
- 2026-02-25: Phase 2 進行中（private_key_jwt 鍵管理を設定駆動へ移行）

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
1. クライアント登録を静的1件から永続化モデルへ移行
2. 署名鍵ローテーション（IDP鍵・client鍵）を段階導入
3. 監査ログと異常検知を段階導入
