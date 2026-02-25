# Bootstrap Plan

## Current Phase
- 2026-02-25: Phase 0（repo + docs + harness scaffold）
- 2026-02-25: Phase 1 着手（OIDC discovery + JWKS の実装）

## Implementation Plan

### Phase 0: Harness-First Scaffold
- リポジトリ雛形作成
- `docs/` 正本化
- `harness/scenarios` と smoke script 作成

### Phase 1: Core Endpoints
- OIDC discovery endpoint
- JWKS endpoint
- Authorization Code + PKCE
  - `authorize` / `token` は placeholder から段階的に実装する

### Phase 2: Hardening
- Refresh Token Rotation
- 署名鍵ローテーション
- 監査ログと失敗ケースの充実

## Acceptance Gates
- Gate A: `BASE_URL=<idp> make harness-smoke` が discovery/JWKS で成功
- Gate B: PKCE 未指定リクエストを拒否できる
- Gate C: 主要フロー変更時に harness シナリオが更新される

## Next Actions
1. `authorization_endpoint` の最小実装（PKCE 必須チェック）
2. `token_endpoint` の最小実装（code_verifier 検証）
3. `Client` / `User` / `Authorization Code` の最小モデル追加
