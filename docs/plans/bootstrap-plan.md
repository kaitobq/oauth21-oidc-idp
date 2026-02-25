# Bootstrap Plan

## Current Phase
- 2026-02-25: Phase 0（repo + docs + harness scaffold）

## Implementation Plan

### Phase 0: Harness-First Scaffold
- リポジトリ雛形作成
- `docs/` 正本化
- `harness/scenarios` と smoke script 作成

### Phase 1: Core Endpoints
- OIDC discovery endpoint
- JWKS endpoint
- Authorization Code + PKCE

### Phase 2: Hardening
- Refresh Token Rotation
- 署名鍵ローテーション
- 監査ログと失敗ケースの充実

## Acceptance Gates
- Gate A: `BASE_URL=<idp> make harness-smoke` が discovery/JWKS で成功
- Gate B: PKCE 未指定リクエストを拒否できる
- Gate C: 主要フロー変更時に harness シナリオが更新される

## Next Actions
1. 実装言語・フレームワークを決定（Go / Node.js など）
2. `authorization_endpoint` と `token_endpoint` の最小実装
3. `harness/scenarios/02-auth-code-pkce.yaml` に沿った自動試験追加
