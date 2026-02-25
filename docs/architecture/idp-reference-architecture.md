# Architecture: IDP Reference

## Components
- Authorization Server
  - 認可エンドポイントとトークンエンドポイントを提供
- Identity Layer (OIDC)
  - ID Token 発行、UserInfo（将来フェーズ）
- Key Management
  - 署名鍵管理、`jwks_uri` 公開、ローテーション
- Client Registry
  - client metadata 管理（redirect URI、auth method、scopes）
- Audit/Telemetry
  - 認可要求、トークン発行、失敗イベントを記録

## Trust Boundaries
- 外部クライアントと IDP の通信境界
- 署名鍵保管領域（HSM/KMS を将来適用）
- 監査ログ保管領域（改ざん検知を考慮）

## Initial Sequence (Auth Code + PKCE)
1. Client -> Authorization Endpoint (`code_challenge=S256`)
2. User 認証・同意
3. Client <- Authorization Code
4. Client -> Token Endpoint (`code_verifier`)
5. Client <- Access Token (+ optional ID Token)

## Harness Integration Points
- discovery contract test
- JWKS contract test
- token endpoint error contract test
- PKCE 必須性 test
