# Harness

IDP 実装に対して継続的に仕様適合を確認するための検証資産です。

## Structure
- `scenarios/`: シナリオ定義（要件と検証観点）
- `../scripts/harness_smoke.sh`: discovery/JWKS の最小自動検証
- `../scripts/harness_auth_code_pkce.sh`: Auth Code + PKCE の最小フロー検証
- `../scripts/harness_refresh_rotation.sh`: refresh token rotation の最小フロー検証
- `../scripts/harness_id_token_claims.sh`: id_token claim（nonce/auth_time/at_hash/azp/sid/acr/amr）の検証
- `../scripts/harness_userinfo.sh`: userinfo endpoint（正常系/invalid_token/insufficient_scope）の検証
- `../scripts/harness_client_secret_basic.sh`: confidential client の `client_secret_basic` 認証検証
- `../scripts/harness_private_key_jwt.sh`: confidential client の `private_key_jwt` 認証検証
- `../scripts/harness_private_jwt_replay_protection.sh`: private_key_jwt の assertion replay (jti) 防止検証
- `../scripts/harness_token_error_contract.sh`: token endpoint のエラーレスポンス契約検証
- `../scripts/harness_private_jwt_key_rotation.sh`: private_key_jwt クライアント鍵ローテーション検証
- `../scripts/harness_admin_auth_jwt.sh`: 管理 API の JWT Bearer scope 認可検証

## Run
```bash
BASE_URL=http://localhost:8080 ../scripts/harness_smoke.sh
BASE_URL=http://localhost:8080 ../scripts/harness_auth_code_pkce.sh
BASE_URL=http://localhost:8080 ../scripts/harness_refresh_rotation.sh
BASE_URL=http://localhost:8080 ../scripts/harness_id_token_claims.sh
BASE_URL=http://localhost:8080 ../scripts/harness_userinfo.sh
BASE_URL=http://localhost:8080 ../scripts/harness_client_secret_basic.sh
BASE_URL=http://localhost:8080 ../scripts/harness_private_key_jwt.sh
BASE_URL=http://localhost:8080 ../scripts/harness_private_jwt_replay_protection.sh
BASE_URL=http://localhost:8080 ../scripts/harness_token_error_contract.sh
BASE_URL=http://localhost:8080 OIDC_PRIVATE_JWT_KEY_ROTATION_TOKEN=dev-private-jwt-key-rotation-token ../scripts/harness_private_jwt_key_rotation.sh
BASE_URL=http://localhost:8080 OIDC_ENABLE_SIGNING_KEY_ROTATION_API=true OIDC_ADMIN_AUTH_MODE=jwt OIDC_ADMIN_JWT_HS256_SECRET=dev-admin-jwt-secret OIDC_ADMIN_JWT_ISS=harness-admin OIDC_ADMIN_JWT_AUD=oidc-admin ../scripts/harness_admin_auth_jwt.sh
```

`harness_private_key_jwt.sh` は既定で `harness/keys/local/private_jwt_client_private.pem` を使用します。
`make bootstrap` または `make gen-private-jwt-dev-keys` で鍵ペアを生成してください。
必要に応じて `OIDC_PRIVATE_JWT_CLIENT_PRIVATE_KEY_PATH` で差し替えてください。
`harness_private_jwt_key_rotation.sh` は `OIDC_ENABLE_PRIVATE_JWT_KEY_ROTATION_API=true` で有効化したAPIを前提にします。
`harness_smoke.sh` は `EXPECT_PRIVATE_JWT`（default: `true`）で `private_key_jwt` の期待値を切り替えられます。

## Rules
- 仕様変更時は `docs/spec/` と `scenarios/` を同時更新する。
- 新しい不具合を修正したら、再発防止のシナリオを追加する。
- `smoke` は常に高速（数秒）を維持し、重い統合試験は別フェーズへ分離する。
