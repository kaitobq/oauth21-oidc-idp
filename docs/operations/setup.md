# Operations Setup

## Prerequisites
- macOS / Linux
- `bash`, `curl`, `jq`, `openssl`
- ローカルで起動できる IDP 実装

## Initial Setup
1. リポジトリルートへ移動
2. 実行権限付与
   ```bash
   make bootstrap
   ```
3. IDP をローカル起動
   - 既定では `organization` API は無効（DB不要）
   - 必要な場合のみ `ENABLE_ORGANIZATION_API=true` を設定
4. 必要に応じて開発用クライアントを設定
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
5. harness 実行
   ```bash
   BASE_URL=http://localhost:8080 make harness-smoke
   BASE_URL=http://localhost:8080 make harness-auth-code-pkce
   BASE_URL=http://localhost:8080 make harness-refresh-rotation
   BASE_URL=http://localhost:8080 make harness-id-token-claims
   BASE_URL=http://localhost:8080 make harness-client-secret-basic
   BASE_URL=http://localhost:8080 make harness-private-key-jwt
   BASE_URL=http://localhost:8080 OIDC_PRIVATE_JWT_KEY_ROTATION_TOKEN=dev-private-jwt-key-rotation-token make harness-private-jwt-key-rotation
   BASE_URL=http://localhost:8080 OIDC_SIGNING_KEY_ROTATION_TOKEN=dev-signing-key-rotation-token make harness-signing-key-rotation
   ```

## Verification Checklist
- discovery endpoint が 200 を返す
- discovery に `issuer`, `jwks_uri`, `authorization_endpoint`, `token_endpoint` が含まれる
- discovery の `token_endpoint_auth_methods_supported` に `none` / `client_secret_basic` が含まれる
- `OIDC_PRIVATE_JWT_ENABLED=true` のとき、`token_endpoint_auth_methods_supported` に `private_key_jwt` が含まれる
- JWKS endpoint が `keys` 配列を返す
- `grant_types_supported` に `password` が含まれない
- `authorize` が 302 で `code` を返す
- `token`(`authorization_code`) が 200 で `access_token` / `id_token` を返す
- 同じ authorization code の再利用が `invalid_grant` で拒否される
- `token`(`refresh_token`) が 200 で新しい `refresh_token` を返す
- 旧 refresh_token の再利用が `invalid_grant` で拒否される
- `authorize` の `nonce` が `id_token` に反映される
- `id_token` が `auth_time` を含む
- `id_token` が `at_hash` を含み、返却された `access_token` と整合する
- `id_token` が `azp` を含み、`client_id` と一致する
- `id_token` が `sid` を含み、refresh 後も同一値を維持する
- `id_token` が `acr` / `amr` を含む
- confidential client が `client_secret_basic` で token 交換できる
- 不正な Basic 認証が `401` / `invalid_client` で拒否される
- confidential client が `private_key_jwt` で token 交換できる
- 不正な client assertion が `401` / `invalid_client` で拒否される
- `OIDC_ENABLE_PRIVATE_JWT_KEY_ROTATION_API=true` のとき、`/oauth2/admin/rotate-private-jwt-client-key` が有効化される
- private_key_jwt 鍵ローテーション後、新鍵と直前鍵は認証成功し、最古鍵は拒否される
- `OIDC_ENABLE_SIGNING_KEY_ROTATION_API=true` のとき、`/oauth2/admin/rotate-signing-key` が有効化される
- 署名鍵ローテーション後、JWKS の active `kid` が更新される
- ローテーション直後は旧 active `kid` が grace window 中に保持される

## Troubleshooting
- `jq command not found`: `jq` をインストール
- `HTTP 404` on discovery: `/.well-known/openid-configuration` の実装漏れ
- `JWKS keys array is empty`: 鍵生成・公開設定を確認
- `invalid_request` on authorize: `client_id` / `redirect_uri` / `code_challenge_method=S256` を確認
