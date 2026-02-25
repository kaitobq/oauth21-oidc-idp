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
5. harness 実行
   ```bash
   BASE_URL=http://localhost:8080 make harness-smoke
   BASE_URL=http://localhost:8080 make harness-auth-code-pkce
   BASE_URL=http://localhost:8080 make harness-refresh-rotation
   BASE_URL=http://localhost:8080 make harness-id-token-claims
   ```

## Verification Checklist
- discovery endpoint が 200 を返す
- discovery に `issuer`, `jwks_uri`, `authorization_endpoint`, `token_endpoint` が含まれる
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

## Troubleshooting
- `jq command not found`: `jq` をインストール
- `HTTP 404` on discovery: `/.well-known/openid-configuration` の実装漏れ
- `JWKS keys array is empty`: 鍵生成・公開設定を確認
- `invalid_request` on authorize: `client_id` / `redirect_uri` / `code_challenge_method=S256` を確認
