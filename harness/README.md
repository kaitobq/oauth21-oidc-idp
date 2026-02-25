# Harness

IDP 実装に対して継続的に仕様適合を確認するための検証資産です。

## Structure
- `scenarios/`: シナリオ定義（要件と検証観点）
- `../scripts/harness_smoke.sh`: discovery/JWKS の最小自動検証
- `../scripts/harness_auth_code_pkce.sh`: Auth Code + PKCE の最小フロー検証
- `../scripts/harness_refresh_rotation.sh`: refresh token rotation の最小フロー検証
- `../scripts/harness_id_token_claims.sh`: id_token claim（nonce/auth_time/at_hash/azp/sid/acr/amr）の検証

## Run
```bash
BASE_URL=http://localhost:8080 ../scripts/harness_smoke.sh
BASE_URL=http://localhost:8080 ../scripts/harness_auth_code_pkce.sh
BASE_URL=http://localhost:8080 ../scripts/harness_refresh_rotation.sh
BASE_URL=http://localhost:8080 ../scripts/harness_id_token_claims.sh
```

## Rules
- 仕様変更時は `docs/spec/` と `scenarios/` を同時更新する。
- 新しい不具合を修正したら、再発防止のシナリオを追加する。
- `smoke` は常に高速（数秒）を維持し、重い統合試験は別フェーズへ分離する。
