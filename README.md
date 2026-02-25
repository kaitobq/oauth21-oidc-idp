# oauth21-oidc-idp

OAuth 2.1 / OpenID Connect 準拠の IDP（Identity Provider）を構築するためのリポジトリです。
この初期セットアップでは、実装前に Harness Engineering の土台を先に用意します。

## 方針
- OAuth 2.1 ドラフト（IETF）と OIDC Core 1.0 を基準に要件を定義
- `AGENTS.md` は最小限の目次として維持
- 仕様・設計・運用・検証を `docs/` と `harness/` に分離
- 小さな変更を `harness` で継続検証する

## クイックスタート
1. リポジトリ初期化
   ```bash
   make bootstrap
   ```
2. ローカル IDP を起動（別ターミナル）
   - 例: `http://localhost:8080`
3. smoke harness 実行
   ```bash
   BASE_URL=http://localhost:8080 make harness-smoke
   ```

## ディレクトリ
- `AGENTS.md`: エージェント向け最小ガイド
- `docs/`: 仕様・設計・運用ドキュメント
- `harness/`: 検証シナリオと運用ルール
- `scripts/harness_smoke.sh`: 最小の自動検証スクリプト

## 参考
- OpenAI: Harnessing engineering agents（公開日: 2026-02-11）
- IETF OAuth 2.1 Draft / OpenID Connect Core

詳細は [docs/index.md](docs/index.md) を参照してください。
