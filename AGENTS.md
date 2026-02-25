# AGENTS.md

## このリポジトリは何か
- OAuth 2.1 / OIDC 準拠 IDP を構築するための実装リポジトリです。
- 目的は「セキュアな認可・認証フローを段階的に実装し、harness で継続検証する」ことです。
- まず Authorization Code + PKCE を最優先で実装します。
- `organization` API は将来のマルチテナント検証用であり、IDP core の必須機能ではありません。

## ドキュメント運用方針
- `AGENTS.md` は最小限の目次として維持し、詳細は `docs/` に書きます。
- 新規ドキュメント追加時は `docs/index.md` と本ファイルのインデックスを更新します。
- 仕様変更は `docs/spec/` を正本として、`harness/` の検証項目も同時更新します。

## Docs Index
- [docs/index.md](docs/index.md): ドキュメント全体の入口
- [docs/project-overview.md](docs/project-overview.md): 目的・非目的・成功条件
- [docs/spec/idp-core-requirements.md](docs/spec/idp-core-requirements.md): OAuth2.1/OIDC 要件（正本）
- [docs/architecture/idp-reference-architecture.md](docs/architecture/idp-reference-architecture.md): 参照アーキテクチャ
- [docs/plans/bootstrap-plan.md](docs/plans/bootstrap-plan.md): 初期セットアップ計画
- [docs/operations/setup.md](docs/operations/setup.md): ローカルセットアップ手順
- [docs/references/openai-harness-engineering.md](docs/references/openai-harness-engineering.md): 参考記事メモ
- [docs/references/standards.md](docs/references/standards.md): 準拠対象の規格リンク
- [harness/README.md](harness/README.md): harness の実行と更新ルール
