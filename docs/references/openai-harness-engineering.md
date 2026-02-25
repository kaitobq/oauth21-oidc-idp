# Reference: OpenAI Harness Engineering

## Source
- OpenAI, "Harnessing engineering agents"（公開日: 2026-02-11）
  - https://openai.com/ja-JP/index/harness-engineering/

## Notes for This Repo
- `AGENTS.md` は詳細仕様置き場ではなく導線として使う。
- 仕様・設計・運用・検証を分割し、更新単位を小さく保つ。
- 変更後に必ず実行可能な harness を回す前提で進める。
- non-goals を明記して、実装のブレを減らす。

## Applied Decisions
- `AGENTS.md` は概要 + docs index のみに限定
- 仕様正本は `docs/spec/` に配置
- 検証は `harness/scenarios/` と `scripts/harness_smoke.sh` で開始
