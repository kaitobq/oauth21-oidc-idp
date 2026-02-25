# Project Overview

## Purpose
- OAuth 2.1 / OIDC 準拠 IDP を段階的に実装し、外部連携可能な認可基盤を作る。
- 変更のたびに harness で回帰確認し、仕様逸脱を早期検知する。

## Non-goals
- 初期フェーズで全拡張規格（FAPI, CIBA, Federation 等）を網羅しない。
- 独自プロトコルを優先して標準互換性を犠牲にしない。
- 最初から分散マルチリージョン構成を前提にしない。

## Scope (Phase 0-2)
- Phase 0: ドキュメントと harness の初期整備
- Phase 1: OIDC Discovery / JWKS / Authorization Code + PKCE
- Phase 2: Refresh Token Rotation / 監査ログ / 鍵ローテーション

## Success Criteria
- OIDC discovery と JWKS が正しいメタデータを返す。
- Authorization Code + PKCE フローが harness で継続的に検証できる。
- 仕様変更時に docs と harness が同時更新される運用が定着する。
