# vuln-signal

脆弱性の緊急情報を配信するサイトのソース（サイト名は未定）。**設計段階で、まだ実装はない。**

- CVE の新規公開と更新（CVSS の変更・KEV への追加など）を一次配信だけから集める。ニュースサイトは使わない。
- Node.js（本体・npm）と Linux（カーネル・主要ディストリ）の緊急度が高いものを優先する。
- 緊急度はルールで決める。LLM は日本語訳・起こりうるリスクの説明・続報の要約だけを担う。
- 配信: Web（Cloudflare Workers + D1）、Discord、RSS、メール。

設計は [`docs/design.md`](docs/design.md)。

## ライセンス

- コード: MIT（[`LICENSE`](LICENSE)）
- 記事・配信データ: CC BY 4.0。一次ソース由来の部分は提供元の条件に従う（[`LICENSE-DATA.md`](LICENSE-DATA.md)）

## 免責

緊急度は公開データを機械的に組み合わせた目安で、特定の環境への影響を保証しない。無保証（as is）で提供する。
