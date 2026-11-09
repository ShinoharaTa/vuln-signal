# vuln-signal 設計（サイト名は未定）

作成日: 2026-11-06。改訂: 2026-11-06（LLM の役割・サイト名・MIT・PoC の扱い・配信チャネルを反映）。
コードは書かず、決めるための材料として作成。
「事実」= 一次情報または実測で確認。「推測」= 未確認の見立て。

---

## 1. 概要

### 何のために
- Node.js（本体・npm）と Linux（カーネル・主要ディストリ）を使う開発者 1 人〜少数が、**自分の環境に関係する緊急の脆弱性だけ**を見逃さないための配信サイト。
- 価値は網羅ではなく「取りこぼさないこと」と「読んで 30 秒で判断できること」。NVD の月間公開数は **17,481 件（2026-10、実測）** あり、そのまま流すと読めない。

### 範囲
- 入力: 一次配信（NVD / CVE.org / KEV / GHSA / OSV / Node.js / ディストリ / EPSS）。ニュースサイト・ブログ記事は入力に使わない。
- 出力: Web（Cloudflare Workers + D1、SSR）、配信チャネルは **RSS / Discord / Slack / メール**（§9.6）。RSS 以外の配信先は運営者がサーバー上の CLI で登録する（公開の登録フォームは置かない）。
- 補助シグナル（PoC 公開・悪用報告）: 状況把握用。本文の情報源にはしない。X は v1 では使わない（§5・§7）。

### 成功条件（受け入れ条件の上位）
- KEV 追加・CVSS ≥ 9.0 の Node/npm/kernel/ディストリ該当 CVE を、一次公開から **2 時間以内**にサイトに反映できる（取得間隔 30 分 + 処理）。
- 1 日あたりの「緊急」「重要」の掲載件数が平均 **20 件以下**（読める量に抑える。kernel の間引きが効いている指標）。
- すべての記事に出典リンク・ライセンス表示・免責・緊急度の判定根拠（ルール名）が付く。
- 読者が記事だけで「**何が起きうるか（被害）・自分が該当するか・何をすればよいか**」を判断できる（LLM の役割。§4.6）。
- API キー・トークンがリポジトリにも git 履歴にも存在しない（gitleaks CI が緑）。

---

## 2. signal-digest からの流用と作り直し

signal-digest は読んだだけで変更していない。以下はコードで確認した事実。

### 2.1 事実（コードで確認）
- batch は Python 3.11 / Poetry / SQLAlchemy。`llm/analyzer.py`（1,269 行）がマルチプロバイダ（OpenRouter→Gemini→OpenAI→Anthropic、Ollama も `router.py` に定義）。`llm/usage.py` がトークン計上と `LLM_TOKEN_BUDGET_PER_RUN` の上限、`LlmUsage` テーブルに step 別記録。
- `llm/copycheck.py`（108 行）は NFKC 正規化後 **30 字連続一致**で丸写しを検出。ひらがな比率で「文章の写し」か「固有名詞の羅列」かを分ける。英文は小文字比率で判定。
- `judge/`（Jev = TypeSafe System One、入力 $0.042/M）は RSS 記事の掲載ゲート（3 段）+ ストーリー結合。`promptVersion` でキャッシュ、shadow/live 切替、`gate-labels.tsv` で precision/recall。
- `signals/novelty.py` は「コーパス初出の固有名詞」、`signals/stories.py`（1,217 行）は埋め込み cosine + Jev で配信をまたぐ結合。`rss/crawler.py` + `urlnorm.py` + `fetch_body.py`（trafilatura）が RSS 前提。
- `notifications/discord.py`（283 行）/ `webpush.py`、`pipelines/scheduler.py`・`notify.py` は常駐プロセス前提（systemd --user で稼働中。実測 `systemctl --user` に scheduler / notify / pg / tts / tunnel / web）。
- web は Next.js 14.2 + Prisma 5 + PostgreSQL、`/admin` と閲覧認証（Viewer / RefreshToken）を持つ。`docs/editorial-style.md` は生成時にシステムプロンプトへ差し込む文体指針。
- DB は `signal-digest-pg.service`（PostgreSQL 16.15、:5433、`~/pgdata` 530MB、DB `jigyaan` 459MB）。

### 2.2 流用（コピーして持ってくる）
| 部品 | 扱い | 理由 |
|---|---|---|
| `llm/usage.py` + `usage_report.py` | ほぼそのままコピー | プロバイダ非依存の計上・予算上限。CVE でも同じ |
| `llm/analyzer.py` のプロバイダ呼び出し層（Gemini 思考抑制・OpenRouter・Anthropic） | 呼び出し部分だけ切り出してコピー。RSS 向け `SYSTEM_PROMPT`・genre・sentiment は捨てる | 1,269 行のうち要るのは 1/3 程度（推測） |
| `llm/copycheck.py` | コピー + 英文判定を調整（§6.4） | 生成文と一次文面の連続一致検査は CVE でも必要 |
| `notifications/discord.py` | 後段でコピー | Discord 配信に流用。Slack は Incoming Webhook で新規（形が近い）。`webpush.py` は使わない |
| `docs/editorial-style.md` の書き方の節 | 文面を CVE 向けに書き直して流用 | 「先頭 2 文で何が起きたか・環境に何が変わるか」はそのまま使える |
| `judge/` の考え方（質問を分けて confidence を見る、promptVersion、shadow→live、正解ラベルで評価） | **設計だけ流用**。コードは Jev 依存が強いので持ってこない | 緊急度の LLM 補足も shadow で始める |
| `config.py`（pydantic-settings）、`db/session.py` | 型だけ流用 | |

### 2.3 作り直す（CVE には合わない）
- `rss/crawler.py`・`urlnorm.py`・`fetch_body.py`: 入力が RSS/HTML ではなく JSON API。取得層は新規。
- `signals/novelty.py`（固有名詞初出）・`emerging`・`coverage`: CVE には ID が付いていて重複判定は ID で済む。novelty はほぼ不要。coverage は「何ソースが同じ CVE を載せたか」に置き換え可能（新規で小さく書く）。
- `signals/stories.py`: CVE は「同じ CVE への更新」が束ねの単位で、埋め込みも Jev も要らない。**更新履歴テーブルで置き換え**。
- `pipelines/scheduler.py`・`notify.py`（常駐）: **systemd --user timer の one-shot** に置き換え（§10）。
- `signal-digest-web` 全体: Next.js 14 + Prisma/PostgreSQL + 認証・管理画面。D1 + Workers 前提だと **コードの流用は ✗**（§9.3）。UI の型（一覧→詳細、紙面レイアウト仕様、速読モード）は参考にする。
- `models/tables.py`: 新規スキーマ（§3.4）。

---

## 3. 一次ソース

### 3.1 一覧（2026-11-06 時点で確認した内容）

凡例: 頻度 = 推奨取得間隔。認証 = 必要/任意/不要。「未確認」= 一次ページで確認できなかった。

| # | ソース | API / 取得口 | 推奨頻度 | 認証 | レート制限 | 利用規約・ライセンス（表示条件） | 備考 |
|---|---|---|---|---|---|---|---|
| 1 | NVD CVE API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0`（`lastModStartDate/EndDate`、最大 120 日幅、`resultsPerPage` 最大 2000） | 30 分〜2 時間 | 任意（キーで上限 10 倍） | **5 req / 30 秒**（キー無）、**50 req / 30 秒**（キー有）[S1][S2] | 表示義務: 「**This product uses the NVD API but is not endorsed or certified by the NVD.**」を目立つ場所に。NVD 名は出典表示にのみ使い、推奨を示唆しない。**改変した内容を NVD に帰属させない**。キーの共有禁止。as-is・無保証 [S1] | 2026-10 公開数 17,481（実測）。`vulnStatus: Deferred` が多い |
| 2 | NVD CVE Change History API | `.../cvehistory/2.0`（`changeStartDate/EndDate`、`eventName` フィルタ） | 30 分 | 同上 | 同上 | 同上 | 2026-11-04 の 1 日で 2,698 イベント、うち「CVE Modified」1,537（実測） |
| 3 | CVE.org / cvelistV5 | GitHub `CVEProject/cvelistV5`: 約 7 分ごと更新。**毎時の delta zip** と `deltaLog.json`（直近 30 日）、日次の全件 zip [S3] | 1 時間（delta zip） | 不要 | GitHub の配布物取得（API 不使用なら制限なし） | CVE Terms of Use: 永続・無償の複製・派生・配布ライセンス。**MITRE の著作権表示と本ライセンスを複製物に再掲**。as-is。「CVE」は MITRE の登録商標 [S4][S4b] | **git clone は ✗**: リポジトリ 3.2GB（gh api `size` 実測 3,315,426KB）。空き 17GB では不可 |
| 4 | CISA KEV | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`、GitHub `cisagov/kev-data`（数分以内に同期） | 1 時間 | 不要 | 未確認（静的 JSON） | **CC0 1.0**。CISA ロゴ・DHS 印の使用不可、推奨を示唆しない [S5][S5b] | 1,768 件。2026 年の月間追加 23〜43 件（実測） |
| 5 | GitHub Advisory Database | REST `GET /advisories`（`ecosystem=npm`、`published`/`modified` 範囲、`severity`、`type=reviewed`、`per_page≤100`、cursor）[S6]。GraphQL `securityAdvisories`。リポジトリ `github/advisory-database`（OSV 形式） | 30 分 | 任意 | REST **60/時（未認証・IP）、5,000/時（PAT）**[S7]。GraphQL 2,000 pt/分 | **CC-BY 4.0**（リポジトリ LICENSE）[S8]。帰属 + ライセンス名 + 変更の明示（翻訳・要約は改変） | npm reviewed 2026-10: 200 件超（2 ページ満杯、実測）。リポジトリ 3.4GB → clone ✗ |
| 6 | OSV.dev | `POST /v1/query`、`/v1/querybatch`、`GET /v1/vulns/{id}`。GCS `gs://osv-vulnerabilities/<ECO>/all.zip`、`modified_id.csv` [S9][S10] | 1 時間 | 不要 | 「現在制限なし」[S9] | **レコードごとに上流ライセンス**（CC-BY 4.0 / CC0 / MIT / Apache-2.0 / CC-BY-SA / CC-BY-NC-ND が混在）[S10]。Google 側の利用規約は未確認 | Debian / Alpine / Red Hat / Ubuntu の変換データも含む。GHSA と重複するので **npm は GHSA 直、ディストリは OSV 経由**が整理しやすい |
| 7 | Node.js 本体 | `nodejs.org/en/feed/vulnerability.xml`（RSS、実測 200）、`nodejs/security-wg` の `vuln/core/index.json`（204 件、CVE・影響版・修正版・ref）[S11] | 1 時間 | 不要 | GitHub raw: 未確認（軽い） | `nodejs/security-wg` は **MIT**（gh api 実測）。nodejs.org ブログ本文の再利用条件は未確認 → 要約 + リンクのみ | 月例セキュリティリリースは事前予告（2026-11-11 分が 11-03 に予告、実測） |
| 8 | npm advisories | `registry.npmjs.org/-/npm/v1/security/advisories/bulk`（実測で応答あり） | — | 不要 | 未確認 | **✗ 使わない**。npm Open Source Terms: セキュリティデータは「個人・社内利用に限る。他者に提供したり他の製品・サービス内で使わない」[S12] | 内容は GHSA と同一（URL が GHSA）。**GHSA（CC-BY 4.0）に置き換える** |
| 8b | npm ダウンロード数 | `api.npmjs.org/downloads/point/last-week/<pkg>` | 記事生成時だけ | 不要 | 未確認（Terms: 月 500 万 req は不合理）[S12] | Public API 経由の複製は許容（Terms 9 項）[S12] | 影響範囲の指標に使う |
| 9 | Debian Security Tracker | `security-tracker.debian.org/tracker/data/json`（**88MB**、`cache-control: max-age=3600`、実測） | **2〜4 回/日**（1 時間ごとは重い） | 不要 | 未確認 | **データのライセンス未確認**。salsa リポジトリに LICENSE/README 無し（実測 404）。debian.org の Web 文書は 2012 年以降 MIT(Expat)/GPL だがトラッカーデータを含むか不明 [S13] | 確認できるまで**リンク + 事実（修正版番号・状態）のみ**。OSV の Debian 変換データで代替可 |
| 10 | Ubuntu Security | `ubuntu.com/security/cves.json`、`/security/notices.json`、`/security/notices/rss.xml`（実測 200）。OVAL も有り | 1 時間 | 不要 | 未確認 | **データのライセンス未確認**（Canonical IP ポリシー文書は CC-BY-SA 3.0 UK だが対象はその文書自身 [S14]）。`ubuntu-cve-tracker` README に記載なし | 同上。要問い合わせ |
| 11 | Red Hat Security Data | `access.redhat.com/hydra/rest/securitydata/cve.json?after=...&per_page=...`（実測で応答あり）。CSAF/VEX、OSV 変換 | 1 時間 | 不要 | 未確認（HEAD は 405） | **CC BY 4.0**。配布・改変時は Red Hat への帰属と原文リンク [S15] | severity（important/critical）が kernel 間引きに使える |
| 12 | Linux kernel CNA | `linux-cve-announce` ML、`git.kernel.org/pub/scm/linux/security/vulns.git`、NVD 上は `sourceIdentifier=416baaa9-...` | NVD 経由で十分 | 不要 | — | CVE レコードなので CVE Terms。`docs.kernel.org/process/cve.html`: stable に修正が入った bugfix に広く CVE を付与（「overly cautious」）、無修正に自動付与なし、該当性はユーザー判断 [S16] | **2026-10 に 1,054 件（NVD 実測、全体の 6%）**。CVSS は CNA が付けないことが多い（推測。docs に CVSS の記述なし） |
| 13 | FIRST EPSS | `api.first.org/data/v1/epss?cve=...`（複数 CVE カンマ区切り 2,000 字まで、`date`、`scope=time-series`）[S17]。日次 CSV | 1 日 1 回（**13:30 UTC 直後**に更新）[S18] | 不要（認証非対応） | **1,000 req/分**（公開）[S19] | 「**Attribution is requested** when EPSS data is used in publications or products」[S18]。明示ライセンスなし（フッタは All Rights Reserved）→ **要確認** | 応答は `cache-control: max-age=86400`（実測） |
| 14 | CISA Vulnrichment | `cisagov/vulnrichment`（CVE レコードへの CVSS/CWE/CPE 補完） | cvelistV5 経由 | 不要 | — | 未確認（CVE レコードの一部として配布） | kernel CNA の CVSS 欠落を補う可能性（推測） |

### 3.2 取得方針（推薦）
- **骨格は NVD（CVE + Change History）**。1 回の同期で `lastModStartDate` を前回時刻にして取る。1 日 2,700 変更 ≒ 2 ページ（2000/頁）なので 30 分ごとでも 1〜2 req/同期。**NVD API キーは取得する**（無料。50/30 秒）。
- **KEV / EPSS / GHSA(npm) / Node.js / Red Hat / Ubuntu** を並走させ、CVE ID でマージ。
- **Debian** は 1 日 2〜4 回に抑える（88MB）。Workers からは扱えない（メモリ 128MB、§9）。
- **cvelistV5 / advisory-database は clone しない**。必要なら毎時 delta zip（数 MB、推測）。
- **npm advisories API は使わない**（規約）。

### 3.3 1 日あたりの件数（見積りの根拠）
| 指標 | 値 | 根拠 |
|---|---|---|
| NVD 新規公開 | 約 560 件/日 | 2026-10 月間 17,481（実測） |
| NVD 変更イベント | 約 2,700 件/日 | 2026-11-04（実測） |
| kernel CNA | 約 34 件/日 | 2026-10 月間 1,054（実測） |
| CVSS v3 CRITICAL（全体） | 約 3 件/日 | 2026-10 月間 92（実測） |
| GHSA npm reviewed | 7 件/日以上 | 2026-10 で 200 超（実測、3 ページ目未確認） |
| KEV 追加 | 約 1 件/日 | 月 23〜43（実測） |
| 対象スタック該当（推測） | 新規 30〜80 件/日、掲載 5〜20 件/日 | NVD の CPE/CNA でのフィルタ後。実装後に実測して補正 |

---

## 4. 緊急度判定

### 4.1 原則
- **緊急度（tier）はルールだけで決める。LLM は上げ下げしない。** 理由: 説明可能性（「なぜ緊急か」を根拠行で示せる）、再現性、誤判定時の責任の所在（§7-18）。
- LLM は「読者向けの説明」「該当条件の抽出」「補助シグナルの要約」を担当し、出力には **`llm_generated=true` を付けて表示上も区別**する。
- LLM が「ルールより高い/低いと思う」場合は **`review_flag` を立てるだけ**（人が見る。tier は変えない）。signal-digest の shadow 運用に相当。

### 4.2 対象スタックのフィルタ（ルール）
| 対象 | 判定材料 | 備考 |
|---|---|---|
| Node.js 本体 | `nodejs/security-wg` index、nodejs.org 脆弱性 RSS、NVD CPE `cpe:2.3:a:nodejs:node.js` | 月例リリースの予告も「予告」として掲載 |
| npm パッケージ | GHSA `ecosystem=npm`（reviewed のみ）、OSV `npm` | 週間 DL 数で影響範囲を重み付け |
| Linux kernel | NVD `sourceIdentifier` = kernel CNA、CPE `linux_kernel` | §4.5 の間引き |
| ディストリ | Debian / Ubuntu / Red Hat に該当エントリがある CVE | 「どのディストリで修正済みか」を表に出す |
| その他 | 設定ファイル（YAML）で vendor/product を追加できるようにする | 初期は空。拡張点だけ用意 |

### 4.3 スコアと tier（ルール）
入力: CVSS（v4.0 があれば優先、無ければ v3.1。NVD と CNA の両方あれば高い方）、EPSS（score / percentile）、KEV、影響範囲（npm 週間 DL、ディストリ採用数）、更新種別。

| tier | 条件（いずれか） | 表示 |
|---|---|---|
| **P0 緊急** | KEV に入った / CVSS ≥ 9.0 かつ EPSS ≥ 0.10 / Node.js 本体の High 以上 / ディストリ 2 つ以上が critical・important 相当 | 即時掲載 + 通知 |
| **P1 重要** | CVSS ≥ 7.0 / EPSS percentile ≥ 0.90 / npm 週間 DL ≥ 100 万の High 以上 / KEV 候補（PoC 公開の補助シグナルあり） | 掲載 + 日次まとめで通知 |
| **P2 情報** | 対象スタック該当で上記未満 | 一覧のみ。記事は生成しない |
| **P3 記録** | kernel CNA で間引き対象、`Deferred`、`Rejected` | DB にだけ残す。週次の件数集計に出す |

- 閾値は設定値として外に出す。初期値は上表。**2 週間 shadow で動かして件数を見てから本番値を決める**（受け入れ条件: P0+P1 が 20 件/日以下）。
- 「更新」の扱い: 変更イベントで tier が上がった場合のみ再掲載（CVSS 追加・KEV 追加・EPSS が 0.2 以上上昇 or percentile 0.9 超え・ディストリ修正公開）。下がった場合は記事に「更新履歴」として追記するだけ。
- 重複統合: CVE ID で一意。GHSA は `cve_id` で寄せ、CVE が無い GHSA は GHSA ID を主キーにする。

### 4.4 更新差分の検知（ルール）
- NVD Change History の `eventName`（CVE Received / Modified / Rejected 等）と `details[].type`（CVSS V3.1 / CVSS V4.0 / Reference / CPE 等）を解釈し、**種別ごとの差分行**を `cve_event` に積む。
- KEV は `dateAdded` の新出、GHSA は `modified`、EPSS は前日との差、ディストリは「修正済み」状態の変化。
- 1 CVE の記事は 1 本。更新は記事下部の時系列に積む（signal-digest のストーリー時系列の簡略版。LLM 不要）。

### 4.5 kernel CNA の間引き（ルール）
月 1,000 件を全部出すと読めないので、**次のいずれかを満たすものだけ P1 以上に上げる**。それ以外は P3。
1. KEV に入った
2. Debian `urgency` high / Ubuntu `priority` high・critical / Red Hat `severity` important・critical のいずれか（ディストリが人手で重みを付けた結果を借りる）
3. EPSS percentile ≥ 0.90
4. NVD/Vulnrichment で CVSS ≥ 8.0 が付いた
5. 補助シグナルで PoC 公開を検知（P1 まで。P0 には上げない）

P3 の kernel CVE は **週次「kernel CVE 件数」1 本**にまとめる（サブシステム別件数の表。LLM 不要）。

### 4.6 LLM に任せる範囲
目的は **危険性を正しく伝えること**。LLM の担当は次の 3 つに絞る（緊急度 tier は §4.1 のとおりルールで決め、LLM は変えない）。

| 役割 | 入力（一次ソースのみ） | 出力 | 検査（ルール） |
|---|---|---|---|
| **① 日本語訳** | CVE description、GHSA 本文、KEV の shortDescription / requiredAction、Red Hat の説明（いずれも翻訳＝翻案が許可されたもの。§6.1） | 原文に忠実な日本語訳。製品名・版番号・CVE/CWE ID・関数名は原文のまま | 原文にある版番号・ID がすべて訳文に残っているか（正規表現で突き合わせ）、訳文にしか無い数字・製品名が無いか |
| **② 起こりうるリスクの説明** | CVSS ベクトル（AV / AC / PR / UI / S / C / I / A、v4 は VC/VI/VA 等）、CWE、影響製品と版、KEV 入りの有無、EPSS、補助シグナル（PoC 公開の有無・件数） | 「攻撃者に何ができるか」「前提条件（ネットワーク越しか・認証が要るか・ユーザー操作が要るか）」「該当する人」「すぐやること（更新先の版・回避策）」を 4 項目で。3〜6 文 | 前提条件の記述が CVSS ベクトルと矛盾しないか（例: `AV:N/PR:N` なのに「ログインが必要」と書いたら破棄して再生成）。修正版の番号が一次ソースと一致するか。一次ソースに無い被害（「情報漏えいの事例がある」等）を書いたら破棄 |
| **③ 続報（変化の伝達）** | §4.4 で検知した差分行（前後の値・ソース・時刻）と、既存記事の要点 | 見出し 1 行 +「何が変わり、読者にとって何を意味するか」2〜3 文（例:「KEV に追加された＝実際の攻撃が確認された。更新の優先度を上げてください」） | 差分行に無い変化を書いていないか。数値は差分行から機械的に差し込む（LLM には書かせず、テンプレートの穴に埋める） |

補助: 該当条件の抽出（`affected_when` / `fixed_in` / `workaround` の JSON）は ② の材料として行う。ルール側の値と矛盾したら LLM の値を捨てて `review_flag`。

**書き方の原則（危険性を伝えるため）**
- 「危険です」の形容ではなく、**何が起きるか・誰が該当するか・何をするか**で書く。誇張（最上級表現・煽り）も過小評価もしない。
- 不明なことは不明と書く（「悪用の報告は現時点で一次ソースに無い」）。推測で被害を足さない。
- 訳文（①）と説明（②③）は表示上分ける。①には「原文」へのトグルを付け、②③には「LLM による説明」を明示する。

**続報の流れ（③）**
- 差分のうち読者に意味があるもの（CVSS の追加・変更、KEV 追加、EPSS の急上昇、修正版の公開、ディストリの修正、PoC 公開、Rejected）だけを続報にする。参照 URL の追加などは時系列に積むだけで続報にしない。
- tier が上がった続報は記事を先頭に戻し、配信チャネルにも流す。下がった続報は記事に追記するだけ（配信しない）。
- 1 CVE = 1 記事。続報は記事内の時系列と、記事冒頭の「最新の状況」に反映する。

**前段の仕分け（Jev、shadow）**: ルールで対象スタックが決まらない CVE（CPE 無し・GHSA 無し・kernel CNA でない）だけ、NVD の英語説明文を TypeSafe の Jev に渡し、種別（`kind`）と対象スタックとの関係（`stack`: `nodejs_core` / `npm_package` / `linux_kernel` / `linux_distro_package` / `none`）を**固定選択肢**で答えさせて `llm_triage` に記録する。自由記述はさせない。tier は変えず、`stack` が `none` 以外で confidence が閾値（既定 0.6）以上のものに**候補**（`triage_candidate`）として印を付けるだけ。精度は後からルールでも対象スタックになった件数（tier 行との突き合わせ）で確かめる。

- プロバイダ: **Gemini**（決定）。① ③ と P2 の ② は `gemini-3.1-flash-lite` 相当、P0/P1 の ② は `gemini-3.8-flash` 相当（signal-digest の実測で原文の重要語保持が 96%。flash-lite は 67%）。モデル名は設定値。思考トークンは signal-digest と同じく既定 0。
- 無料枠は 3.8-flash が 20 req/日（signal-digest の実測）で足りないため、**課金（prepay）を有効にしたキー**を前提にする。
- signal-digest の BYOK・マルチプロバイダは不要。1 プロバイダ + フォールバック（Gemini Flash 相当）で十分。

### 4.7 誤判定時の扱い
- tier はルールの結果なので、誤りは **閾値かデータの誤り**。修正は設定変更 or ソース側の訂正取り込みで行い、その履歴を記事の時系列に残す（「2026-11-06 CVSS 9.8 → 7.5 に変更（NVD）」）。
- LLM の説明が誤っていた場合は記事を再生成し、旧版を `article_revision` に残す。訂正は見出し下に「訂正」の印。
- 手動の上書き（運用者が tier を変える）は **許可するが理由必須**で、記事に「編集部判断」と出す。

---

## 5. 補助シグナル（PoC 公開・悪用報告・ベンダー声明）

### 5.1 位置づけ
- **本文の情報源にしない。** 表示は「状況」欄に件数・最初に観測した時刻・出典リンクのみ。投稿本文・投稿者名は保存も表示もしない。
- 使途: (a) P1→P0 の候補フラグ（自動では上げない）、(b) 「公開 PoC あり」の**事実の表示（リンクなし）**、(c) ベンダー声明へのリンク。
- **PoC・エクスプロイトへのリンクは出さない**（§7-17）。配信の目的（危険性を伝える）には「公開されている」という事実だけで足りる。

### 5.2 取得手段の比較

| 手段 | 取り方 | 規約・制限（確認結果） | 月額（概算） | 評価 |
|---|---|---|---|---|
| **X API** | pay-per-use のみ（サブスク廃止）。Post 読み取り **$0.005/件**、User 読み取り $0.010/件、月 300 万 Post 読み取り上限 [S21]。初回入金後 $20 クレジット | Developer Agreement: Licensed Material の再配布・派生物作成を禁止（明示許可を除く）、削除・非公開化に 24 時間以内の追従、Display Requirements 準拠、基盤モデル学習禁止、制限回避禁止 [S22]。Restricted Use: hydrated content の**公開発信禁止**、監視目的禁止 [S23]。x.com ToS はスクレイピング禁止（本文は 403 で未確認、二次情報） | 1 日 200 件読むと $30/月。表示には使えないので費用に見合わない | **✗（v1 では使わない）**。「件数だけ表示」でも派生物/監視と解釈されうる → 要確認（弁護士） |
| **Bluesky（AT Protocol）** | `public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=CVE-...`（AppView、認証非対応・キャッシュ有）[S24]。Jetstream（WebSocket firehose、常駐が要る） | PDS: 3,000 req/5 分/IP [S24]。開発者ガイドラインは spam・UGC 機能・削除対応・連絡先の義務 [S25]。投稿の著作権は投稿者 | $0 | **○**。ただし **本サーバーから curl すると 403**（実測。UA/経路の問題か不明）→ Workers からの疎通を要確認。Jetstream は常駐なので ✗ |
| **Mastodon** | `GET /api/v1/timelines/tag/:hashtag`（instance 設定次第で認証必要）[S26]。300 req/5 分/IP [S27] | `infosec.exchange` は未認証で **422**（実測）→ アカウント + トークンが要る。instance ルール: bot は明示、自動投稿は制限 [S28]。`mastodon.social` は未認証 200（実測） | $0 | **○**。infosec.exchange はアカウント作成が要る（規約同意）。読み取りだけなら投稿ルールには触れない |
| **GitHub（PoC リポジトリ）** | Search API `q=CVE-2026-xxxxx`（repositories / code）。**10 req/分（未認証）、30 req/分（PAT）**、結果 1,000 件まで [S29] | リポジトリ名・URL・star 数のみ保存。コードは取らない | $0 | **◎**。最も一次に近い「PoC 公開」の証拠。P0 候補は 1 日数十件なので 30/分で足りる |
| **Exploit-DB** | RSS `/rss.xml`、GitLab ミラー（GPL-2.0、`files_exploits.csv`） | ToS: Service の複製・再利用禁止、自動負荷禁止、API トークン共有禁止 [S30]。→ **ミラーの CSV（ID・CVE・タイトル）とリンクのみ** | $0 | ○ |
| **Metasploit / nuclei-templates** | GitHub リポジトリの検索（`CVE-` を含むファイル追加の commit）。Metasploit **BSD-3-Clause**、nuclei-templates **MIT**（実測） | ライセンス上は転載も可。方針として ID とリンクのみ | $0 | ◎（「検出テンプレあり」「モジュールあり」の二値） |
| **Claude などエージェント経由**（API + Web 検索ツール） | P0 候補ごとに「この CVE の PoC・悪用報告・ベンダー声明を探せ」 | Web 検索ツールの単価は今回未確認（pricing ページの本文に見当たらず）。モデル費: Sonnet 5.5 で 1 回 20k in / 2k out ≒ $0.06 | 1 日 10 件 × 30 日 ≒ **$18〜30/月 + 検索ツール費** | △。出典が二次サイトになりやすく、本文に混ざるリスク。**ベンダー声明の URL 探索**に限定するなら ○ |

### 5.3 推薦
- v1: **GitHub Search（PAT 1 本）+ Metasploit/nuclei の commit 監視 + Exploit-DB ミラー CSV**。費用 $0、規約リスク最小。
- v1.5: **Bluesky 公開検索**（Workers から疎通確認後）。**Mastodon** は mastodon.social の公開タグで開始、infosec.exchange はアカウント作成の可否をユーザーが決める。
- X は使わない。エージェント経由は「ベンダー声明 URL の探索」に限定し、月 $20 上限で試す（任意）。

### 5.4 表示
- 「状況」欄: `公開 PoC: あり（GitHub で 2 件を観測、最初 11/05 14:10 UTC） / Metasploit モジュール: なし / 投稿: Bluesky 5 件・Mastodon 3 件（件数のみ）`。
- リンクを出すのはベンダー声明・修正版などの**対策側の一次情報だけ**。PoC リポジトリ・Exploit-DB・Metasploit モジュール・SNS 投稿へのリンクは**出さない**。
- PoC の URL は判定の根拠として作業 DB（N100 のローカル SQLite）にだけ残し、D1・公開 API・配信には載せない。投稿本文・ID・投稿者は保存しない（§7-16）。

---

## 6. 著作権・出典

### 6.1 一次ソースの文面をどこまで使うか
| ソース | ライセンス | 原文（英語）の転載 | 翻訳・要約 | 出典表示の書式 |
|---|---|---|---|---|
| CVE description（CVE.org / cvelistV5 / kernel CNA） | CVE Terms（複製・派生・配布可、著作権表示 + ライセンス再掲）[S4b] | ○（「原文」欄に全文可） | ○ | `出典: CVE-2026-xxxxx（CVE Program） © The MITRE Corporation. CVE Terms of Use に基づき掲載` + フッタにライセンス全文リンク |
| NVD の付加情報（CVSS、CPE、参照） | NVD Terms（表示義務、改変物の帰属禁止）[S1] | ○（値） | 翻訳したら「NVD の記述」とは書かない | フッタ常設: `This product uses the NVD API but is not endorsed or certified by the NVD.` 記事内は `CVSS 9.8（NVD）` |
| GHSA 本文 | CC-BY 4.0 [S8] | ○ | ○（改変を明示） | `出典: GHSA-xxxx（GitHub Advisory Database, CC BY 4.0）。日本語訳・要約は当サイトによる` |
| KEV（shortDescription・requiredAction） | CC0 [S5] | ○ | ○ | `出典: CISA KEV`（ロゴ不可） |
| Red Hat（CVE ページ・CSAF） | CC BY 4.0 [S15] | ○ | ○ | `出典: Red Hat Security Data（CC BY 4.0）` + 原文リンク |
| EPSS | 明示ライセンスなし、帰属の要請 [S18] | 値のみ | — | `EPSS 0.93（FIRST.org EPSS, 2026-11-06）` + フッタ `EPSS scores: Forum of Incident Response and Security Teams (FIRST)` |
| Debian / Ubuntu | **未確認** | ✗（確認まで） | **事実のみ**（修正版番号・状態・URL） | `Debian: bookworm 修正済み（1.2.3-1+deb12u1）` + リンク |
| Node.js 公式ブログ | 未確認（security-wg の JSON は MIT） | ✗ | ○（要約のみ、2〜3 文） | `出典: Node.js Security Releases（nodejs.org）` + リンク |
| ベンダーアドバイザリ全般 | 各社 | ✗ | ○（要約。引用は必要最小限、明瞭区別） | リンク必須 |
| SNS 投稿 | 投稿者 | ✗ | ✗（件数のみ） | — |

### 6.2 LLM 生成文の扱い
- 生成文は **当サイトの著作物として扱い CC BY 4.0 で公開**（§8.2。コードは MIT、記事は CC BY 4.0 で決定）。ただし原文引用部は元ライセンスが優先することを記事フッタに書く。
- 記事に「この説明は LLM（モデル名）が一次ソースから生成し、ルールで検査したものです」を常設。
- 「原文に無い事実を足さない」「ベンダーの対応を評価しない」「最上級表現なし」は editorial-style から流用。

### 6.3 免責表示（草案）
> 本サイトの緊急度は公開データ（NVD / CVE / CISA KEV / GitHub Advisory Database / FIRST EPSS 等）を機械的に組み合わせた目安であり、特定の環境での影響を保証するものではありません。対策の要否は各自の環境で判断してください。本サイトは無保証（as is）で提供され、掲載内容の誤りや遅延により生じた損害について責任を負いません。誤りの指摘は <連絡先> まで。

### 6.4 copycheck の流用
- 流用可。ただし調整が要る:
  - CVE description・GHSA 本文は **引用が許可**されているので、検査対象は「LLM 生成の説明文」×「ベンダーブログ本文・Debian/Ubuntu の記述」に絞る。
  - 英文判定（小文字 20 字以上・大文字 1 割以下）は英語の説明文を生成する場合に効く。日本語生成なら現行ロジックのまま。
  - 30 字の閾値は CVE 文面（製品名・版番号の羅列が長い）で誤検知しやすい → ホワイトリスト（製品名・CPE 文字列）を除外してから比較する。

---

## 7. 法的リスクの洗い出し

凡例: 回避できた = 設計で回避済み（根拠あり）。要確認 = 誰に確認するか。残るリスク = 回避後も残るもの。

| # | 項目 | 回避できた | 要確認（誰に） | 残るリスク |
|---|---|---|---|---|
| 1 | NVD 利用規約 | ○ 表示文をフッタ常設、改変物を NVD に帰属させない、キーは 1 人で使う [S1] | — | ほぼなし |
| 2 | CVE Terms of Use | ○ 著作権表示 + ライセンス再掲 [S4b] | △ 現行ページ本文を**ブラウザで確認**（JS 描画で取得不可。今回はミラー + 旧サイト）→ ユーザー | 低 |
| 3 | KEV（CC0） | ○ | — | ロゴ使用禁止のみ注意 |
| 4 | GHSA（CC-BY 4.0） | ○ 帰属・ライセンス名・改変の明示 | — | 低 |
| 5 | EPSS | △ 帰属表示はする | **FIRST に利用条件を確認**（明示ライセンスなし、フッタ All Rights Reserved）→ ユーザーがメール or 弁護士 | 中（商用でないなら実務上低いと推測） |
| 6 | Red Hat（CC BY 4.0） | ○ | — | 低 |
| 7 | Debian トラッカーデータ | △ 確認まで事実 + リンクのみ | **Debian セキュリティチームに確認**（team@security.debian.org）→ ユーザー | 中。事実（版番号）は著作物性が低いと推測 |
| 8 | Ubuntu Security データ | △ 同上 | **Canonical に確認** → ユーザー | 同上 |
| 9 | Node.js 公式ブログ本文 | ○ 要約 + リンクのみ | — | 低 |
| 10 | npm advisories API | ○ **使わない**（規約が製品内利用を禁止）[S12] | — | なし |
| 11 | npm ダウンロード数 API | ○ 公開 API・低頻度 | — | 低 |
| 12 | OSV.dev 集約データ | △ レコードごとに上流ライセンスを記録・表示 | Google の API 利用規約 → ユーザー（docs に記載なし） | 低 |
| 13 | kernel CNA レコード | ○ CVE Terms に従う | — | 低 |
| 14 | 引用・要約（著作権法 32 条） | ○ 主従関係・明瞭区別・出典・必要最小限を設計で担保（copycheck） | 翻訳は翻案 → ライセンスで許可される範囲（CVE/GHSA/RH）に限定。ベンダーブログは要約のみ | 低〜中 |
| 15 | X 由来の情報 | ○ **v1 では使わない** | 将来使うなら Developer Agreement の派生物・公開発信禁止 [S22][S23] を弁護士に | 使えば高い |
| 16 | Bluesky / Mastodon 投稿 | ○ 本文・投稿者名を保存・表示しない。件数のみ。投稿へのリンクも出さない | infosec.exchange のアカウント規約（読み取り専用でも同意が要る）→ ユーザー | 低。件数集計は個人情報を含まない |
| 17 | PoC の扱い | ○ **リンクを出さない**。「公開 PoC あり」の事実と件数だけ表示。URL は作業 DB にだけ残し公開しない（§5.4） | — | 低。事実の記載は報道・注意喚起の範囲。リンクを出す場合は刑法 168 条の 2・3（不正指令電磁的記録の提供・供用）や幇助の論点が生じうるため、方針を変えるときは弁護士に確認 |
| 18 | 誤報・誤った緊急度判定の責任 | △ 免責表示（§6.3）、tier の根拠表示、訂正履歴、連絡窓口、無償・非保証 | 免責文の妥当性 → 弁護士（任意） | 中。完全には消えない。「目安」の表示を徹底 |
| 19 | 商標（「CVE」は MITRE 登録商標 [S4b]） | ○ **サイト名に「CVE」を入れない**（§9.7）。ロゴ不使用、記事中の「CVE-2026-xxxx」表記は識別子としての使用。「CVE Program と無関係」を明記 | サイト名候補の商標調査（J-PlatPat・USPTO）→ ユーザー | 低 |
| 20 | 名誉・ベンダー評価 | ○ 「対応が遅い」等の評価を書かない（editorial rule + LLM 検査） | — | 低 |
| 21 | 個人情報（研究者クレジット等） | ○ 一次ソースの表示のまま。独自収集しない | — | 低 |
| 22 | LLM 生成の表示 | ○ 記事ごとに明記 | — | 低 |
| 24 | メール配信（受信者のアドレス） | ○ 公開の登録フォームを置かず、運営者が CLI で登録（§9.6）。同意の日付・方法を必須で記録。全メールに送信者名・連絡先・配信停止の方法。アドレスは N100 のローカル DB だけに置き、D1・公開リポジトリには入れない | 特定電子メール法の同意記録と表示義務の細目 → 総務省のガイドラインで確認 | 低。N100 の DB ファイルの漏えい（chmod 600・バックアップの扱い） |
| 25 | TypeSafe（Jev）への送信 | ○ 送るのは NVD の英語説明文のみ。ベンダー表明「顧客データで学習しない」 | 保持期間は DPA 未確認 → **TypeSafe の DPA・MCA を確認** → ユーザー | 出力（仕分け結果）の再配布条項が未確認 |
| 23 | 免責表記の設置場所 | ○ フッタ常設 + /about + 記事末尾 | — | — |

**ドメイン取得の判断基準（§9.5）**: 上表の「要確認」のうち **#2, #5, #7, #8, #19（サイト名の商標調査）** が「確認済み or 代替策で回避」になったとき。#24 はメール配信を始める前まで。それまでは `*.workers.dev` + `noindex` で運用する。

---

## 8. OSS 化とライセンス

### 8.1 秘密情報の扱い（公開リポジトリ前提）
| 置き場所 | 方法 | 根拠・備考 |
|---|---|---|
| Workers のシークレット | `wrangler secret put <KEY>`（本番）、ローカルは `.dev.vars` または `.env`（**どちらか一方**）。`.dev.vars*` と `.env*` を `.gitignore` [S31] | `wrangler.jsonc` の `database_id` / `account_id` は秘密ではないが、D1 の **API トークンは Workers 側には不要**（binding で済む） |
| N100 側（収集バッチ） | `~/.config/vuln-signal/env`（chmod 600）を systemd `EnvironmentFile=` で読む。リポジトリには `env.example` だけ | signal-digest も `.env` 運用。vuln-signal は**リポジトリ外**に置く |
| GitHub Actions | `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` を Actions secrets。デプロイは `wrangler deploy --secrets-file`（任意）[S31] | fork からの PR では secrets が渡らない（GitHub 既定） |
| 漏えい検査 | **gitleaks** を pre-commit（`gitleaks protect --staged`）と CI（`gitleaks/gitleaks-action`）の両方。`.gitleaks.toml` で `env.example` を allowlist | 初回 push 前に `gitleaks detect` で履歴全体を検査（空リポジトリなので今が最も安い） |
| D1 ダンプ・ログ | `wrangler d1 export` の出力、`usage` ログは `.gitignore`。LLM 入出力ログにキーが混ざらないよう usage.py はキーをログに出さない（signal-digest と同じ） | |

### 8.2 ライセンス案（コード / 配信データ・記事）
| 対象 | 案 1 | 案 2 | 推薦 |
|---|---|---|---|
| コード | **MIT**（決定） | — | **MIT**。一次ソースの帰属表示は `NOTICE` ではなく `/about` と `LICENSE-DATA.md` に集約する |
| 記事（LLM 生成の説明・解説・緊急度） | **CC BY 4.0**（決定） | — | **CC BY 4.0**。GHSA（CC-BY 4.0）と同系で整合。ただし記事内の **引用部は元ライセンス**（CVE Terms / CC0 / CC BY 4.0）に従う旨を明記 |
| 配信データ（D1 のエクスポート、JSON API） | 「本サイトの付加項目（tier、根拠、翻訳）は CC BY 4.0。一次ソース由来の列はそれぞれのライセンス」を `LICENSE-DATA.md` に書く | ODbL | 案 1。**Debian/Ubuntu 由来の列はライセンス確認まで配布しない**（API に出さない） |

整合性チェック（事実）: CVE Terms は再配布・派生を許可（表示条件あり）、KEV は CC0、GHSA/RH は CC BY 4.0 → CC BY 4.0 の記事に取り込める。NVD は「改変物を NVD に帰属させない」だけなので CC BY 4.0 の自作文に含めても矛盾しない。EPSS は値のみで帰属表示。**CC BY-SA / CC BY-NC-ND のレコード（OSV に混在）は取り込まない**（NC-ND は派生不可）。

### 8.3 公開リポジトリに置かないもの
- 閾値以外の「運用者の手動上書き」履歴、連絡先メール、infosec.exchange のアカウント情報。

---

## 9. ホスティング（Cloudflare）

### 9.1 制限と料金（developers.cloudflare.com、2026-11-06 確認）
| 項目 | Workers Free | Workers Paid（$5/月〜） | 出典 |
|---|---|---|---|
| リクエスト | 100,000/日 | 1,000 万/月込み、超過 $0.30/100 万 | [S32][S33] |
| CPU 時間 / 呼び出し | **10 ms** | HTTP 既定 30 秒（最大 5 分）。**Cron: 間隔 1 時間未満は 30 秒、1 時間以上は 15 分** | [S32] |
| Cron の wall-clock | 15 分 | 15 分 | [S32] |
| サブリクエスト / 呼び出し | **50** | 10,000（設定で最大 1,000 万） | [S32] |
| 同時外向き接続 | 6 | 6 | [S32] |
| メモリ | 128 MB | 128 MB | [S32] |
| Worker サイズ（圧縮後） | 3 MiB | 10 MiB | [S34] |
| Cron Triggers / アカウント | 5 | 250 | [S32] |
| D1 DB サイズ | **500 MB** | **10 GB** | [S35] |
| D1 読み取り行 | 500 万/日 | 250 億/月込み、超過 $0.001/100 万 | [S36] |
| D1 書き込み行 | **10 万/日** | 5,000 万/月込み、超過 $1.00/100 万 | [S36] |
| D1 ストレージ | 5 GB | 5 GB 込み、超過 $0.75/GB-月 | [S36] |
| D1 クエリ / 呼び出し | 50 | 1,000（`batch()` は 1 と数える） | [S35] |
| D1 バインド変数 / クエリ | 100 | 100 | [S35] |
| Queues | 1 万 ops/日 | 100 万 ops/月込み、超過 $0.40/100 万 | [S37] |
| Workflows | 3,000 steps/日、CPU 10 ms/step | 50 万 steps 込み、CPU 30 秒/step | [S33][S38] |
| D1 HTTP API | `POST /accounts/{account_id}/d1/database/{database_id}/query`、`sql`+`params` または `batch[]`。API Token（D1 Read/Write） | 同左。レート制限は未記載 | [S39] |

### 9.2 バッチの実行場所（3 通り）
| | (a) N100 の systemd --user timer → D1 HTTP API | (b) Workers Cron Triggers（+ D1 binding） | (c) Workflows / Queues で分割 |
|---|---|---|---|
| Debian 88MB JSON | ○ 取れる（Python、メモリ十分） | ✗ 128 MB メモリ・Free 10 ms CPU では不可 | ✗ 同上（step 結果 1 MiB 上限） |
| NVD 2000 件/頁の JSON | ○ | △ Paid なら CPU 30 秒で可。Free 10 ms は不可（推測。数 MB の JSON parse は 10 ms を超える） | △ |
| LLM 呼び出し（1 件数秒〜十数秒） | ○ | ○ wall-clock 15 分、CPU は待ち時間を数えない | ◎ step ごとに再試行 |
| Python 資産（usage / copycheck）の流用 | ◎ | ✗ TypeScript で書き直し | ✗ |
| サーバー依存 | ✗ N100 停止で更新が止まる（表示は D1 から継続） | ◎ なし | ◎ なし |
| 常駐プロセス | なし（timer の one-shot） | なし | なし |
| 月額 | $0（Workers Free で表示のみ） | **$5（Paid 必須）** | $5 以上 |
| 秘密情報 | D1 API トークンを N100 に置く | なし（binding） | なし |
| 実装量 | 小〜中（Python） | 中〜大（TS 全面） | 大 |

### 9.3 閲覧側（SSR フレームワーク）の比較
| | Hono + hono/jsx | OpenNext（Next.js 15/16） | Astro（Cloudflare adapter） |
|---|---|---|---|
| バンドル | ◎ 数十 KB。Free の 3 MiB に余裕 | △ Next のランタイムで数 MB。**Free 3 MiB の壁**、Paid 10 MiB [S34] | ○ 小〜中 |
| SSR + D1 | ◎ `c.env.DB` | ○ `getCloudflareContext()` | ○ `import { env } from 'cloudflare:workers'`（v13 以降。`locals.runtime.env` は廃止）[S40] |
| Cron handler 同居 | ◎ `export { fetch: app.fetch, scheduled }` [S41] | △ 別 Worker が自然 | △ |
| signal-digest-web の流用 | ✗ | △ Next 14 は OpenNext の対応打ち切り（2026 Q1）[S34]。Prisma/PostgreSQL・認証・admin は不要 → 実質書き直し | ✗ |
| 学習・保守 | ○ 小さい | △ 重い | ○ |
| 評価 | **◎** | △ | ○（コンテンツ寄せなら候補） |

signal-digest-web は **コードの流用 ✗**（Next 14 + Prisma/PostgreSQL + 認証）。流用するのは `紙面レイアウト仕様.md` の一覧/詳細の型、速読モードの発想、Tailwind のトークン程度。

### 9.4 D1 スキーマ（骨子。Free 500 MB を守る設計）
- D1 には **対象スタック該当分だけ**入れる（§3.3 の 30〜80 件/日）。NVD 全件は入れない。
- `cve`（id, published, last_modified, cvss_v31, cvss_v40, epss, epss_pct, kev_added, tier, tier_reason, stack_tags, source_licenses）約 1 KB/行
- `cve_event`（cve_id, observed_at, kind, before, after, source）約 300 B/行、1 日 100〜300 行
- `article`（cve_id, version, lang, headline, summary, body, llm_model, generated_at, copycheck_ok）約 4 KB/行、1 日 5〜20 行
- `aux_signal`（cve_id, kind, count, first_seen, url_hash）本文なし
- `distro_status`（cve_id, distro, release, status, fixed_version, url）
- 見積り: 年 **100〜150 MB**（推測）。Free 500 MB で 3 年。超えたら P3 と古い event を N100 側に退避。
- 書き込み: 1 日 1,000〜3,000 行 ≪ 10 万/日。読み取り: 1 ページ 50 行 × 1 日 2,000 PV = 10 万 ≪ 500 万。

### 9.5 ドメインとリリース段階
1. `vuln-signal.<account>.workers.dev` + `<meta name="robots" content="noindex">` で 2〜4 週間 shadow 運用（記事は生成するが公開導線なし）。
2. §7 の判断基準を満たしたら Cloudflare Registrar でドメイン取得（原価販売。.dev/.net で年 $10〜20 程度と推測、未確認）。サイト名は #19（商標）の結論に合わせる。
3. Custom Domain を Worker に付け、noindex を外す。

---

### 9.6 配信チャネル（RSS / Discord / Slack / メール）
**RSS 以外の配信先は、運営者が N100 上の CLI で追加・削除する**（Claude Code からコマンドを実行する運用）。公開の登録フォームは置かない。

| チャネル | 実装 | 何を流すか | 費用 | 備考 |
|---|---|---|---|---|
| **RSS** | Worker が D1 から `/feed.xml`（全体）と `/feed/p0.xml`・`/feed/node.xml`・`/feed/linux.xml`（tier・スタック別）を SSR。Cache API で 5 分キャッシュ | 新規記事と tier が上がった続報 | $0 | 誰でも購読できる唯一のチャネル。購読者情報を持たない |
| **Discord** | Webhook へ投稿（signal-digest の `notifications/discord.py` を流用） | 配信先ごとの設定（下記） | $0 | Webhook URL は秘密情報 |
| **Slack** | Incoming Webhook へ投稿（Block Kit。Discord と同じ組み立てから出し分け） | 同上 | $0 | Webhook URL は秘密情報。Slack アプリの作成はワークスペース側で行う |
| **メール** | N100 からメール送信 API を呼ぶ | 同上（既定は日次まとめ） | Resend 無料枠（月 3,000 通・1 日 100 通と記憶、**未確認**）／Amazon SES（$0.10/1,000 通、**未確認**）／Cloudflare Email Service（提供状況・料金 **未確認**） | SPF / DKIM / DMARC のためドメイン取得後に開始 |

**配信先の管理（CLI）**
```
vuln-signal channel add discord <webhook-url> --name ops --mode p0-instant
vuln-signal channel add slack   <webhook-url> --name team --mode daily --stack node,linux
vuln-signal channel add email   <address>     --name alice --mode daily --consent "2026-11-06 本人から口頭で同意"
vuln-signal channel list                 # URL・アドレスは伏せ字で表示
vuln-signal channel test <name>          # テスト投稿を 1 件送る
vuln-signal channel pause|resume <name>
vuln-signal channel remove <name>
```
- `--mode`: `p0-instant`（P0 と tier が上がった続報を即時）/ `daily`（1 日 1 回のまとめ。JST 7:00）/ `both`。`--stack`: `node` / `linux` / `distro` / `all`（既定）。
- 保存先は **N100 のローカル作業 DB（SQLite）の `channel` テーブル**。D1 には置かない（送信は N100 から行うので Cloudflare 側に配信先を持つ理由が無い。漏えい面も小さくなる）。DB ファイルは chmod 600、リポジトリ外（`~/.local/share/vuln-signal/`）。
- Webhook URL・メールアドレスはログに出さない。`list` は末尾 4 文字だけ表示。
- `add` の直後に `test` を自動で送り、失敗したら登録しない（打ち間違いの検出）。
- 送信失敗が連続 N 回（既定 5）で自動 pause し、運営者に Discord（運営用チャンネル）で知らせる。
- 二重配信防止: `delivery(channel_id, article_id, revision)` を作業 DB に記録（signal-digest の `notified_at` と同じ考え方）。
- **Claude からの操作**: リポジトリに `.claude/skills/channel/SKILL.md` を置き、上の CLI の使い方・確認手順（追加前に名前と mode を復唱、remove 前に `list` で対象確認）を書く。Claude は CLI を実行するだけで、DB を直接触らない。
- WebPush は入れない。

**メールの法的扱い（§7-24）**: 公開フォームが無いので「誰でも登録できる」状態にはならないが、特定電子メール法の同意は受信者本人から得る必要がある。`--consent` に同意の日付と方法を必須で記録する（同法の同意記録の保存義務）。各メールに送信者名・連絡先・配信停止の方法（運営者への返信または mailto の List-Unsubscribe）を入れる。停止依頼は運営者が `channel remove` で処理する。

### 9.7 サイト名
「CVE」を含めない（§7-19）。候補（DNS で NS レコードが無いことだけ確認。**登録状況・商標は未確認**）:

| 候補 | 由来 | ドメイン（NS 未設定を確認） | 所感 |
|---|---|---|---|
| **HAYAGANE（早鐘）**（推薦） | 火事や危険を知らせるために激しく打ち鳴らす鐘。「早鐘を打つ」 | hayagane.dev / .net / .io / .jp / .news | 緊急を知らせる用途にそのまま合う。英語圏でも固有名詞として読める |
| HINOBAN（火の番） | 夜回りで火の元を見張る役 | hinoban.dev / .net / .io / .jp | 常時見張っているイメージ。少し地味 |
| NOROSHI（狼煙） | 異変を遠くへ知らせる煙。signal-digest の「signal」とも対応 | .dev / .net / .jp は使用中、.io / .news は空き | 最も通りが良いが主要 TLD が埋まっている |

**リポジトリ名は `vuln-signal`**（決定。商標の「CVE」を避け、signal-digest と対にした説明的な名前）。サイト名は未定のまま進め、決まったら表示名とドメインだけ差し替える。

---

## 10. 運用負荷とコスト

### 10.1 取得頻度ごとのリクエスト数（案 B。N100 から）
| ソース | 間隔 | req/日 | 転送/日（推測） |
|---|---|---|---|
| NVD CVE + History | 30 分 | 48 × 2〜3 = 100〜150（キー有なら制限内） | 50〜100 MB |
| KEV JSON | 1 時間 | 24 | 24 × 1.5 MB = 36 MB（条件付き GET で削減） |
| GHSA REST（npm, modified） | 30 分 | 48〜96（PAT で 5,000/時） | 10 MB |
| EPSS | 1 日 1 回 + 記事生成時 | 10〜50 | 数 MB（全件 CSV なら 10 MB 級） |
| Node.js RSS + security-wg | 1 時間 | 48 | 1 MB |
| Red Hat cve.json | 1 時間 | 24 | 5 MB |
| Ubuntu cves.json / notices | 1 時間 | 48 | 10 MB |
| Debian JSON | 4 回/日 | 4 | **352 MB** |
| GitHub Search（P0/P1 候補） | 1 時間、候補 20 件 | 480（30/分の制限内） | 5 MB |
| 合計 | | 約 900 req/日 | **約 0.5 GB/日** |

### 10.2 N100 の負荷
- timer は 30 分ごとに 1 プロセス（Python、ピーク RSS 200〜400 MB、Debian 処理時 600 MB 程度と推測）、数十秒〜数分で終了。available 5.5 GB の範囲。
- ディスク: 作業 DB（SQLite）に対象外も含む NVD の生 JSON を圧縮保存して **年 1〜2 GB**（推測。560 件/日 × 8 KB）。対象外は 90 日で削除すれば **数百 MB** に収まる。cvelistV5 / advisory-database の clone はしない（3.2 GB + 3.4 GB）。
- PostgreSQL は使わない: D1 が SQLite 互換なので **ローカル作業 DB も SQLite** にするとスキーマと SQL を共有できる（`signal-digest-pg` を巻き込まない）。別 DB を既存インスタンスに作る案は、スキーマ二重管理になるので ✗。

### 10.3 LLM 費用（案 B、Claude 価格 [S20]）
| 用途 | 件/日 | 入出力 | モデル | 日額 | 月額 |
|---|---|---|---|---|---|
| ① 日本語訳・③ 続報 | 80 | 2.5k in / 0.8k out | flash-lite 相当 | | |
| ② リスク説明（P0/P1） | 10 | 8k in / 1.5k out | 3.8-flash 相当 | | |
| ② リスク説明（P2）・補助シグナル要約 | 50 | 2k / 0.4k | flash-lite 相当 | | |
| 合計 | 約 140 回/日、約 0.4M トークン/日（約 12M/月） | | | | **$6〜20/月（推測）**。signal-digest の実測単価（1,000 回・約 380 トークンあたり flash-lite $0.23 / 3.8-flash $0.62）からの換算。Gemini の現行単価は未確認。上限は `LLM_TOKEN_BUDGET_PER_RUN` で固定 |

### 10.4 月額の合計（案別）
| | 案 A（全部 Cloudflare） | 案 B（N100 収集 + Workers 表示） | 案 C（静的） |
|---|---|---|---|
| Cloudflare | **$5**（Paid 必須） | $0（Free。PV 増や CPU 超過で $5） | $0 |
| LLM（Gemini） | $6〜20 | $6〜20 | $6〜20 |
| ドメイン | $1〜2/月換算 | 同 | 同 |
| GitHub PAT / NVD キー | $0 | $0 | $0 |
| 合計 | **約 $12〜27** | **約 $7〜22** | 約 $7〜22 |

---

## 11. 設計案の比較と推薦

### 案 A: 全部 Cloudflare（Workers Cron + Workflows + D1、TypeScript）
- 収集・判定・生成・表示をすべて Workers で。Cron（30 分）→ Workflows で CVE ごとに step 分割 → D1。
- 利点: N100 に依存しない（可用性）、常駐ゼロ、秘密情報は binding で完結。
- 欠点: **Paid 必須**（Free の 10 ms CPU では NVD の JSON を処理できない）、Debian 88 MB は扱えない（OSV 変換で代替）、Python 資産（usage / copycheck）を TS で書き直し、Workflows のデバッグ経験が要る。
- 実装量: 大（TS 全面新規 + Workflows）。運用: $12〜27/月。

### 案 B: N100 で収集・判定・生成（systemd --user timer、Python）→ D1 HTTP API に書く。表示は Workers（Hono + hono/jsx）+ D1
- 30 分 timer: NVD/GHSA/KEV/… を取得 → ローカル SQLite（作業 DB）→ ルール判定 → LLM → copycheck → **対象分だけ D1 に batch 書き込み**。Workers は読み取り専用 SSR。
- 利点: signal-digest の Python 資産を流用、Debian も扱える、Cloudflare は Free で足りる見込み、**常駐プロセスなし**、D1 = SQLite なのでスキーマ共有。N100 停止時も表示は D1 から継続（「最終更新」で鮮度が分かる）。
- 欠点: N100 への依存（更新が止まる）、D1 API トークンを N100 に置く、2 言語（Python / TS）。
- 実装量: 中（Python 収集 + 小さな Hono）。運用: $7〜22/月。

### 案 C: N100 で生成 → 静的サイト（Astro static or JSON + HTML）を Workers Static Assets に配備。D1 なし
- 利点: 最も単純、Cloudflare 無料、SSR 不要。
- 欠点: **D1 + SSR という前提に合わない**、検索・絞り込み・更新履歴の表示が静的で苦しい、記事 1 万件規模でビルドが重くなる。
- 実装量: 小。運用: $12/月。

### 比較表
| 観点 | A | B | C |
|---|---|---|---|
| 前提（Cloudflare / D1 / SSR）への適合 | ◎ | ◎ | ✗ |
| 一次ソース全部を扱える（Debian 含む） | △ | ◎ | ◎ |
| signal-digest 資産の流用 | ✗ | ◎ | ○ |
| 常駐プロセスを増やさない | ◎ | ◎（timer） | ◎ |
| N100 非依存（可用性） | ◎ | △ | △ |
| 秘密情報の置き場が少ない | ◎ | ○ | ○ |
| 月額 | △ $12〜27 | ◎ $7〜22 | ◎ $7〜22 |
| 実装量 | ✗ 大 | ○ 中 | ◎ 小 |
| 2 週間で shadow 運用に入れるか | ✗ | ○ | ○ |

### 推薦: **案 B**（採用。2026-11-06 決定）
理由:
1. 一次ソースを全部扱える（Debian の 88 MB は Workers では無理）。ソースを削ると「ディストリ採用」の軸が弱くなる。
2. usage / copycheck / 通知の Python 資産がそのまま使え、判定ロジックの検証（shadow → live、ラベル突き合わせ）も signal-digest の作法を踏める。
3. 常駐を増やさず、Cloudflare は Free で始められる。N100 停止は「更新停止」であって「閉鎖」ではない。
4. D1 と SQLite の互換で、ローカル検証と本番のスキーマを 1 つに保てる。
将来 N100 を外したくなったら、収集部だけ案 A に寄せる（表示層は変えずに済む）。

### 実装の段階（implementer に渡す粒度の目安）
- **Phase 0（設計決定後すぐ）**: リポジトリ初期化、MIT（コード）/ CC BY 4.0（記事）/ LICENSE-DATA.md、`.gitignore`（`.env*`、`.dev.vars*`、`data/`）、gitleaks pre-commit + CI、`env.example`。
- **Phase 1（収集・判定、shadow）**: Python パッケージ `vuln_signal`（uv or Poetry）。モジュール: `sources/{nvd,kev,ghsa,epss,nodejs,redhat,ubuntu,debian}.py`（各 1 関数 `fetch_since(ts) -> list[Record]`）、`store/sqlite.py`（スキーマ §9.4 と同一）、`rules/tier.py`（§4.3〜4.5 を設定ファイルから読む）、`cli.py sync|judge|report`。systemd --user `vuln-signal-sync.timer`（30 分）。LLM・D1 書き込みはまだ無し。`report` で件数分布を出す。
- **Phase 2（表示）**: `web/`（Hono + hono/jsx、wrangler）。D1 スキーマ適用、`/`（P0/P1 一覧）、`/cve/:id`、`/about`（規約表示・免責）、`/feed.xml`。N100 側に `publish` コマンド（D1 HTTP API batch、100 変数/クエリを守る）。workers.dev + noindex。
- **Phase 3（LLM）**: usage.py / copycheck.py 移植、`llm/explain.py`、記事生成、`review_flag`。
- **Phase 4（補助シグナル・通知）**: GitHub Search、Metasploit/nuclei、Exploit-DB CSV、`channel` CLI と Discord / Slack / メール配信（RSS は Phase 2）、Bluesky（疎通確認後）。
- **Phase 5（公開）**: 法的チェックリスト完了 → ドメイン → noindex 解除。

---

## 12. ユーザーが決めること

### 決定が要る（Phase 0〜1 を始める前）
- [x] 案 B（N100 で収集 → D1、Workers で表示）で進める（決定）。
- [x] リポジトリ名は `vuln-signal`、サイト名は未定（決定。§9.7）。
- [x] サイト名に「CVE」を入れない（決定）。候補から選ぶ（§9.7。推薦 HAYAGANE）。
- [x] コードは MIT、記事は CC BY 4.0（決定。§8.2）。
- [ ] NVD API キー（メールで無料発行）と GitHub PAT（public_repo 読み取り、Search 用）を用意するか。
- [x] LLM は Gemini（決定）。キーはユーザーが後で発行（課金有効のもの）。月額上限（提案 $20/月）は未定。
- [ ] 作業 DB を SQLite にする（既存 PostgreSQL を触らない）方針でよいか。

### 決定が要る（Phase 4〜5 の前）
- [x] 配信チャネルは RSS / Discord / Slack / メール。RSS 以外は運営者が CLI で配信先を登録（決定。§9.6）。メール送信サービスの選択は未定。
- [ ] 補助シグナルの範囲: GitHub + Metasploit/nuclei + Exploit-DB で開始するか。Bluesky / Mastodon を足すか。infosec.exchange のアカウントを作るか。**X は使わない**でよいか。
- [x] PoC・エクスプロイトへのリンクは出さない（決定。§5.4・§7-17）。
- [ ] 法的確認の実施者: EPSS（FIRST）、Debian、Ubuntu への問い合わせを誰が出すか。免責文を弁護士に見せるか。
- [ ] ドメイン（Cloudflare Registrar、TLD）。取得タイミングは §7 の基準。

### 未確認事項（本草稿で確認できなかったもの）
- CVE.org 現行 Terms of Use の全文（JS 描画。ミラーと旧サイトで内容確認）。
- EPSS の明示ライセンス、Debian / Ubuntu のデータライセンス、OSV の利用規約、Red Hat API のレート制限。
- Claude Web 検索ツールの単価（pricing ページの本文に見当たらず）。
- Bluesky `public.api.bsky.app` が本サーバーから 403 になる原因（Workers からの疎通未確認）。Jetstream のホスト名（docs サイトが JS 描画）。
- x.com ToS 本文（403）。Developer Agreement と Restricted Use Cases は確認済み。
- Cloudflare Registrar の TLD 価格。

---

## 13. 出典 URL

- [S1] NVD API Terms of Use（ミラー。原本は JS 描画）: https://scancode-licensedb.aboutcode.org/nist-nvd-api-tou.html / 原本 https://nvd.nist.gov/developers/terms-of-use
- [S2] NVD Developers Start Here（5/50 req per 30 s）: https://nvd.nist.gov/developers/start-here
- [S3] cvelistV5 README（7 分更新、hourly delta、deltaLog 30 日）: https://github.com/CVEProject/cvelistV5
- [S4] CVE Program Terms of Use（原本、JS 描画）: https://www.cve.org/Legal/TermsOfUse
- [S4b] 同ミラー（xen.org）: https://xenbits.xen.org/people/iwj/security-cna/termsofuse.html / 旧サイト: https://www.cve.org/Resources/Media/Archives/OldWebsite/about/termsofuse.html
- [S5] CISA KEV license（CC0）: https://www.cisa.gov/sites/default/files/licenses/kev/license.txt
- [S5b] cisagov/kev-data README・LICENSE: https://github.com/cisagov/kev-data
- [S6] GitHub REST Global Security Advisories: https://docs.github.com/en/rest/security-advisories/global-advisories
- [S7] GitHub REST rate limits: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- [S8] github/advisory-database（CC-BY 4.0）: https://github.com/github/advisory-database
- [S9] OSV API: https://google.github.io/osv.dev/api/
- [S10] OSV Data（GCS、ソース別ライセンス）: https://google.github.io/osv.dev/data/
- [S11] nodejs/security-wg: https://github.com/nodejs/security-wg / RSS https://nodejs.org/en/feed/vulnerability.xml
- [S12] npm Open Source Terms: https://docs.npmjs.com/policies/open-source-terms
- [S13] Debian web license: https://www.debian.org/license / tracker: https://security-tracker.debian.org/tracker/data/json / salsa: https://salsa.debian.org/security-tracker-team/security-tracker
- [S14] Canonical IP policy: https://canonical.com/legal/intellectual-property-policy / Ubuntu Security API: https://ubuntu.com/security/api/docs
- [S15] Red Hat Security Data（CC BY 4.0）: https://access.redhat.com/security/data
- [S16] Linux kernel CNA process: https://docs.kernel.org/process/cve.html
- [S17] EPSS API: https://api.first.org/epss/
- [S18] EPSS FAQ（attribution requested、13:30 UTC）: https://www.first.org/epss/faq / https://www.first.org/epss/
- [S19] api.first.org（1,000 req/min）: https://api.first.org/
- [S20] Claude pricing: https://platform.claude.com/docs/en/about-claude/pricing
- [S21] X API pricing: https://docs.x.com/x-api/getting-started/pricing
- [S22] X Developer Agreement: https://docs.x.com/developer-terms/agreement
- [S23] X Restricted Use Cases: https://docs.x.com/developer-terms/restricted-use-cases
- [S24] Bluesky rate limits: https://github.com/bluesky-social/bsky-docs/blob/main/docs/advanced-guides/rate-limits.md
- [S25] Bluesky developer guidelines: https://github.com/bluesky-social/bsky-docs/blob/main/docs/support/developer-guidelines.md / Jetstream: https://github.com/bluesky-social/jetstream
- [S26] Mastodon timelines API: https://docs.joinmastodon.org/methods/timelines/
- [S27] Mastodon rate limits: https://docs.joinmastodon.org/api/rate-limits/
- [S28] infosec.exchange rules: https://infosec.exchange/api/v1/instance/rules
- [S29] GitHub Search API rate limits: https://docs.github.com/en/rest/search/search
- [S30] Exploit-DB terms: https://www.exploit-db.com/terms / GitLab mirror（GPL-2.0）: https://gitlab.com/exploit-database/exploitdb
- [S31] Cloudflare Workers secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- [S32] Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- [S33] Workers pricing: https://developers.cloudflare.com/workers/platform/pricing/
- [S34] OpenNext Cloudflare: https://opennext.js.org/cloudflare
- [S35] D1 limits: https://developers.cloudflare.com/d1/platform/limits/
- [S36] D1 pricing: https://developers.cloudflare.com/d1/platform/pricing/
- [S37] Queues pricing: https://developers.cloudflare.com/queues/platform/pricing/
- [S38] Workflows limits: https://developers.cloudflare.com/workflows/reference/limits/
- [S39] D1 HTTP API query: https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/
- [S40] Astro Cloudflare adapter: https://docs.astro.build/en/guides/integrations-guide/cloudflare/
- [S41] Hono on Cloudflare Workers: https://hono.dev/docs/getting-started/cloudflare-workers
- Metasploit LICENSE（BSD-3-Clause）: https://github.com/rapid7/metasploit-framework/blob/master/LICENSE / nuclei-templates（MIT）: https://github.com/projectdiscovery/nuclei-templates
- gitleaks: https://github.com/gitleaks/gitleaks
- CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
