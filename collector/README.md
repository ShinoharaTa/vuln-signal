# collector

一次ソースから CVE の新規公開と更新を取得し、作業 DB（SQLite）に記録する。設計は [`../docs/design.md`](../docs/design.md)。
変化は `cve_event` に差分として積む（`source` 列がソース名）。

| ソース | コマンド | 取得するもの | 主なイベント |
|---|---|---|---|
| NVD CVE API 2.0 | `sync nvd` | lastModified の範囲の CVE | `first_seen` / `cvss_v31_changed` / `cvss_v40_changed` / `status_changed` / `source_changed` / `cpe_changed` |
| CISA KEV | `sync kev` | カタログ全体（ETag で条件付き GET） | `kev_added` / `kev_removed` / `kev_ransomware_changed` |
| FIRST EPSS | `sync epss` | 直近の CVE・KEV・GHSA の CVE の EPSS（1 日 1 回） | `epss_changed`（score +0.2 以上、または percentile 0.9 を跨ぐ） |
| GitHub Advisory（npm、reviewed） | `sync ghsa` | modified の範囲の advisory | `ghsa_first_seen` / `ghsa_severity_changed` / `ghsa_patched_changed` / `ghsa_withdrawn` / `ghsa_cve_assigned` / `ghsa_cve_changed` |

- NVD の `cpe_changed` は after に追加分 `+cpe...` と削除分 `-cpe...` を改行区切りで入れる（2,000 字を超えたら切って `…(+N)`）。`source_changed` は CNA（sourceIdentifier）の変化。
- KEV は初回（`kev` が空）だけ全件を入れてイベントを出さない（出力に `bootstrap: true`）。件数が既存の 90% 未満の配信は失敗にする。
- EPSS は当日分（UTC 14:00 以降は今日、それより前は昨日）を取得済みならスキップする。`--force` で取り直す。
- GHSA で CVE の無いものは `cve_event.cve_id` に GHSA ID を入れる。

## tier 判定（`classify`、shadow）

作業 DB の内容だけから、対象スタックの判定と P0〜P3 の付与をルールで行い `tier` テーブルに記録する（配信はまだしない）。
subject は CVE ID と、CVE の無い GHSA の GHSA ID。

- スタック: `nodejs_core`（CPE `cpe:2.3:a:nodejs:node.js:`）/ `npm`（GHSA あり、または CPE の target_sw が `node.js`）/
  `linux_kernel`（kernel CNA、または CPE `cpe:2.3:o:linux:linux_kernel:`）/ `extra:<name>`（rules.toml）。
  どれにも当たらない subject は対象外（`tier` に入れない。入っていたら消す）。
- tier: Rejected / withdrawn → P3。KEV、CVSS ≥ 9.0 かつ EPSS ≥ 0.10、Node.js 本体で CVSS ≥ 7.0 → P0。
  CVSS ≥ 7.0（無ければ GHSA severity high 以上）、EPSS percentile ≥ 0.90 → P1。それ以外 → P2。
  Deferred は KEV でなければ P3。kernel だけの P1 / P2 は KEV・percentile ≥ 0.90・CVSS ≥ 8.0 のどれも無ければ P3（`kernel_thinned`）。
  CVSS は各ソースで v4.0 優先、NVD と GHSA の最大。当たった規則は `tier.reasons` に入る。
- 対象は前回から増えた `cve_event`（`tier_changed` 以外）と、前回以降に取った EPSS の CVE。`--all` で全 subject。
- tier が変わったとき（新規・対象外へを含む）だけ `tier_changed`（`source` は `rules`）を積む。
- 閾値と追加スタックは `~/.config/vuln-signal/rules.toml`（`VULN_SIGNAL_RULES_FILE` で変更）。既定パスに無ければ既定値、`VULN_SIGNAL_RULES_FILE` で指定したファイルが無ければエラー。
  書式と既定値は [`rules.example.toml`](rules.example.toml)。未知のキーはエラー。
  実効設定のハッシュ（先頭 12 桁）を `rules_version` として `tier` に残す。ルールを変えたら `classify --all` で判定し直す。

## 前段の仕分け（`triage`、Jev、shadow）

ルールで対象スタックが決まらない CVE を TypeSafe の Jev に渡し、種別（`kind`）と対象スタックとの関係（`stack`）を固定選択肢で答えさせて `llm_triage` に記録する。tier は変えない。

- 対象: 前回から増えた `first_seen` / `cpe_changed` / `source_changed` の CVE のうち、CPE が空・kernel CNA でない・GHSA に無い・Rejected でない・説明文があるもの。
  説明文の hash（sha256 先頭 16 桁）が既存行と同じなら送らない。CVE ID 順に `JEV_MAX_PER_RUN` 件まで（`--limit` で変更）。残りは次回。
- 送るのは `description_en`（`JEV_MAX_CHARS` 字で切る）だけ。1 CVE = 1 リクエスト（質問 2 つ）。
- `stack` が `none` 以外で confidence ≥ `JEV_MIN_CONFIDENCE` なら `candidate = 1`。0→1 で `triage_candidate`、1→0 で `triage_candidate_cleared`（`source` は `jev`）。
- 429 は Retry-After 秒待って再試行（無ければ 10 / 30 / 60 秒）、5xx / 529 / 接続エラーも再試行。再試行切れなどの 1 件の失敗はその CVE を飛ばして `failed` に数え、
  1 件でもあれば cursor を進めず `last_error` に `triage: N/M requests failed; last: ...` を残す（exit 0。成功分は書く。次回は失敗した CVE だけ送り直す）。401 / 400 / 422 は全体を失敗にする（exit 1、`last_error` に残す）。
- `TYPESAFE_API_KEY` が無ければ `triage skipped: TYPESAFE_API_KEY not set` を出して何もしない（exit 0）。`--dry-run` は API を呼ばず、キーが無くても対象件数と先頭 5 件の ID を出す。
- `report` に `triage rows`、窓内の候補数と stack 別の内訳、候補のうち tier 行があるもの、tier 行があるのに候補でないもの（見逃し）を出す。

```sh
cd collector
uv sync

# 取得と差分計算だけ（DB に書かない）
uv run vuln-signal sync nvd --dry-run
# 取得して作業 DB に反映。開始時刻を指定するときは --since 2026-11-06T00:00:00Z
uv run vuln-signal sync nvd

# KEV / EPSS / GHSA（どれも --dry-run 可。epss は --force、ghsa は --since も受ける）
uv run vuln-signal sync kev
uv run vuln-signal sync epss
uv run vuln-signal sync ghsa

# nvd → kev → ghsa → epss → classify → triage の順に全部。1 つ失敗しても残りを続け、最後に exit 1
uv run vuln-signal sync all

# tier 判定（差分）。--all で全件、--dry-run で件数だけ
uv run vuln-signal classify
uv run vuln-signal classify --all --dry-run

# Jev による前段の仕分け。--dry-run は API を呼ばない。--limit でこの実行の上限
uv run vuln-signal triage --dry-run
uv run vuln-signal triage --limit 50

# 直近 N 日の件数（tier 別件数、P0+P1 の新規 / 日 を含む）
uv run vuln-signal report --days 1

uv run pytest -q
```

- 作業 DB: `~/.local/share/vuln-signal/work.sqlite3`（`VULN_SIGNAL_DATA_DIR` で変更。`uv run vuln-signal db path` で表示）
- env ファイル: `~/.config/vuln-signal/env`（`VULN_SIGNAL_ENV_FILE` で変更）。既に環境変数にあるキーは上書きしない。
  使う変数は `NVD_API_KEY`（空でよい）、`VULN_SIGNAL_DATA_DIR`、`NVD_INITIAL_LOOKBACK_HOURS`（初回に遡る時間、既定 24）、
  `GITHUB_TOKEN`（空でよい。無いと GitHub API は 60 req/時）、`GHSA_INITIAL_LOOKBACK_HOURS`（既定 24）、
  `EPSS_WINDOW_DAYS`（EPSS を取る CVE の公開日・GHSA 更新日の範囲、既定 30）、
  `TYPESAFE_API_KEY`（空なら triage はスキップ）、`JEV_MODEL`（既定 `jev-latest`。応答の model を行に残す）、
  `JEV_MIN_CONFIDENCE`（既定 0.6）、`JEV_MAX_PER_RUN`（既定 500）、`JEV_MAX_CHARS`（既定 4000）。
