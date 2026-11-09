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

# nvd → kev → ghsa → epss → classify の順に全部。1 つ失敗しても残りを続け、最後に exit 1
uv run vuln-signal sync all

# tier 判定（差分）。--all で全件、--dry-run で件数だけ
uv run vuln-signal classify
uv run vuln-signal classify --all --dry-run

# 直近 N 日の件数（tier 別件数、P0+P1 の新規 / 日 を含む）
uv run vuln-signal report --days 1

uv run pytest -q
```

- 作業 DB: `~/.local/share/vuln-signal/work.sqlite3`（`VULN_SIGNAL_DATA_DIR` で変更。`uv run vuln-signal db path` で表示）
- env ファイル: `~/.config/vuln-signal/env`（`VULN_SIGNAL_ENV_FILE` で変更）。既に環境変数にあるキーは上書きしない。
  使う変数は `NVD_API_KEY`（空でよい）、`VULN_SIGNAL_DATA_DIR`、`NVD_INITIAL_LOOKBACK_HOURS`（初回に遡る時間、既定 24）、
  `GITHUB_TOKEN`（空でよい。無いと GitHub API は 60 req/時）、`GHSA_INITIAL_LOOKBACK_HOURS`（既定 24）、
  `EPSS_WINDOW_DAYS`（EPSS を取る CVE の公開日・GHSA 更新日の範囲、既定 30）。
