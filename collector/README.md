# collector

一次ソースから CVE の新規公開と更新を取得し、作業 DB（SQLite）に記録する。設計は [`../docs/design.md`](../docs/design.md)。
変化は `cve_event` に差分として積む（`source` 列がソース名）。

| ソース | コマンド | 取得するもの | 主なイベント |
|---|---|---|---|
| NVD CVE API 2.0 | `sync nvd` | lastModified の範囲の CVE | `first_seen` / `cvss_v31_changed` / `cvss_v40_changed` / `status_changed` |
| CISA KEV | `sync kev` | カタログ全体（ETag で条件付き GET） | `kev_added` / `kev_removed` / `kev_ransomware_changed` |
| FIRST EPSS | `sync epss` | 直近の CVE・KEV・GHSA の CVE の EPSS（1 日 1 回） | `epss_changed`（score +0.2 以上、または percentile 0.9 を跨ぐ） |
| GitHub Advisory（npm、reviewed） | `sync ghsa` | modified の範囲の advisory | `ghsa_first_seen` / `ghsa_severity_changed` / `ghsa_patched_changed` / `ghsa_withdrawn` / `ghsa_cve_assigned` / `ghsa_cve_changed` |

- KEV は初回（`kev` が空）だけ全件を入れてイベントを出さない（出力に `bootstrap: true`）。件数が既存の 90% 未満の配信は失敗にする。
- EPSS は当日分（UTC 14:00 以降は今日、それより前は昨日）を取得済みならスキップする。`--force` で取り直す。
- GHSA で CVE の無いものは `cve_event.cve_id` に GHSA ID を入れる。

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

# nvd → kev → ghsa → epss の順に全部。1 つ失敗しても残りを続け、最後に exit 1
uv run vuln-signal sync all

# 直近 N 日の件数
uv run vuln-signal report --days 1

uv run pytest -q
```

- 作業 DB: `~/.local/share/vuln-signal/work.sqlite3`（`VULN_SIGNAL_DATA_DIR` で変更。`uv run vuln-signal db path` で表示）
- env ファイル: `~/.config/vuln-signal/env`（`VULN_SIGNAL_ENV_FILE` で変更）。既に環境変数にあるキーは上書きしない。
  使う変数は `NVD_API_KEY`（空でよい）、`VULN_SIGNAL_DATA_DIR`、`NVD_INITIAL_LOOKBACK_HOURS`（初回に遡る時間、既定 24）、
  `GITHUB_TOKEN`（空でよい。無いと GitHub API は 60 req/時）、`GHSA_INITIAL_LOOKBACK_HOURS`（既定 24）、
  `EPSS_WINDOW_DAYS`（EPSS を取る CVE の公開日・GHSA 更新日の範囲、既定 30）。
