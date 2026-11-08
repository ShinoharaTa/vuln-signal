# collector

一次ソース（現状は NVD CVE API 2.0 のみ）から CVE の新規公開と更新を取得し、作業 DB（SQLite）に記録する。
CVSS（v3.1 / v4.0）と `vulnStatus` の変化は `cve_event` に差分として積む。設計は [`../docs/design.md`](../docs/design.md)。

```sh
cd collector
uv sync

# 取得と差分計算だけ（DB に書かない）
uv run vuln-signal sync nvd --dry-run
# 取得して作業 DB に反映。開始時刻を指定するときは --since 2026-11-06T00:00:00Z
uv run vuln-signal sync nvd

# 直近 N 日の件数
uv run vuln-signal report --days 1

uv run pytest -q
```

- 作業 DB: `~/.local/share/vuln-signal/work.sqlite3`（`VULN_SIGNAL_DATA_DIR` で変更。`uv run vuln-signal db path` で表示）
- env ファイル: `~/.config/vuln-signal/env`（`VULN_SIGNAL_ENV_FILE` で変更）。既に環境変数にあるキーは上書きしない。
  使う変数は `NVD_API_KEY`（空でよい）、`VULN_SIGNAL_DATA_DIR`、`NVD_INITIAL_LOOKBACK_HOURS`（初回に遡る時間、既定 24）。
