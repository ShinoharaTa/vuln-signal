"""直近 N 日の件数をテキスト表にまとめる。

「新規公開」は cve.published が窓内の CVE、「初出」は作業 DB に初めて入った CVE
（cve_event の kind='first_seen'）。lastModified で取るので初出には古い CVE も混じる。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from vuln_signal.sources.nvd import LINUX_KERNEL_CNA
from vuln_signal.store import Store, iso

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
NO_SEVERITY = "(none)"


@dataclass
class Report:
    since: str
    until: str
    new_count: int
    first_seen_count: int
    events: dict[str, int]
    new_by_severity: dict[str, int]
    new_kernel_cna: int
    sync_state: list[tuple[str, str | None, str | None]]  # (source, last_ok_at, last_error)


def build_report(store: Store, now: datetime, days: int = 1) -> Report:
    since = iso(now - timedelta(days=days))
    until = iso(now)
    window = (since, until)
    conn = store.conn

    events = {
        row["kind"]: row["n"]
        for row in conn.execute(
            "SELECT kind, COUNT(*) AS n FROM cve_event "
            "WHERE observed_at >= ? AND observed_at <= ? GROUP BY kind ORDER BY kind",
            window,
        )
    }

    first_seen_count = conn.execute(
        "SELECT COUNT(DISTINCT cve_id) FROM cve_event "
        "WHERE kind = 'first_seen' AND observed_at >= ? AND observed_at <= ?",
        window,
    ).fetchone()[0]

    new_ids = "SELECT id FROM cve WHERE published >= ? AND published <= ?"
    new_count = conn.execute(f"SELECT COUNT(*) FROM ({new_ids})", window).fetchone()[0]

    by_severity = dict.fromkeys((*SEVERITIES, NO_SEVERITY), 0)
    for row in conn.execute(
        f"SELECT cvss_v31_severity AS sev, COUNT(*) AS n FROM cve "
        f"WHERE id IN ({new_ids}) GROUP BY cvss_v31_severity",
        window,
    ):
        key = row["sev"] if row["sev"] in SEVERITIES else NO_SEVERITY
        by_severity[key] += row["n"]

    kernel = conn.execute(
        f"SELECT COUNT(*) FROM cve WHERE id IN ({new_ids}) AND source_identifier = ?",
        (*window, LINUX_KERNEL_CNA),
    ).fetchone()[0]

    state = [(r["source"], r["last_ok_at"], r["last_error"]) for r in store.list_sync_state()]
    return Report(since, until, new_count, first_seen_count, events, by_severity, kernel, state)


def _table(headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> str:
    cells = [headers, *[tuple("" if v is None else str(v) for v in r) for r in rows]]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in cells]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def format_report(rep: Report) -> str:
    parts = [
        f"period: {rep.since} .. {rep.until}",
        "",
        _table(
            ("metric", "count"),
            [
                ("new CVEs (published in period)", rep.new_count),
                ("new from Linux kernel CNA", rep.new_kernel_cna),
                ("first seen (first_seen events)", rep.first_seen_count),
            ],
        ),
        "",
        _table(("new by CVSS v3.1 severity", "count"), list(rep.new_by_severity.items())),
        "",
        _table(("event kind", "count"), list(rep.events.items()) or [("(none)", 0)]),
        "",
        _table(
            ("source", "last_ok_at", "last_error"), list(rep.sync_state) or [("(none)", None, None)]
        ),
    ]
    return "\n".join(parts)
