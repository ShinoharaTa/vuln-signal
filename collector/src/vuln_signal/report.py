"""直近 N 日の件数をテキスト表にまとめる。

「新規公開」は cve.published が窓内の CVE、「初出」は作業 DB に初めて入った CVE
（cve_event の kind='first_seen'）。lastModified で取るので初出には古い CVE も混じる。
tier の「窓内の新規」は first_seen / ghsa_first_seen が窓内の subject の現在の tier。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from vuln_signal.rules import TIERS
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
    # テーブルの総行数（期間に関係しない）
    kev_total: int = 0
    epss_rows: int = 0
    ghsa_rows: int = 0
    days: int = 1
    # tier テーブル全体の件数
    tier_current: dict[str, int] = field(default_factory=lambda: dict.fromkeys(TIERS, 0))
    # 窓内に初出した subject の現在の tier
    tier_new: dict[str, int] = field(default_factory=lambda: dict.fromkeys(TIERS, 0))
    # 窓内の tier_changed のうち上がったもの（NULL → P0 / P1 を含む）
    tier_upgrades: int = 0
    # 窓内に初出した subject で kernel_thinned で P3 になったもの
    kernel_thinned: int = 0

    @property
    def p0_p1_new_per_day(self) -> float:
        return (self.tier_new["P0"] + self.tier_new["P1"]) / self.days


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

    tier_current = dict.fromkeys(TIERS, 0)
    for row in conn.execute("SELECT tier, COUNT(*) AS n FROM tier GROUP BY tier"):
        tier_current[row["tier"]] = row["n"]

    new_subjects = (
        "SELECT cve_id FROM cve_event WHERE kind IN ('first_seen', 'ghsa_first_seen') "
        "AND observed_at >= ? AND observed_at <= ?"
    )
    tier_new = dict.fromkeys(TIERS, 0)
    for row in conn.execute(
        f"SELECT tier, COUNT(*) AS n FROM tier WHERE subject_id IN ({new_subjects}) GROUP BY tier",
        window,
    ):
        tier_new[row["tier"]] = row["n"]

    # P0 < P1 < ... の順なので文字列比較で上がったかが分かる
    tier_upgrades = conn.execute(
        "SELECT COUNT(*) FROM cve_event WHERE kind = 'tier_changed' "
        "AND observed_at >= ? AND observed_at <= ? AND ("
        "(before IS NULL AND after IN ('P0', 'P1')) "
        "OR (before IS NOT NULL AND after IS NOT NULL AND after < before))",
        window,
    ).fetchone()[0]

    kernel_thinned = conn.execute(
        f"SELECT COUNT(*) FROM tier WHERE subject_id IN ({new_subjects}) "
        "AND EXISTS (SELECT 1 FROM json_each(tier.reasons) WHERE value = 'kernel_thinned')",
        window,
    ).fetchone()[0]

    state = [(r["source"], r["last_ok_at"], r["last_error"]) for r in store.list_sync_state()]
    return Report(
        since,
        until,
        new_count,
        first_seen_count,
        events,
        by_severity,
        kernel,
        state,
        kev_total=store.count_rows("kev"),
        epss_rows=store.count_rows("epss"),
        ghsa_rows=store.count_rows("ghsa"),
        days=days,
        tier_current=tier_current,
        tier_new=tier_new,
        tier_upgrades=tier_upgrades,
        kernel_thinned=kernel_thinned,
    )


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
        f"kev total: {rep.kev_total}",
        f"epss rows: {rep.epss_rows}",
        f"ghsa rows: {rep.ghsa_rows}",
        "",
        _table(
            ("tier", "current", "new in window"),
            [(t, rep.tier_current[t], rep.tier_new[t]) for t in TIERS],
        ),
        "",
        f"P0+P1 new per day: {rep.p0_p1_new_per_day:.1f}",
        f"tier upgrades in window: {rep.tier_upgrades}",
        f"kernel thinned (P3) in window: {rep.kernel_thinned}",
        "",
        _table(
            ("source", "last_ok_at", "last_error"), list(rep.sync_state) or [("(none)", None, None)]
        ),
    ]
    return "\n".join(parts)
