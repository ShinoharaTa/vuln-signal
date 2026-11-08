"""同期: 取得 → 差分 → イベント記録 → カーソル更新。"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from vuln_signal.sources.nvd import CveRecord, NvdClient
from vuln_signal.store import Store, iso, parse_iso

SOURCE_NVD = "nvd"
# 前回カーソルから少し戻して取り、境界の取りこぼしを防ぐ
CURSOR_OVERLAP = timedelta(minutes=5)

# (kind, before, after)
Event = tuple[str, str | None, str | None]


@dataclass
class SyncResult:
    start: datetime
    end: datetime
    fetched: int = 0
    # 初出のうち published が [start, end] 内のもの（新規公開）
    new: int = 0
    events: Counter[str] = field(default_factory=Counter)


def _cvss_text(score: float | None, vector: str | None) -> str | None:
    if score is None and vector is None:
        return None
    return " ".join(str(v) for v in (score, vector) if v is not None)


def diff_events(old: sqlite3.Row | None, new: CveRecord) -> list[Event]:
    """既存行と新しいレコードの差分をイベントにする。last_modified だけの変化は対象外。"""
    if old is None:
        return [("first_seen", None, new.published)]
    events: list[Event] = []
    for ver in ("v31", "v40"):
        score_col, vector_col = f"cvss_{ver}_score", f"cvss_{ver}_vector"
        before = _cvss_text(old[score_col], old[vector_col])
        after = _cvss_text(getattr(new, score_col), getattr(new, vector_col))
        if before != after:
            events.append((f"cvss_{ver}_changed", before, after))
    if old["vuln_status"] != new.vuln_status:
        events.append(("status_changed", old["vuln_status"], new.vuln_status))
    return events


def _latest_by_id(records: list[CveRecord]) -> dict[str, CveRecord]:
    """同じ CVE が重複して来たら last_modified が新しい方（同じなら後に来た方）を採る。"""
    latest: dict[str, CveRecord] = {}
    for rec in records:
        cur = latest.get(rec.id)
        if cur is None or (rec.last_modified or "") >= (cur.last_modified or ""):
            latest[rec.id] = rec
    return latest


def resolve_start(
    store: Store, now: datetime, since: datetime | None, lookback_hours: int
) -> datetime:
    if since is not None:
        return since
    state = store.get_sync_state(SOURCE_NVD)
    if state is not None and state["cursor"]:
        return parse_iso(state["cursor"]) - CURSOR_OVERLAP
    return now - timedelta(hours=lookback_hours)


def sync_nvd(
    store: Store,
    client: NvdClient,
    now: datetime,
    since: datetime | None = None,
    *,
    lookback_hours: int = 24,
    dry_run: bool = False,
) -> SyncResult:
    """NVD から lastModified が [開始, now] の CVE を取り、作業 DB に反映する。

    dry_run では取得と差分計算だけして DB に書かない（sync_state も触らない）。
    失敗時は sync_state の last_run_at と last_error だけを更新し、例外を投げ直す。
    """
    start = resolve_start(store, now, since, lookback_hours)
    now_s = iso(now)
    result = SyncResult(start=start, end=now)
    try:
        records = client.fetch_modified(start, now)
        result.fetched = len(records)
        latest = _latest_by_id(records)
        if dry_run:
            for rec in latest.values():
                _count(result, diff_events(store.get_cve(rec.id), rec), rec)
            return result
        with store.transaction():
            for rec in latest.values():
                events = diff_events(store.get_cve(rec.id), rec)
                store.upsert_cve(rec, now_s)
                for kind, before, after in events:
                    store.add_event(rec.id, now_s, kind, before, after, SOURCE_NVD)
                _count(result, events, rec)
            store.mark_sync_ok(SOURCE_NVD, now_s)
    except Exception as e:
        if not dry_run:
            store.mark_sync_error(SOURCE_NVD, now_s, client.redact(f"{type(e).__name__}: {e}"))
        raise
    return result


def _count(result: SyncResult, events: list[Event], rec: CveRecord) -> None:
    for kind, _, _ in events:
        result.events[kind] += 1
        # lastModified で取るので、昔公開されて最近更新された CVE も初出になる。新規公開とは分ける
        if kind == "first_seen" and rec.published is not None:
            if iso(result.start) <= rec.published <= iso(result.end):
                result.new += 1
