"""同期: 取得 → 差分 → イベント記録 → カーソル更新。"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from vuln_signal.sources.epss import EpssClient, EpssRecord
from vuln_signal.sources.kev import KevClient, KevError, KevRecord
from vuln_signal.sources.nvd import CveRecord, NvdClient
from vuln_signal.store import Store, iso, parse_iso

SOURCE_NVD = "nvd"
SOURCE_KEV = "kev"
# KEV の件数が既存行数のこの割合を下回ったら壊れた配信とみなす（一斉削除イベントを出さない）
KEV_MIN_RATIO = 0.9
SOURCE_EPSS = "epss"
# EPSS の変化をイベントにする閾値: score の上昇幅、または percentile がこの値を跨いだとき
EPSS_SCORE_JUMP = 0.2
EPSS_PERCENTILE_HIGH = 0.9
# FIRST が当日のモデルを出し終える目安の時刻（UTC）。これより前は前日分が最新
EPSS_PUBLISH_HOUR_UTC = 14
# 浮動小数の誤差で閾値ちょうどを取りこぼさないための幅
_EPS = 1e-9
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


@dataclass
class KevSyncResult:
    catalog_version: str | None = None
    # 304 で変化なし
    not_modified: bool = False
    # kev テーブルが空だった（全件を入れるだけでイベントは出さない）
    bootstrap: bool = False
    fetched: int = 0
    events: Counter[str] = field(default_factory=Counter)


def diff_kev(old: sqlite3.Row | None, new: KevRecord) -> list[Event]:
    """KEV の 1 件の差分。追加と ransomware 利用の変化だけをイベントにする。"""
    if old is None:
        return [("kev_added", None, new.date_added)]
    if old["known_ransomware"] != new.known_ransomware:
        return [("kev_ransomware_changed", old["known_ransomware"], new.known_ransomware)]
    return []


def _kev_diff(
    existing: dict[str, sqlite3.Row], records: dict[str, KevRecord]
) -> list[tuple[str, Event]]:
    """(cve_id, event) の一覧。消えた CVE は kev_removed。"""
    out: list[tuple[str, Event]] = []
    for cve_id, rec in records.items():
        out.extend((cve_id, ev) for ev in diff_kev(existing.get(cve_id), rec))
    for cve_id in sorted(existing.keys() - records.keys()):
        out.append((cve_id, ("kev_removed", existing[cve_id]["date_added"], None)))
    return out


def sync_kev(
    store: Store, client: KevClient, now: datetime, *, dry_run: bool = False
) -> KevSyncResult:
    """KEV カタログを取り、作業 DB の kev に反映する。cursor には catalogVersion を入れる。

    etag があれば条件付き GET にし、304 なら成功だけ記録する。
    kev が空のとき（初回）は全件を入れるだけでイベントを出さない。
    失敗時は sync_state の last_run_at と last_error だけを更新し、例外を投げ直す。
    """
    now_s = iso(now)
    result = KevSyncResult()
    state = store.get_sync_state(SOURCE_KEV)
    try:
        fetched = client.fetch(state["etag"] if state is not None else None)
        if fetched.not_modified:
            result.not_modified = True
            result.catalog_version = state["cursor"] if state is not None else None
            if not dry_run:
                with store.transaction():
                    store.mark_sync_ok(SOURCE_KEV, now_s, cursor=result.catalog_version)
            return result

        result.catalog_version = fetched.catalog_version
        result.fetched = len(fetched.records)
        records = {rec.cve_id: rec for rec in fetched.records}
        existing = store.list_kev()
        if not records:
            raise KevError("KEV feed has no vulnerabilities")
        if len(records) < len(existing) * KEV_MIN_RATIO:
            raise KevError(
                f"KEV feed has {len(records)} entries, "
                f"less than {KEV_MIN_RATIO:.0%} of {len(existing)} stored"
            )
        result.bootstrap = not existing
        diff = [] if result.bootstrap else _kev_diff(existing, records)
        for _, (kind, _, _) in diff:
            result.events[kind] += 1
        if dry_run:
            return result
        with store.transaction():
            for rec in records.values():
                store.upsert_kev(rec, now_s)
            for cve_id, (kind, before, after) in diff:
                if kind == "kev_removed":
                    store.delete_kev(cve_id)
                store.add_event(cve_id, now_s, kind, before, after, SOURCE_KEV)
            store.set_sync_etag(SOURCE_KEV, fetched.etag)
            store.mark_sync_ok(SOURCE_KEV, now_s, cursor=fetched.catalog_version)
    except Exception as e:
        if not dry_run:
            store.mark_sync_error(SOURCE_KEV, now_s, client.redact(f"{type(e).__name__}: {e}"))
        raise
    return result


@dataclass
class EpssSyncResult:
    expected_date: str
    # 既に期待モデル日のデータを持っていて取得しなかった
    skipped: bool = False
    # 応答の date の最大値（スキップ時は前回の値）
    model_date: str | None = None
    targets: int = 0
    fetched: int = 0
    events: Counter[str] = field(default_factory=Counter)


def expected_epss_date(now: datetime) -> str:
    """いま取れるはずの最新モデル日。UTC 14:00 以降なら今日、それより前なら昨日。"""
    day: date = now.astimezone(UTC).date()
    if now.astimezone(UTC).hour < EPSS_PUBLISH_HOUR_UTC:
        day -= timedelta(days=1)
    return day.isoformat()


def _epss_text(score: float, percentile: float) -> str:
    return f"{score:.4f} p{percentile:.3f}"


def diff_epss(old: sqlite3.Row | None, new: EpssRecord) -> list[Event]:
    """score が EPSS_SCORE_JUMP 以上上がったか、percentile が EPSS_PERCENTILE_HIGH を跨いだら変化。

    既存行が無ければイベントにしない。
    """
    if old is None:
        return []
    jumped = new.score - old["score"] >= EPSS_SCORE_JUMP - _EPS
    crossed = old["percentile"] < EPSS_PERCENTILE_HIGH <= new.percentile
    if jumped or crossed:
        before = _epss_text(old["score"], old["percentile"])
        return [("epss_changed", before, _epss_text(new.score, new.percentile))]
    return []


def sync_epss(
    store: Store,
    client: EpssClient,
    now: datetime,
    *,
    window_days: int = 30,
    force: bool = False,
    dry_run: bool = False,
) -> EpssSyncResult:
    """対象 CVE の EPSS を取り、作業 DB の epss に反映する。cursor は応答の date の最大値。

    既に期待モデル日以降のデータがあれば何もしない（force で無視）。
    失敗時は sync_state の last_run_at と last_error だけを更新し、例外を投げ直す。
    """
    now_s = iso(now)
    result = EpssSyncResult(expected_date=expected_epss_date(now))
    state = store.get_sync_state(SOURCE_EPSS)
    cursor = state["cursor"] if state is not None else None
    if not force and cursor is not None and cursor >= result.expected_date:
        result.skipped = True
        result.model_date = cursor
        return result
    try:
        since = iso(now - timedelta(days=window_days))
        targets = store.epss_targets(since, since)
        result.targets = len(targets)
        records = client.fetch(targets)
        result.fetched = len(records)
        result.model_date = max((r.model_date for r in records), default=cursor)
        if dry_run:
            for rec in records:
                for kind, _, _ in diff_epss(store.get_epss(rec.cve_id), rec):
                    result.events[kind] += 1
            return result
        with store.transaction():
            for rec in records:
                events = diff_epss(store.get_epss(rec.cve_id), rec)
                store.upsert_epss(rec, now_s)
                for kind, before, after in events:
                    store.add_event(rec.cve_id, now_s, kind, before, after, SOURCE_EPSS)
                    result.events[kind] += 1
            store.mark_sync_ok(SOURCE_EPSS, now_s, cursor=result.model_date)
    except Exception as e:
        if not dry_run:
            store.mark_sync_error(SOURCE_EPSS, now_s, client.redact(f"{type(e).__name__}: {e}"))
        raise
    return result
