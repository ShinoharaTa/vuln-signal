"""同期: 取得 → 差分 → イベント記録 → カーソル更新。"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from vuln_signal import rules as tier_rules
from vuln_signal.config import Rules
from vuln_signal.sources.epss import EpssClient, EpssRecord
from vuln_signal.sources.ghsa import GhsaClient, GhsaRecord
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
SOURCE_GHSA = "ghsa"
SOURCE_CLASSIFY = "classify"
# tier_changed イベントの source
SOURCE_RULES = "rules"
# 浮動小数の誤差で閾値ちょうどを取りこぼさないための幅
_EPS = 1e-9
# cpe_changed の after の最大文字数（超えたら切って末尾に …(+N)）
CPE_DIFF_MAX_CHARS = 2000
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


def cpe_diff_text(before: list[str], after: list[str], limit: int = CPE_DIFF_MAX_CHARS) -> str:
    """追加分を +cpe、削除分を -cpe の改行区切りにする。limit を超えたら切って …(+N) を付ける。"""
    old, new = set(before), set(after)
    lines = [f"+{c}" for c in sorted(new - old)] + [f"-{c}" for c in sorted(old - new)]
    text = "\n".join(lines)
    if len(text) <= limit:
        return text
    kept: list[str] = []
    for i, line in enumerate(lines):
        suffix = f"…(+{len(lines) - i - 1})"
        # この行を入れても、残りの件数を付けて limit に収まるか
        if len("\n".join([*kept, line, suffix])) > limit:
            break
        kept.append(line)
    return "\n".join([*kept, f"…(+{len(lines) - len(kept)})"])


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
    if old["source_identifier"] != new.source_identifier:
        events.append(("source_changed", old["source_identifier"], new.source_identifier))
    old_cpe = json.loads(old["cpe_criteria"] or "[]")
    if sorted(old_cpe) != sorted(new.cpe_criteria):
        events.append(("cpe_changed", None, cpe_diff_text(old_cpe, new.cpe_criteria)))
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
    store: Store,
    now: datetime,
    since: datetime | None,
    lookback_hours: int,
    source: str = SOURCE_NVD,
) -> datetime:
    if since is not None:
        return since
    state = store.get_sync_state(source)
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
        newest = max((r.model_date for r in records if r.model_date), default=None)
        result.model_date = newest or cursor
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
            # 有効な date が無ければ cursor は据え置く（now を入れると同日の再実行がスキップされる）
            if newest is None:
                store.mark_sync_ok(SOURCE_EPSS, now_s, keep_cursor=True)
            else:
                store.mark_sync_ok(SOURCE_EPSS, now_s, cursor=newest)
    except Exception as e:
        if not dry_run:
            store.mark_sync_error(SOURCE_EPSS, now_s, client.redact(f"{type(e).__name__}: {e}"))
        raise
    return result


@dataclass
class GhsaSyncResult:
    start: datetime
    end: datetime
    fetched: int = 0
    events: Counter[str] = field(default_factory=Counter)


def _patched_text(packages: list[dict[str, str | None]]) -> str:
    """first_patched_version の集合を name@version のカンマ連結にする。未修正は name@-。"""
    items = {f"{p['name']}@{p['first_patched_version'] or '-'}" for p in packages}
    return ",".join(sorted(items))


def ghsa_subject(rec: GhsaRecord) -> str:
    """cve_event.cve_id に入れる主体。CVE があればそれ、無ければ GHSA ID。"""
    return rec.cve_id or rec.ghsa_id


def diff_ghsa(old: sqlite3.Row | None, new: GhsaRecord) -> list[Event]:
    """既存行と新しいレコードの差分をイベントにする。updated_at だけの変化は対象外。"""
    if old is None:
        return [("ghsa_first_seen", None, new.ghsa_id)]
    events: list[Event] = []
    if old["cve_id"] != new.cve_id:
        if old["cve_id"] is None:
            events.append(("ghsa_cve_assigned", new.ghsa_id, new.cve_id))
        else:
            # 値→別の値、値→NULL。NULL 側は GHSA ID で表す
            events.append(("ghsa_cve_changed", old["cve_id"], new.cve_id or new.ghsa_id))
    if old["severity"] != new.severity:
        events.append(("ghsa_severity_changed", old["severity"], new.severity))
    before = _patched_text(json.loads(old["packages"] or "[]"))
    after = _patched_text(new.packages)
    if before != after:
        events.append(("ghsa_patched_changed", before, after))
    if old["withdrawn_at"] is None and new.withdrawn_at is not None:
        events.append(("ghsa_withdrawn", None, new.withdrawn_at))
    return events


def _latest_ghsa(records: list[GhsaRecord]) -> dict[str, GhsaRecord]:
    """同じ GHSA が重複して来たら updated_at が新しい方（同じなら後に来た方）を採る。"""
    latest: dict[str, GhsaRecord] = {}
    for rec in records:
        cur = latest.get(rec.ghsa_id)
        if cur is None or (rec.updated_at or "") >= (cur.updated_at or ""):
            latest[rec.ghsa_id] = rec
    return latest


def sync_ghsa(
    store: Store,
    client: GhsaClient,
    now: datetime,
    since: datetime | None = None,
    *,
    lookback_hours: int = 24,
    dry_run: bool = False,
) -> GhsaSyncResult:
    """GitHub Advisory Database（npm、reviewed）から modified が [開始, now] のものを取り反映する。

    開始は NVD と同じ（--since、無ければ前回 cursor - 5 分、初回は now - lookback_hours）。
    失敗時は sync_state の last_run_at と last_error だけを更新し、例外を投げ直す。
    """
    start = resolve_start(store, now, since, lookback_hours, SOURCE_GHSA)
    now_s = iso(now)
    result = GhsaSyncResult(start=start, end=now)
    try:
        records = client.fetch_modified(start, now)
        result.fetched = len(records)
        latest = _latest_ghsa(records)
        if dry_run:
            for rec in latest.values():
                for kind, _, _ in diff_ghsa(store.get_ghsa(rec.ghsa_id), rec):
                    result.events[kind] += 1
            return result
        with store.transaction():
            for rec in latest.values():
                events = diff_ghsa(store.get_ghsa(rec.ghsa_id), rec)
                store.upsert_ghsa(rec, now_s)
                for kind, before, after in events:
                    store.add_event(ghsa_subject(rec), now_s, kind, before, after, SOURCE_GHSA)
                    result.events[kind] += 1
            store.mark_sync_ok(SOURCE_GHSA, now_s)
    except Exception as e:
        if not dry_run:
            store.mark_sync_error(SOURCE_GHSA, now_s, client.redact(f"{type(e).__name__}: {e}"))
        raise
    return result


@dataclass
class ClassifyResult:
    rules_version: str
    all: bool = False
    targets: int = 0
    # 今回判定した subject の tier 別件数（対象外は "excluded"）
    tiers: Counter[str] = field(default_factory=Counter)
    # tier_changed の内訳: up / down / new / removed
    changes: Counter[str] = field(default_factory=Counter)


def _change_kind(before: str | None, after: str | None) -> str:
    if before is None:
        return "new"
    if after is None:
        return "removed"
    # P0 < P1 < ... の順なので文字列比較で上下が分かる
    return "up" if after < before else "down"


def classify(
    store: Store,
    rules: Rules,
    now: datetime,
    *,
    all_subjects: bool = False,
    dry_run: bool = False,
) -> ClassifyResult:
    """変化のあった subject（all_subjects なら全部）をルールで判定し、tier に反映する。

    cursor は処理した最大の cve_event.id。tier が変わったときだけ tier_changed を積む。
    dry_run では判定して数えるだけで書かない（sync_state も触らない）。
    失敗時は sync_state の last_run_at と last_error だけを更新し、例外を投げ直す。
    """
    now_s = iso(now)
    result = ClassifyResult(rules_version=rules.version, all=all_subjects)
    try:
        state = store.get_sync_state(SOURCE_CLASSIFY)
        cursor = int(state["cursor"]) if state is not None and state["cursor"] else 0
        last_ok = state["last_ok_at"] if state is not None else None
        upto = store.max_event_id()
        if all_subjects:
            subjects = store.all_subjects()
        else:
            subjects = store.changed_subjects(cursor, upto, last_ok)
        result.targets = len(subjects)

        def _apply() -> None:
            for subject in subjects:
                inputs = tier_rules.collect_inputs(store, subject)
                decision = tier_rules.evaluate(inputs, rules)
                old = store.get_tier(subject)
                before = old["tier"] if old is not None else None
                after = decision.tier if decision is not None else None
                result.tiers[after or "excluded"] += 1
                if before != after:
                    result.changes[_change_kind(before, after)] += 1
                if dry_run:
                    continue
                if decision is None:
                    if old is not None:
                        store.delete_tier(subject)
                else:
                    store.upsert_tier(
                        subject,
                        decision.tier,
                        list(decision.stacks),
                        list(decision.reasons),
                        inputs.as_json(),
                        rules.version,
                        now_s,
                    )
                if before != after:
                    store.add_event(subject, now_s, "tier_changed", before, after, SOURCE_RULES)

        if dry_run:
            _apply()
            return result
        with store.transaction():
            _apply()
            store.mark_sync_ok(SOURCE_CLASSIFY, now_s, cursor=str(upto))
    except Exception as e:
        if not dry_run:
            store.mark_sync_error(SOURCE_CLASSIFY, now_s, f"{type(e).__name__}: {e}")
        raise
    return result
