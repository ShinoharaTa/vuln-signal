"""Jev（TypeSafe）による CVE の前段の仕分け（shadow）。

ルールで決まらない CVE（CPE 無し・GHSA 無し・kernel CNA でない）の英語説明文を Jev に渡し、
種別（kind）と対象スタックとの関係（stack）を固定選択肢で答えさせて llm_triage に記録する。
tier は変えない。stack が none 以外で confidence が閾値以上なら候補（candidate）として印を付ける。
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from vuln_signal.sources.jev import (
    JevClient,
    JevError,
    JevFatalError,
    JevPermanentError,
    JevResponse,
    Question,
)
from vuln_signal.store import Store, iso

log = logging.getLogger(__name__)

SOURCE_TRIAGE = "triage"
# triage_candidate / triage_candidate_cleared の source と llm_triage.provider
SOURCE_JEV = "jev"
PROVIDER = "jev"
# dry-run で表示する先頭の件数
PREVIEW_COUNT = 5
NO_STACK = "none"
# 送り直しても直らない失敗の行の kind / stack
ERROR_CHOICE = "error"
# 浮動小数の誤差で閾値ちょうどを取りこぼさないための幅
_EPS = 1e-9

QUESTIONS: dict[str, Question] = {
    "kind": Question(
        "What kind of software component is affected",
        {
            "language_runtime": (
                "Programming language implementation or runtime "
                "(Node.js, Python, JVM, PHP interpreter)"
            ),
            "framework": "Web or application framework (Express, Rails, Spring, Django)",
            "library": "Reusable library or package consumed by other code (npm, PyPI, crates)",
            "server": "Standalone server software (web server, database, mail server, proxy)",
            "os_kernel": "Operating system kernel or core OS component",
            "device_firmware": "Router, IoT device, appliance or firmware",
            "application": "End-user application, CMS, plugin, SaaS or mobile app",
            "other": "None of the above or unclear",
        },
    ),
    "stack": Question(
        "Which of these is directly affected",
        {
            "nodejs_core": "Node.js runtime itself",
            "npm_package": "A package distributed via npm (JavaScript/TypeScript library or tool)",
            "linux_kernel": "The Linux kernel",
            "linux_distro_package": (
                "Software shipped by Linux distributions (glibc, OpenSSL, systemd, sudo, etc.)"
            ),
            NO_STACK: "Not related to Node.js, npm or Linux",
        },
    ),
}


@dataclass
class TriageResult:
    limit: int
    # 送る対象の件数（上限で切る前）
    targets: int = 0
    # 今回送る対象の先頭の ID（dry-run の表示用）
    preview: list[str] = field(default_factory=list)
    requested: int = 0
    # permanent_failed を含む
    failed: int = 0
    # 送り直しても直らない失敗（llm_triage に error 行を入れ、次回は送らない）
    permanent_failed: int = 0
    # 今回 candidate になったもの（triage_candidate の件数）
    candidates: int = 0
    kinds: Counter[str] = field(default_factory=Counter)
    stacks: Counter[str] = field(default_factory=Counter)
    input_tokens: int = 0
    # 進めた cursor（進めなかったら None）
    cursor: int | None = None


def description_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def is_candidate(resp: JevResponse, min_confidence: float) -> bool:
    stack = resp.answers["stack"]
    return stack.choice != NO_STACK and stack.confidence >= min_confidence - _EPS


def _write(
    store: Store, cve_id: str, row: dict[str, Any], candidate: bool, stack: str, now_s: str
) -> bool:
    """llm_triage に入れ、candidate の変化をイベントにする。0→1 なら True。"""
    old = store.get_llm_triage(cve_id)
    before = old is not None and bool(old["candidate"])
    with store.transaction():
        store.upsert_llm_triage(
            {
                "subject_id": cve_id,
                "provider": PROVIDER,
                **row,
                "candidate": int(candidate),
                "requested_at": now_s,
            }
        )
        if candidate and not before:
            store.add_event(cve_id, now_s, "triage_candidate", None, stack, SOURCE_JEV)
        elif before and not candidate:
            store.add_event(
                cve_id, now_s, "triage_candidate_cleared", old["stack"], None, SOURCE_JEV
            )
    return candidate and not before


def _record(
    store: Store,
    cve_id: str,
    desc_hash: str,
    resp: JevResponse,
    min_confidence: float,
    now_s: str,
) -> bool:
    """応答を llm_triage に入れる。0→1 なら True。"""
    kind, stack = resp.answers["kind"], resp.answers["stack"]
    row = {
        "model": resp.model,
        "kind": kind.choice,
        "kind_confidence": kind.confidence,
        "kind_probs": kind.probabilities,
        "stack": stack.choice,
        "stack_confidence": stack.confidence,
        "stack_probs": stack.probabilities,
        "input_tokens": resp.input_tokens,
        "description_hash": desc_hash,
        "error": None,
    }
    candidate = is_candidate(resp, min_confidence)
    return _write(store, cve_id, row, candidate, stack.choice, now_s)


def _record_error(
    store: Store, cve_id: str, desc_hash: str, model: str, error: str, now_s: str
) -> None:
    """送り直しても直らない失敗を error 行として入れる（同じ説明文は次回送らない）。"""
    row = {
        "model": model,
        "kind": ERROR_CHOICE,
        "kind_confidence": 0.0,
        "kind_probs": {},
        "stack": ERROR_CHOICE,
        "stack_confidence": 0.0,
        "stack_probs": {},
        "input_tokens": None,
        "description_hash": desc_hash,
        "error": error,
    }
    _write(store, cve_id, row, False, ERROR_CHOICE, now_s)


def triage(
    store: Store,
    client: JevClient | None,
    now: datetime,
    *,
    model: str,
    min_confidence: float,
    max_per_run: int,
    max_chars: int,
    dry_run: bool = False,
) -> TriageResult:
    """前回から増えたイベントの CVE のうちルールで決まらないものを Jev に聞き、llm_triage に入れる。

    説明文の hash が既存行と同じものは送らない。CVE ID 順に max_per_run 件まで。
    cursor は処理した最大の cve_event.id（上限で残した CVE があればその最小イベント id の手前）。
    1 件の失敗はスキップして数える。送り直しても直らない失敗（413・応答の形）は error 行を入れて
    次回から送らない。それ以外（429 / 5xx / 接続エラー）が 1 件でもあれば cursor を進めず、
    失敗件数と最後のエラーを last_error に残す（例外にはしない。成功分は書く）。
    JevFatalError（401 / 400 / 422）は全体の失敗にする（それまでの成功分は書いたまま）。
    dry_run では対象を数えるだけで API を呼ばず、書かない（client は None でよい）。
    失敗時は sync_state の last_run_at と last_error だけを更新し、例外を投げ直す。
    """
    now_s = iso(now)
    result = TriageResult(limit=max_per_run)
    try:
        state = store.get_sync_state(SOURCE_TRIAGE)
        cursor = int(state["cursor"]) if state is not None and state["cursor"] else 0
        upto = store.max_event_id()
        pending = [
            (row, desc_hash)
            for row in store.triage_targets(cursor, upto)
            if (desc_hash := description_hash(row["description_en"])) != row["triage_hash"]
        ]
        result.targets = len(pending)
        batch, rest = pending[:max_per_run], pending[max_per_run:]
        result.preview = [row["id"] for row, _ in batch[:PREVIEW_COUNT]]
        if dry_run:
            return result
        if client is None:
            raise ValueError("client is required unless dry_run")

        last_error = ""
        retryable = 0
        for row, desc_hash in batch:
            result.requested += 1
            try:
                resp = client.ask(model, row["description_en"][:max_chars], QUESTIONS)
            except JevFatalError:
                raise
            except JevPermanentError as e:
                result.failed += 1
                result.permanent_failed += 1
                error = client.redact(f"{type(e).__name__}: {e}")
                log.warning("triage %s failed permanently: %s", row["id"], error)
                _record_error(store, row["id"], desc_hash, model, error, now_s)
                continue
            except JevError as e:
                result.failed += 1
                retryable += 1
                last_error = client.redact(f"{type(e).__name__}: {e}")
                log.warning("triage %s failed: %s", row["id"], last_error)
                continue
            if _record(store, row["id"], desc_hash, resp, min_confidence, now_s):
                result.candidates += 1
            result.kinds[resp.answers["kind"].choice] += 1
            result.stacks[resp.answers["stack"].choice] += 1
            result.input_tokens += resp.input_tokens or 0

        if retryable:
            # cursor は据え置き（mark_sync_error は cursor を触らない）
            store.mark_sync_error(
                SOURCE_TRIAGE,
                now_s,
                f"triage: {result.failed}/{result.requested} requests failed; last: {last_error}",
            )
        else:
            # 上限で残した CVE のイベントを次回も拾えるようにする
            new_cursor = min(row["event_id"] for row, _ in rest) - 1 if rest else upto
            store.mark_sync_ok(SOURCE_TRIAGE, now_s, cursor=str(new_cursor))
            result.cursor = new_cursor
    except Exception as e:
        if not dry_run:
            text = f"{type(e).__name__}: {e}"
            store.mark_sync_error(SOURCE_TRIAGE, now_s, client.redact(text) if client else text)
        raise
    return result
