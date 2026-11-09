import json
from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import make_cve, make_ghsa

from vuln_signal.sources.jev import BASE_URL, JevClient, JevFatalError
from vuln_signal.sources.nvd import LINUX_KERNEL_CNA
from vuln_signal.triage import QUESTIONS, description_hash, triage

NOW1 = datetime(2099, 1, 2, 0, 0, tzinfo=UTC)
NOW2 = datetime(2099, 1, 2, 1, 0, tzinfo=UTC)
KEY = "test-key-not-real-1234"
NPM_PKG = "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:node.js:*:*"


def _put(store, cve_id, desc="A flaw in widget.", kind="first_seen", **kw):
    store.upsert_cve(make_cve(cve_id, description_en=desc, **kw), "x")
    store.add_event(cve_id, "x", kind, None, None, "nvd")


def _answer(stack="npm_package", conf=0.8, kind="library", tokens=100):
    return {
        "model": "jev-1.14.0",
        "answers": {
            "kind": {
                "type": "choice",
                "choice": kind,
                "confidence": 0.9,
                "probabilities": {kind: 0.9, "other": 0.1},
            },
            "stack": {
                "type": "choice",
                "choice": stack,
                "confidence": conf,
                "probabilities": {stack: conf, "server": 0.05},
            },
        },
        "usage": {"input_tokens": tokens, "output_tokens": 2},
    }


def _ok(**kw):
    return httpx.Response(200, json=_answer(**kw))


def _by_state(mapping):
    """state（説明文）ごとに応答を返す side_effect。値がリストなら順に返す。"""

    def handler(request):
        state = json.loads(request.content)["state"]
        resp = mapping[state]
        resp = resp.pop(0) if isinstance(resp, list) else resp
        if isinstance(resp, Exception):
            raise resp
        return resp

    return handler


def _run(store, fake_sleep, now=NOW1, **kw):
    opts = dict(model="jev-latest", min_confidence=0.6, max_per_run=500, max_chars=4000)
    opts.update(kw)
    dry_run = opts.get("dry_run", False)
    client = None if dry_run else JevClient(KEY, sleep=fake_sleep)
    return triage(store, client, now, **opts)


def _events(store):
    return [
        tuple(r)
        for r in store.conn.execute(
            "SELECT cve_id, kind, before, after, source FROM cve_event "
            "WHERE source = 'jev' ORDER BY id"
        )
    ]


def _seed_mixed(store):
    _put(store, "CVE-2099-0001")
    _put(store, "CVE-2099-0002", cpe_criteria=[NPM_PKG])
    _put(store, "CVE-2099-0003", source_identifier=LINUX_KERNEL_CNA)
    _put(store, "CVE-2099-0004")
    store.upsert_ghsa(make_ghsa("GHSA-aaaa-0004", "CVE-2099-0004", "high"), "x")
    _put(store, "CVE-2099-0005", vuln_status="Rejected")
    _put(store, "CVE-2099-0006", desc=None)
    _put(store, "CVE-2099-0007", desc="   ")
    # 対象のイベント種別でない
    _put(store, "CVE-2099-0008", kind="status_changed")
    _put(store, "CVE-2099-0009", kind="cpe_changed")
    _put(store, "CVE-2099-0010", kind="source_changed", source_identifier=None)


@respx.mock
def test_dry_run_selects_only_rule_undecided_and_sends_nothing(store, fake_sleep):
    _seed_mixed(store)
    route = respx.post(BASE_URL).mock(return_value=_ok())
    res = _run(store, fake_sleep, dry_run=True)
    assert res.targets == 3
    assert res.preview == ["CVE-2099-0001", "CVE-2099-0009", "CVE-2099-0010"]
    assert route.call_count == 0
    assert store.list_sync_state() == []
    assert store.count_rows("llm_triage") == 0


@respx.mock
def test_dry_run_preview_is_first_five_within_limit(store, fake_sleep):
    for i in range(1, 9):
        _put(store, f"CVE-2099-{i:04d}", desc=f"flaw {i}")
    res = _run(store, fake_sleep, dry_run=True, max_per_run=3)
    assert res.targets == 8
    assert res.preview == ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]
    res = _run(store, fake_sleep, dry_run=True)
    assert len(res.preview) == 5


@respx.mock
def test_records_answers_and_candidate_threshold(store, fake_sleep):
    long_desc = "x" * 50
    _put(store, "CVE-2099-0001", desc="exact")
    _put(store, "CVE-2099-0002", desc="below")
    _put(store, "CVE-2099-0003", desc="none")
    _put(store, "CVE-2099-0004", desc=long_desc)
    route = respx.post(BASE_URL).mock(
        side_effect=_by_state(
            {
                "exact": _ok(conf=0.6),
                "below": _ok(conf=0.59),
                "none": _ok(stack="none", conf=0.99, kind="device_firmware"),
                "x" * 10: _ok(stack="linux_distro_package", conf=0.7, kind="server", tokens=5),
            }
        )
    )
    res = _run(store, fake_sleep, max_chars=10)

    assert (res.targets, res.requested, res.failed, res.candidates) == (4, 4, 0, 2)
    assert dict(res.kinds) == {"library": 2, "device_firmware": 1, "server": 1}
    assert dict(res.stacks) == {"npm_package": 2, "none": 1, "linux_distro_package": 1}
    assert res.input_tokens == 305
    body = json.loads(route.calls[0].request.content)
    assert body["model"] == "jev-latest"
    assert set(body["questions"]) == {"kind", "stack"}
    assert body["questions"]["stack"]["criteria"] == dict(QUESTIONS["stack"].criteria)

    row = store.get_llm_triage("CVE-2099-0001")
    assert (row["provider"], row["model"], row["candidate"]) == ("jev", "jev-1.14.0", 1)
    assert (row["kind"], row["kind_confidence"]) == ("library", 0.9)
    assert (row["stack"], row["stack_confidence"]) == ("npm_package", 0.6)
    assert json.loads(row["stack_probs"]) == {"npm_package": 0.6, "server": 0.05}
    assert json.loads(row["kind_probs"]) == {"library": 0.9, "other": 0.1}
    assert row["input_tokens"] == 100
    assert row["description_hash"] == description_hash("exact")
    assert row["requested_at"] == "2099-01-02T00:00:00Z"
    assert store.get_llm_triage("CVE-2099-0002")["candidate"] == 0
    assert store.get_llm_triage("CVE-2099-0003")["candidate"] == 0
    # hash は切る前の説明文全体
    assert store.get_llm_triage("CVE-2099-0004")["description_hash"] == description_hash(long_desc)

    assert _events(store) == [
        ("CVE-2099-0001", "triage_candidate", None, "npm_package", "jev"),
        ("CVE-2099-0004", "triage_candidate", None, "linux_distro_package", "jev"),
    ]
    state = store.get_sync_state("triage")
    assert state["cursor"] == "4" and res.cursor == 4
    assert state["last_ok_at"] == "2099-01-02T00:00:00Z"
    assert state["last_error"] is None


@respx.mock
def test_same_hash_not_resent_and_candidate_cleared(store, fake_sleep):
    _put(store, "CVE-2099-0001", desc="v1")
    respx.post(BASE_URL).mock(
        side_effect=_by_state({"v1": _ok(), "v2": _ok(stack="none", conf=0.9)})
    )
    _run(store, fake_sleep)

    # 説明文が変わらなければ、対象のイベントがあっても送らない
    store.add_event("CVE-2099-0001", "x", "cpe_changed", None, "+cpe", "nvd")
    res = _run(store, fake_sleep, now=NOW2)
    assert (res.targets, res.requested) == (0, 0)

    _put(store, "CVE-2099-0001", desc="v2", kind="source_changed")
    res = _run(store, fake_sleep, now=NOW2)
    assert (res.targets, res.requested, res.candidates) == (1, 1, 0)
    assert store.get_llm_triage("CVE-2099-0001")["candidate"] == 0
    assert _events(store) == [
        ("CVE-2099-0001", "triage_candidate", None, "npm_package", "jev"),
        ("CVE-2099-0001", "triage_candidate_cleared", "npm_package", None, "jev"),
    ]


@respx.mock
def test_limit_keeps_cursor_before_remaining_events(store, fake_sleep):
    # イベント id: 0001=1, 0003=2, 0002=3
    _put(store, "CVE-2099-0001", desc="a")
    _put(store, "CVE-2099-0003", desc="c")
    _put(store, "CVE-2099-0002", desc="b")
    route = respx.post(BASE_URL).mock(return_value=_ok())
    res = _run(store, fake_sleep, max_per_run=2)
    assert (res.targets, res.requested) == (3, 2)
    assert store.get_llm_triage("CVE-2099-0003") is None
    # 残した 0003 のイベント（id 2）を次回も拾う
    assert store.get_sync_state("triage")["cursor"] == "1"

    res = _run(store, fake_sleep, now=NOW2, max_per_run=2)
    assert (res.targets, res.requested) == (1, 1)
    assert route.call_count == 3
    # 前回の triage_candidate（id 4, 5）までが処理済み
    assert store.get_sync_state("triage")["cursor"] == "5"


@respx.mock
def test_429_waits_retry_after_then_records(store, fake_sleep):
    _put(store, "CVE-2099-0001")
    respx.post(BASE_URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "3"}), _ok()]
    )
    res = _run(store, fake_sleep)
    assert (res.requested, res.failed) == (1, 0)
    assert fake_sleep.calls == [3.0]
    assert store.get_llm_triage("CVE-2099-0001") is not None


@respx.mock
def test_retry_exhausted_skips_cve_and_keeps_cursor(store, fake_sleep, caplog):
    _put(store, "CVE-2099-0001", desc="bad")
    _put(store, "CVE-2099-0002", desc="good")
    respx.post(BASE_URL).mock(
        side_effect=_by_state({"bad": [httpx.Response(429)] * 4 + [_ok()], "good": _ok()})
    )
    res = _run(store, fake_sleep)
    assert (res.targets, res.requested, res.failed) == (2, 2, 1)
    assert res.cursor is None
    assert store.get_llm_triage("CVE-2099-0001") is None
    assert store.get_llm_triage("CVE-2099-0002") is not None
    state = store.get_sync_state("triage")
    assert state["cursor"] is None
    assert state["last_ok_at"] == "2099-01-02T00:00:00Z"
    assert "CVE-2099-0001" in caplog.text

    # 次回は失敗した CVE だけ送り直す
    res = _run(store, fake_sleep, now=NOW2)
    assert (res.targets, res.requested, res.failed) == (1, 1, 0)
    assert store.get_llm_triage("CVE-2099-0001") is not None
    # 前回の triage_candidate（id 3）までが処理済み
    assert store.get_sync_state("triage")["cursor"] == "3"


@respx.mock
def test_401_fails_whole_run_but_keeps_earlier_rows(store, fake_sleep):
    _put(store, "CVE-2099-0001", desc="one")
    _put(store, "CVE-2099-0002", desc="two")
    _put(store, "CVE-2099-0003", desc="three")
    route = respx.post(BASE_URL).mock(
        side_effect=_by_state({"one": _ok(), "two": httpx.Response(401), "three": _ok()})
    )
    with pytest.raises(JevFatalError):
        _run(store, fake_sleep)
    assert route.call_count == 2
    assert fake_sleep.calls == []
    assert store.get_llm_triage("CVE-2099-0001") is not None
    assert store.count_rows("llm_triage") == 1
    assert _events(store) == [("CVE-2099-0001", "triage_candidate", None, "npm_package", "jev")]
    state = store.get_sync_state("triage")
    assert state["last_error"] == "JevFatalError: HTTP 401"
    assert state["cursor"] is None and state["last_ok_at"] is None


@respx.mock
def test_key_not_in_last_error_or_logs(store, fake_sleep, caplog, monkeypatch):
    _put(store, "CVE-2099-0001", desc="one")
    _put(store, "CVE-2099-0002", desc="two")
    respx.post(BASE_URL).mock(
        side_effect=_by_state({"one": httpx.ConnectError("refused " + KEY), "two": _ok()})
    )

    def broken(row):
        raise RuntimeError("write failed " + KEY)

    monkeypatch.setattr(store, "upsert_llm_triage", broken)
    with caplog.at_level("INFO"), pytest.raises(RuntimeError):
        _run(store, fake_sleep)
    assert KEY not in caplog.text
    error = store.get_sync_state("triage")["last_error"]
    assert error == "RuntimeError: write failed ***"
