import json
from datetime import UTC, datetime

import pytest
from conftest import make_cve, make_ghsa

from vuln_signal.config import Rules, parse_rules
from vuln_signal.sources.epss import EpssRecord
from vuln_signal.sources.nvd import LINUX_KERNEL_CNA
from vuln_signal.sync import classify

NOW1 = datetime(2099, 1, 2, 0, 0, tzinfo=UTC)
NOW2 = datetime(2099, 1, 2, 1, 0, tzinfo=UTC)
NOW3 = datetime(2099, 1, 2, 2, 0, tzinfo=UTC)
NPM_PKG = "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:node.js:*:*"
OTHER = "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*"


def _cve(cve_id, cvss=None, cpe=(NPM_PKG,), status="Analyzed", source="cna@example.invalid"):
    return make_cve(
        cve_id,
        vuln_status=status,
        source_identifier=source,
        cvss_v31_score=cvss,
        cpe_criteria=list(cpe),
    )


def _put(store, rec, at="2099-01-01T00:00:00Z", kind="first_seen"):
    store.upsert_cve(rec, at)
    store.add_event(rec.id, at, kind, None, None, "nvd")


def _tier_events(store):
    return [
        tuple(r)
        for r in store.conn.execute(
            "SELECT cve_id, before, after, source FROM cve_event "
            "WHERE kind = 'tier_changed' ORDER BY id"
        )
    ]


def _tiers(store):
    return {r["subject_id"]: r["tier"] for r in store.conn.execute("SELECT * FROM tier")}


def test_first_classify_writes_tier_and_events(store):
    _put(store, _cve("CVE-2099-0001", 7.5))
    _put(store, _cve("CVE-2099-0002", 5.0))
    _put(store, _cve("CVE-2099-0003", 9.8, cpe=(OTHER,)))
    res = classify(store, Rules(), NOW1)

    assert res.targets == 3
    assert dict(res.tiers) == {"P1": 1, "P2": 1, "excluded": 1}
    assert dict(res.changes) == {"new": 2}
    assert res.rules_version == Rules().version
    assert _tiers(store) == {"CVE-2099-0001": "P1", "CVE-2099-0002": "P2"}
    assert _tier_events(store) == [
        ("CVE-2099-0001", None, "P1", "rules"),
        ("CVE-2099-0002", None, "P2", "rules"),
    ]
    row = store.get_tier("CVE-2099-0001")
    assert json.loads(row["stacks"]) == ["npm"]
    assert json.loads(row["reasons"]) == ["cvss"]
    assert json.loads(row["inputs"]) == {
        "cvss": 7.5,
        "epss": None,
        "percentile": None,
        "kev": False,
        "vuln_status": "Analyzed",
        "ghsa_severity": None,
    }
    assert (row["rules_version"], row["computed_at"]) == (Rules().version, "2099-01-02T00:00:00Z")
    state = store.get_sync_state("classify")
    # cursor は処理開始時点の MAX(id)。今回積んだ tier_changed は含まない
    assert state["cursor"] == "3"
    assert state["last_ok_at"] == "2099-01-02T00:00:00Z"


def test_diff_selects_only_new_non_rule_events(store):
    _put(store, _cve("CVE-2099-0001", 7.5))
    _put(store, _cve("CVE-2099-0002", 5.0))
    classify(store, Rules(), NOW1)

    # 変化の無い 2 回目は対象 0（tier_changed は対象にしない）
    res = classify(store, Rules(), NOW2)
    assert res.targets == 0
    assert store.get_sync_state("classify")["cursor"] == str(store.max_event_id())

    # CVSS が上がった CVE だけを見る
    store.upsert_cve(_cve("CVE-2099-0002", 9.0), "2099-01-02T01:30:00Z")
    store.add_event(
        "CVE-2099-0002", "2099-01-02T01:30:00Z", "cvss_v31_changed", "5.0", "9.0", "nvd"
    )
    res = classify(store, Rules(), NOW3)
    assert res.targets == 1
    assert dict(res.changes) == {"up": 1}
    assert _tier_events(store)[-1] == ("CVE-2099-0002", "P2", "P1", "rules")


def test_diff_selects_epss_fetched_after_last_ok(store):
    _put(store, _cve("CVE-2099-0001", 5.0))
    _put(store, _cve("CVE-2099-0002", 5.0))
    classify(store, Rules(), NOW1)
    # 閾値未満の変化でイベントが無くても、EPSS が新しく取れたら判定し直す
    store.upsert_epss(EpssRecord("CVE-2099-0001", 0.01, 0.95, "2099-01-02"), "2099-01-02T00:30:00Z")
    store.upsert_epss(EpssRecord("CVE-2099-0002", 0.01, 0.10, "2099-01-01"), "2099-01-01T12:00:00Z")
    res = classify(store, Rules(), NOW2)
    assert res.targets == 1
    assert _tiers(store)["CVE-2099-0001"] == "P1"


def test_tier_changed_only_when_tier_changes(store):
    _put(store, _cve("CVE-2099-0001", 7.5))
    classify(store, Rules(), NOW1)
    # tier は P1 のまま、reasons と inputs だけ変わる
    store.upsert_cve(_cve("CVE-2099-0001", 7.8), "x")
    store.add_event("CVE-2099-0001", "x", "cvss_v31_changed", "7.5", "7.8", "nvd")
    store.upsert_epss(EpssRecord("CVE-2099-0001", 0.01, 0.95, "2099-01-02"), "2099-01-02T00:30:00Z")
    res = classify(store, Rules(), NOW2)
    assert res.targets == 1
    assert dict(res.changes) == {}
    assert len(_tier_events(store)) == 1
    row = store.get_tier("CVE-2099-0001")
    assert json.loads(row["reasons"]) == ["cvss", "epss_percentile"]
    assert json.loads(row["inputs"])["cvss"] == 7.8
    assert row["computed_at"] == "2099-01-02T01:00:00Z"


def test_moving_out_of_scope_deletes_tier(store):
    _put(store, _cve("CVE-2099-0001", 9.0))
    classify(store, Rules(), NOW1)
    store.upsert_cve(_cve("CVE-2099-0001", 9.0, cpe=(OTHER,)), "x")
    store.add_event("CVE-2099-0001", "x", "status_changed", "Analyzed", "Modified", "nvd")
    res = classify(store, Rules(), NOW2)
    assert dict(res.changes) == {"removed": 1}
    assert dict(res.tiers) == {"excluded": 1}
    assert store.get_tier("CVE-2099-0001") is None
    assert _tier_events(store)[-1] == ("CVE-2099-0001", "P1", None, "rules")


def test_down_change(store):
    _put(store, _cve("CVE-2099-0001", 9.0))
    classify(store, Rules(), NOW1)
    store.upsert_cve(_cve("CVE-2099-0001", 9.0, status="Rejected"), "x")
    store.add_event("CVE-2099-0001", "x", "status_changed", "Analyzed", "Rejected", "nvd")
    res = classify(store, Rules(), NOW2)
    assert dict(res.changes) == {"down": 1}
    assert _tiers(store) == {"CVE-2099-0001": "P3"}


def test_ghsa_cve_assigned_reclassifies_old_ghsa_subject(store):
    store.upsert_ghsa(make_ghsa("GHSA-aaaa-0001", None, "high"), "x")
    store.add_event("GHSA-aaaa-0001", "x", "ghsa_first_seen", None, "GHSA-aaaa-0001", "ghsa")
    classify(store, Rules(), NOW1)
    assert _tiers(store) == {"GHSA-aaaa-0001": "P1"}

    store.upsert_ghsa(make_ghsa("GHSA-aaaa-0001", "CVE-2099-0009", "high"), "x")
    store.add_event(
        "CVE-2099-0009", "x", "ghsa_cve_assigned", "GHSA-aaaa-0001", "CVE-2099-0009", "ghsa"
    )
    res = classify(store, Rules(), NOW2)
    assert res.targets == 2
    assert _tiers(store) == {"CVE-2099-0009": "P1"}
    assert dict(res.changes) == {"new": 1, "removed": 1}


def test_all_reclassifies_everything_with_new_rules(store):
    _put(store, _cve("CVE-2099-0001", 5.0))
    _put(store, _cve("CVE-2099-0002", 7.5, source=LINUX_KERNEL_CNA, cpe=()))
    classify(store, Rules(), NOW1)
    assert _tiers(store) == {"CVE-2099-0001": "P2", "CVE-2099-0002": "P3"}

    rules = parse_rules({"thresholds": {"p1_cvss": 5.0, "kernel_cvss": 7.0}})
    assert classify(store, rules, NOW2).targets == 0
    res = classify(store, rules, NOW3, all_subjects=True)
    assert res.all and res.targets == 2
    assert dict(res.changes) == {"up": 2}
    assert _tiers(store) == {"CVE-2099-0001": "P1", "CVE-2099-0002": "P1"}
    assert {r["rules_version"] for r in store.conn.execute("SELECT * FROM tier")} == {rules.version}


def _dump(store):
    return [
        list(map(tuple, store.conn.execute(f"SELECT * FROM {t} ORDER BY 1")))
        for t in ("sync_state", "tier", "cve_event")
    ]


def test_dry_run_writes_nothing(store):
    _put(store, _cve("CVE-2099-0001", 7.5))
    before = _dump(store)
    res = classify(store, Rules(), NOW1, dry_run=True)
    assert res.targets == 1
    assert dict(res.tiers) == {"P1": 1}
    assert dict(res.changes) == {"new": 1}
    assert _dump(store) == before


def test_failure_records_error_and_rolls_back(store, monkeypatch):
    _put(store, _cve("CVE-2099-0001", 7.5))
    _put(store, _cve("CVE-2099-0002", 7.5))
    calls = {"n": 0}
    orig = store.upsert_tier

    def flaky(*args):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        orig(*args)

    monkeypatch.setattr(store, "upsert_tier", flaky)
    with pytest.raises(RuntimeError):
        classify(store, Rules(), NOW1)
    assert store.count_rows("tier") == 0
    assert _tier_events(store) == []
    state = store.get_sync_state("classify")
    assert state["last_error"] == "RuntimeError: boom"
    assert state["cursor"] is None and state["last_ok_at"] is None
