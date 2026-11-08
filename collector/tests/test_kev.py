import copy
import json
from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import load_fixture

from vuln_signal.sources.http import USER_AGENT
from vuln_signal.sources.kev import FEED_URL, KevClient, KevError
from vuln_signal.store import Store
from vuln_signal.sync import sync_kev

NOW1 = datetime(2099, 1, 2, 0, 0, tzinfo=UTC)
NOW2 = datetime(2099, 1, 3, 0, 0, tzinfo=UTC)


def _client(fake_sleep):
    return KevClient(sleep=fake_sleep)


def _ok(data: dict, etag: str | None = '"v1"') -> httpx.Response:
    headers = {"ETag": etag} if etag else {}
    return httpx.Response(200, json=data, headers=headers)


def _events(store: Store) -> list[tuple]:
    return [
        tuple(r)
        for r in store.conn.execute(
            "SELECT cve_id, observed_at, kind, before, after, source FROM cve_event ORDER BY id"
        )
    ]


def _dump(store: Store) -> list:
    return [
        list(map(tuple, store.conn.execute(f"SELECT * FROM {t} ORDER BY 1")))
        for t in ("sync_state", "kev", "cve_event")
    ]


@respx.mock
def test_first_sync_is_bootstrap_without_events(store, fake_sleep):
    route = respx.get(FEED_URL).mock(return_value=_ok(load_fixture("kev_catalog.json")))
    result = sync_kev(store, _client(fake_sleep), NOW1)

    assert result.bootstrap is True
    assert (result.fetched, result.catalog_version) == (3, "2099.01.01")
    assert dict(result.events) == {}
    assert _events(store) == []
    assert "If-None-Match" not in route.calls[0].request.headers
    assert route.calls[0].request.headers["User-Agent"] == USER_AGENT

    row = store.list_kev()["CVE-2099-0002"]
    assert row["date_added"] == "2098-12-31"
    assert row["known_ransomware"] == "Known"
    assert json.loads(row["cwes"]) == ["CWE-287", "CWE-308"]
    assert row["fetched_at"] == "2099-01-02T00:00:00Z"
    state = store.get_sync_state("kev")
    assert state["cursor"] == "2099.01.01"
    assert state["etag"] == '"v1"'
    assert state["last_ok_at"] == state["last_run_at"] == "2099-01-02T00:00:00Z"


@respx.mock
def test_second_sync_detects_added_removed_and_ransomware(store, fake_sleep):
    data = load_fixture("kev_catalog.json")
    respx.get(FEED_URL).mock(return_value=_ok(data))
    sync_kev(store, _client(fake_sleep), NOW1)

    changed = copy.deepcopy(data)
    changed["catalogVersion"] = "2099.01.02"
    vulns = changed["vulnerabilities"]
    vulns[0]["knownRansomwareCampaignUse"] = "Known"
    vulns[1]["dueDate"] = "2099-02-01"  # イベント無しで上書き
    del vulns[2]
    for i in (3, 4):
        extra = copy.deepcopy(vulns[1])
        extra["cveID"] = f"CVE-2099-000{i}"
        extra["dateAdded"] = "2099-01-02"
        vulns.append(extra)
    route = respx.get(FEED_URL).mock(return_value=_ok(changed, etag=None))
    result = sync_kev(store, _client(fake_sleep), NOW2)

    assert route.calls.last.request.headers["If-None-Match"] == '"v1"'
    assert result.bootstrap is False
    assert dict(result.events) == {
        "kev_added": 2,
        "kev_removed": 1,
        "kev_ransomware_changed": 1,
    }
    t = "2099-01-03T00:00:00Z"
    assert _events(store) == [
        ("CVE-2099-0001", t, "kev_ransomware_changed", "Unknown", "Known", "kev"),
        ("CVE-2099-0003", t, "kev_added", None, "2099-01-02", "kev"),
        ("CVE-2099-0004", t, "kev_added", None, "2099-01-02", "kev"),
        ("CVE-2098-9999", t, "kev_removed", "2099-01-01", None, "kev"),
    ]
    kev = store.list_kev()
    assert set(kev) == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"}
    assert kev["CVE-2099-0002"]["due_date"] == "2099-02-01"
    state = store.get_sync_state("kev")
    assert state["cursor"] == "2099.01.02"
    # 応答に ETag が無ければ NULL
    assert state["etag"] is None


@respx.mock
def test_not_modified_changes_nothing(store, fake_sleep):
    respx.get(FEED_URL).mock(return_value=_ok(load_fixture("kev_catalog.json")))
    sync_kev(store, _client(fake_sleep), NOW1)
    before = _dump(store)

    respx.get(FEED_URL).mock(return_value=httpx.Response(304))
    result = sync_kev(store, _client(fake_sleep), NOW2)

    assert result.not_modified is True
    assert result.catalog_version == "2099.01.01"
    assert dict(result.events) == {}
    after = _dump(store)
    assert after[1:] == before[1:]
    state = store.get_sync_state("kev")
    assert state["etag"] == '"v1"'
    assert state["cursor"] == "2099.01.01"
    assert state["last_ok_at"] == "2099-01-03T00:00:00Z"


@respx.mock
def test_shrunk_feed_fails_and_keeps_cursor(store, fake_sleep):
    data = load_fixture("kev_catalog.json")
    respx.get(FEED_URL).mock(return_value=_ok(data))
    sync_kev(store, _client(fake_sleep), NOW1)
    before = _dump(store)

    shrunk = copy.deepcopy(data)
    shrunk["catalogVersion"] = "2099.01.02"
    shrunk["vulnerabilities"] = shrunk["vulnerabilities"][:2]  # 2 < 3 * 0.9
    respx.get(FEED_URL).mock(return_value=_ok(shrunk, etag='"v2"'))
    with pytest.raises(KevError, match="less than 90%"):
        sync_kev(store, _client(fake_sleep), NOW2)

    state = store.get_sync_state("kev")
    assert state["cursor"] == "2099.01.01"
    assert state["etag"] == '"v1"'
    assert state["last_ok_at"] == "2099-01-02T00:00:00Z"
    assert state["last_run_at"] == "2099-01-03T00:00:00Z"
    assert "less than 90%" in state["last_error"]
    assert _dump(store)[1:] == before[1:]


@respx.mock
def test_empty_feed_fails(store, fake_sleep):
    data = load_fixture("kev_catalog.json")
    data["vulnerabilities"] = []
    respx.get(FEED_URL).mock(return_value=_ok(data))
    with pytest.raises(KevError, match="no vulnerabilities"):
        sync_kev(store, _client(fake_sleep), NOW1)
    assert store.count_rows("kev") == 0
    assert "no vulnerabilities" in store.get_sync_state("kev")["last_error"]


@respx.mock
def test_dry_run_does_not_write(store, fake_sleep):
    data = load_fixture("kev_catalog.json")
    respx.get(FEED_URL).mock(return_value=_ok(data))
    result = sync_kev(store, _client(fake_sleep), NOW1, dry_run=True)
    assert result.bootstrap is True and result.fetched == 3
    assert store.count_rows("kev") == 0
    assert store.get_sync_state("kev") is None

    sync_kev(store, _client(fake_sleep), NOW1)
    before = _dump(store)
    changed = copy.deepcopy(data)
    changed["vulnerabilities"][0]["knownRansomwareCampaignUse"] = "Known"
    respx.get(FEED_URL).mock(return_value=_ok(changed))
    result = sync_kev(store, _client(fake_sleep), NOW2, dry_run=True)
    assert dict(result.events) == {"kev_ransomware_changed": 1}
    assert _dump(store) == before


@respx.mock
def test_retry_5xx_then_success(fake_sleep):
    route = respx.get(FEED_URL).mock(
        side_effect=[
            httpx.ConnectError("boom"),
            httpx.Response(502),
            _ok(load_fixture("kev_catalog.json")),
        ]
    )
    client = _client(fake_sleep)
    fetched = client.fetch()
    assert len(fetched.records) == 3
    assert route.call_count == client.request_count == 3
    assert fake_sleep.calls == [10.0, 30.0]


@respx.mock
def test_404_fails_immediately(fake_sleep):
    route = respx.get(FEED_URL).mock(return_value=httpx.Response(404))
    with pytest.raises(KevError, match="404"):
        _client(fake_sleep).fetch()
    assert route.call_count == 1
    assert fake_sleep.calls == []
