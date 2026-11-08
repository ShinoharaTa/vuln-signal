import copy
import gzip
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from conftest import load_fixture

from vuln_signal.sources.nvd import BASE_URL, NvdClient, NvdError
from vuln_signal.store import Store
from vuln_signal.sync import sync_nvd

NOW1 = datetime(2099, 1, 2, 0, 0, tzinfo=UTC)
NOW2 = datetime(2099, 1, 2, 0, 30, tzinfo=UTC)


def _client(fake_sleep, key=""):
    return NvdClient(key, sleep=fake_sleep)


def _page(cves: list[dict]) -> dict:
    return {
        "totalResults": len(cves),
        "startIndex": 0,
        "resultsPerPage": len(cves),
        "vulnerabilities": [{"cve": c} for c in cves],
    }


def _base_cves() -> list[dict]:
    return [v["cve"] for v in load_fixture("nvd_two_cves.json")["vulnerabilities"]]


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
        for t in ("sync_state", "cve", "cve_event")
    ]


@respx.mock
def test_first_sync_records_first_seen(store, fake_sleep):
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(_base_cves())))
    result = sync_nvd(store, _client(fake_sleep), NOW1)

    assert (result.fetched, result.new) == (2, 2)
    assert dict(result.events) == {"first_seen": 2}
    # cursor 無しは now - 24 時間から
    params = route.calls[0].request.url.params
    assert params["lastModStartDate"] == "2099-01-01T00:00:00.000Z"
    assert params["lastModEndDate"] == "2099-01-02T00:00:00.000Z"

    assert _events(store) == [
        (
            "CVE-2099-0001",
            "2099-01-02T00:00:00Z",
            "first_seen",
            None,
            "2099-01-01T10:15:30Z",
            "nvd",
        ),
        (
            "CVE-2099-0002",
            "2099-01-02T00:00:00Z",
            "first_seen",
            None,
            "2099-01-01T11:00:00Z",
            "nvd",
        ),
    ]
    row = store.get_cve("CVE-2099-0001")
    assert json.loads(row["cwe_ids"]) == ["CWE-125", "CWE-787"]
    assert json.loads(gzip.decompress(row["raw_gz"]))["id"] == "CVE-2099-0001"
    assert row["fetched_at"] == "2099-01-02T00:00:00Z"
    state = store.get_sync_state("nvd")
    assert state["cursor"] == state["last_ok_at"] == state["last_run_at"] == "2099-01-02T00:00:00Z"
    assert state["last_error"] is None


@respx.mock
def test_second_sync_detects_cvss_and_status_changes(store, fake_sleep):
    cves = _base_cves()
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(cves)))
    sync_nvd(store, _client(fake_sleep), NOW1)

    changed = copy.deepcopy(cves)
    m = changed[0]["metrics"]["cvssMetricV31"][1]["cvssData"]
    m["baseScore"] = 9.8
    m["vectorString"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    changed[0]["lastModified"] = "2099-01-02T00:10:00.000"
    changed[1]["vulnStatus"] = "Rejected"
    changed[1]["metrics"] = {
        "cvssMetricV40": [
            {
                "type": "Secondary",
                "cvssData": {
                    "baseScore": 6.9,
                    "vectorString": "CVSS:4.0/AV:N",
                    "baseSeverity": "MEDIUM",
                },
            }
        ]
    }
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(changed)))
    result = sync_nvd(store, _client(fake_sleep), NOW2)

    assert result.new == 0
    assert dict(result.events) == {
        "cvss_v31_changed": 1,
        "cvss_v40_changed": 1,
        "status_changed": 1,
    }
    # 前回 cursor - 5 分から
    assert route.calls.last.request.url.params["lastModStartDate"] == "2099-01-01T23:55:00.000Z"
    ev = _events(store)[2:]
    assert ev == [
        (
            "CVE-2099-0001",
            "2099-01-02T00:30:00Z",
            "cvss_v31_changed",
            "7.8 CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "nvd",
        ),
        (
            "CVE-2099-0002",
            "2099-01-02T00:30:00Z",
            "cvss_v40_changed",
            None,
            "6.9 CVSS:4.0/AV:N",
            "nvd",
        ),
        ("CVE-2099-0002", "2099-01-02T00:30:00Z", "status_changed", "Received", "Rejected", "nvd"),
    ]
    assert store.get_cve("CVE-2099-0001")["last_modified"] == "2099-01-02T00:10:00Z"


@respx.mock
def test_last_modified_only_change_has_no_event(store, fake_sleep):
    cves = _base_cves()
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(cves)))
    sync_nvd(store, _client(fake_sleep), NOW1)

    touched = copy.deepcopy(cves)
    touched[0]["lastModified"] = "2099-01-02T00:20:00.000"
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(touched)))
    result = sync_nvd(store, _client(fake_sleep), NOW2)

    assert dict(result.events) == {}
    assert len(_events(store)) == 2
    assert store.get_cve("CVE-2099-0001")["last_modified"] == "2099-01-02T00:20:00Z"


@respx.mock
def test_duplicates_in_one_sync_are_merged(store, fake_sleep):
    first = _base_cves()[1]
    later = copy.deepcopy(first)
    later["lastModified"] = "2099-01-01T23:00:00.000"
    later["vulnStatus"] = "Rejected"
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page([later, first])))
    result = sync_nvd(store, _client(fake_sleep), NOW1)

    assert result.fetched == 2
    assert dict(result.events) == {"first_seen": 1}
    assert store.get_cve("CVE-2099-0002")["vuln_status"] == "Rejected"


@respx.mock
def test_failure_keeps_cursor(store, fake_sleep):
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(_base_cves())))
    sync_nvd(store, _client(fake_sleep), NOW1)
    before = _dump(store)

    key = "00000000-test-key-not-real"
    respx.get(BASE_URL).mock(return_value=httpx.Response(400, headers={"message": "bad " + key}))
    with pytest.raises(NvdError):
        sync_nvd(store, _client(fake_sleep, key), NOW2)

    state = store.get_sync_state("nvd")
    assert state["cursor"] == "2099-01-02T00:00:00Z"
    assert state["last_ok_at"] == "2099-01-02T00:00:00Z"
    assert state["last_run_at"] == "2099-01-02T00:30:00Z"
    assert "400" in state["last_error"]
    assert key not in state["last_error"]
    # cve / cve_event は変わらない
    assert _dump(store)[1:] == before[1:]


@respx.mock
def test_write_failure_rolls_back(store, fake_sleep, monkeypatch):
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(_base_cves())))
    calls = {"n": 0}
    orig = Store.add_event

    def flaky(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk full")
        return orig(self, *args, **kwargs)

    monkeypatch.setattr(Store, "add_event", flaky)
    with pytest.raises(RuntimeError):
        sync_nvd(store, _client(fake_sleep), NOW1)

    assert store.conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0] == 0
    assert _events(store) == []
    state = store.get_sync_state("nvd")
    assert state["cursor"] is None and state["last_ok_at"] is None
    assert state["last_error"] == "RuntimeError: disk full"


@respx.mock
def test_since_overrides_cursor(store, fake_sleep):
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page([])))
    sync_nvd(store, _client(fake_sleep), NOW1, since=datetime(2098, 12, 31, tzinfo=UTC))
    assert route.calls[0].request.url.params["lastModStartDate"] == "2098-12-31T00:00:00.000Z"


@respx.mock
def test_lookback_hours(store, fake_sleep):
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page([])))
    sync_nvd(store, _client(fake_sleep), NOW1, lookback_hours=2)
    start = route.calls[0].request.url.params["lastModStartDate"]
    assert start == "2099-01-01T22:00:00.000Z"
    assert NOW1 - timedelta(hours=2) == datetime(2099, 1, 1, 22, tzinfo=UTC)


@respx.mock
def test_dry_run_does_not_write(store, fake_sleep):
    cves = _base_cves()
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(cves[:1])))
    sync_nvd(store, _client(fake_sleep), NOW1)
    before = _dump(store)

    changed = copy.deepcopy(cves)
    changed[0]["vulnStatus"] = "Modified"
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page(changed)))
    result = sync_nvd(store, _client(fake_sleep), NOW2, dry_run=True)

    # CVE-2099-0002 の published は窓（前回 cursor - 5 分以降）より前なので新規公開ではない
    assert (result.fetched, result.new) == (2, 0)
    assert dict(result.events) == {"first_seen": 1, "status_changed": 1}
    assert _dump(store) == before


@respx.mock
def test_old_cve_recently_modified_is_first_seen_but_not_new(store, fake_sleep):
    old = copy.deepcopy(_base_cves()[1])
    old["id"] = "CVE-2019-9999"
    old["published"] = "2019-05-01T00:00:00.000"
    old["lastModified"] = "2099-01-01T23:00:00.000"
    fresh = _base_cves()[0]
    respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=_page([old, fresh])))
    result = sync_nvd(store, _client(fake_sleep), NOW1)

    assert dict(result.events) == {"first_seen": 2}
    assert result.new == 1
    kinds = {(r[0], r[2], r[4]) for r in _events(store)}
    assert ("CVE-2019-9999", "first_seen", "2019-05-01T00:00:00Z") in kinds
