import copy
import gzip
import json
import logging
from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import load_fixture

from vuln_signal.sources.ghsa import BASE_URL, GhsaClient, GhsaError, parse_advisory
from vuln_signal.sources.http import USER_AGENT
from vuln_signal.store import Store
from vuln_signal.sync import sync_ghsa

NOW1 = datetime(2099, 1, 2, 0, 0, tzinfo=UTC)
NOW2 = datetime(2099, 1, 2, 0, 30, tzinfo=UTC)
NEXT_URL = f"{BASE_URL}?ecosystem=npm&per_page=100&after=Y3Vyc29yOnYy"
TOKEN = "test-token-not-real-0000"


def _client(fake_sleep, token=""):
    return GhsaClient(token, sleep=fake_sleep)


def _all() -> list[dict]:
    return load_fixture("ghsa_page1_of_2.json") + load_fixture("ghsa_page2_of_2.json")


def _mock(advisories: list[dict]):
    return respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=advisories))


def _events(store: Store) -> list[tuple]:
    return [
        tuple(r)
        for r in store.conn.execute(
            "SELECT cve_id, kind, before, after, source FROM cve_event ORDER BY id"
        )
    ]


def _dump(store: Store) -> list:
    return [
        list(map(tuple, store.conn.execute(f"SELECT * FROM {t} ORDER BY 1")))
        for t in ("sync_state", "ghsa", "cve_event")
    ]


def test_parse_advisory():
    rec = parse_advisory(load_fixture("ghsa_page1_of_2.json")[0])
    assert (rec.ghsa_id, rec.cve_id, rec.severity) == (
        "GHSA-2099-aaaa-0001",
        "CVE-2099-0001",
        "high",
    )
    assert rec.updated_at == "2099-01-01T12:00:00Z"
    assert rec.withdrawn_at is None
    assert (rec.cvss_v3_score, rec.cvss_v4_score) == (9.1, 9.3)
    assert rec.cvss_v3_vector.startswith("CVSS:3.1/")
    # name, range で並べる
    assert rec.packages == [
        {"name": "example-a", "vulnerable_version_range": "< 0.9.9", "first_patched_version": None},
        {
            "name": "example-a",
            "vulnerable_version_range": ">= 1.0.0, < 1.4.2",
            "first_patched_version": "1.4.2",
        },
        {
            "name": "example-b",
            "vulnerable_version_range": "< 2.0.0",
            "first_patched_version": "2.0.0",
        },
    ]


def test_zero_score_with_null_vector_is_none():
    rec = parse_advisory(load_fixture("ghsa_page1_of_2.json")[1])
    assert (rec.cvss_v3_score, rec.cvss_v3_vector) == (None, None)
    assert (rec.cvss_v4_score, rec.cvss_v4_vector) == (None, None)


@respx.mock
def test_paging_follows_link(fake_sleep):
    route = respx.get(BASE_URL).mock(
        side_effect=[
            httpx.Response(
                200,
                json=load_fixture("ghsa_page1_of_2.json"),
                headers={"Link": f'<{NEXT_URL}>; rel="next", <{NEXT_URL}x>; rel="last"'},
            ),
            httpx.Response(200, json=load_fixture("ghsa_page2_of_2.json")),
        ]
    )
    client = _client(fake_sleep)
    recs = client.fetch_modified(datetime(2099, 1, 1, tzinfo=UTC), NOW1)
    assert [r.ghsa_id for r in recs] == [
        "GHSA-2099-aaaa-0001",
        "GHSA-2099-bbbb-0002",
        "GHSA-2099-cccc-0003",
    ]
    assert route.call_count == client.request_count == 2
    first, second = (c.request for c in route.calls)
    assert dict(first.url.params) == {
        "ecosystem": "npm",
        "type": "reviewed",
        "modified": "2099-01-01T00:00:00Z..2099-01-02T00:00:00Z",
        "per_page": "100",
        "sort": "updated",
        "direction": "asc",
    }
    assert str(second.url) == NEXT_URL
    assert first.headers["Accept"] == "application/vnd.github+json"
    assert first.headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert first.headers["User-Agent"] == USER_AGENT
    assert "Authorization" not in first.headers
    assert fake_sleep.calls == []


@respx.mock
def test_page_limit(fake_sleep):
    respx.get(BASE_URL).mock(
        return_value=httpx.Response(200, json=[], headers={"Link": f'<{NEXT_URL}>; rel="next"'})
    )
    client = GhsaClient(sleep=fake_sleep, max_pages=3)
    with pytest.raises(GhsaError, match="more than 3 pages"):
        client.fetch_modified(datetime(2099, 1, 1, tzinfo=UTC), NOW1)
    assert client.request_count == 3


@respx.mock
def test_first_sync_records_first_seen(store, fake_sleep):
    route = _mock(_all())
    result = sync_ghsa(store, _client(fake_sleep), NOW1)

    assert result.fetched == 3
    assert dict(result.events) == {"ghsa_first_seen": 3}
    # cursor 無しは now - 24 時間から
    assert route.calls[0].request.url.params["modified"] == (
        "2099-01-01T00:00:00Z..2099-01-02T00:00:00Z"
    )
    # CVE の無い GHSA は GHSA ID が主体
    assert _events(store) == [
        ("CVE-2099-0001", "ghsa_first_seen", None, "GHSA-2099-aaaa-0001", "ghsa"),
        ("GHSA-2099-bbbb-0002", "ghsa_first_seen", None, "GHSA-2099-bbbb-0002", "ghsa"),
        ("CVE-2099-0003", "ghsa_first_seen", None, "GHSA-2099-cccc-0003", "ghsa"),
    ]
    row = store.get_ghsa("GHSA-2099-bbbb-0002")
    assert row["cvss_v3_score"] is None and row["cvss_v4_vector"] is None
    assert json.loads(row["packages"]) == [
        {"name": "example-c", "vulnerable_version_range": "<= 3.1.0", "first_patched_version": None}
    ]
    assert json.loads(gzip.decompress(row["raw_gz"]))["ghsa_id"] == "GHSA-2099-bbbb-0002"
    assert row["fetched_at"] == "2099-01-02T00:00:00Z"
    state = store.get_sync_state("ghsa")
    assert state["cursor"] == state["last_ok_at"] == "2099-01-02T00:00:00Z"


@respx.mock
def test_second_sync_detects_each_change(store, fake_sleep):
    advs = _all()
    _mock(advs)
    sync_ghsa(store, _client(fake_sleep), NOW1)

    changed = copy.deepcopy(advs)
    for a in changed:
        a["updated_at"] = "2099-01-02T00:20:00Z"
    changed[0]["severity"] = "critical"
    changed[0]["vulnerabilities"][2]["first_patched_version"] = "0.9.9"
    changed[1]["cve_id"] = "CVE-2099-0002"
    changed[2]["withdrawn_at"] = "2099-01-02T00:10:00Z"
    route = _mock(changed)
    result = sync_ghsa(store, _client(fake_sleep), NOW2)

    # 前回 cursor - 5 分から
    assert route.calls.last.request.url.params["modified"].startswith("2099-01-01T23:55:00Z..")
    assert dict(result.events) == {
        "ghsa_severity_changed": 1,
        "ghsa_patched_changed": 1,
        "ghsa_cve_assigned": 1,
        "ghsa_withdrawn": 1,
    }
    assert _events(store)[3:] == [
        ("CVE-2099-0001", "ghsa_severity_changed", "high", "critical", "ghsa"),
        (
            "CVE-2099-0001",
            "ghsa_patched_changed",
            "example-a@-,example-a@1.4.2,example-b@2.0.0",
            "example-a@0.9.9,example-a@1.4.2,example-b@2.0.0",
            "ghsa",
        ),
        # cve_id 付与以後は CVE が主体
        ("CVE-2099-0002", "ghsa_cve_assigned", "GHSA-2099-bbbb-0002", "CVE-2099-0002", "ghsa"),
        ("CVE-2099-0003", "ghsa_withdrawn", None, "2099-01-02T00:10:00Z", "ghsa"),
    ]
    assert store.get_ghsa("GHSA-2099-bbbb-0002")["cve_id"] == "CVE-2099-0002"


@respx.mock
def test_updated_at_only_change_has_no_event(store, fake_sleep):
    advs = _all()
    _mock(advs)
    sync_ghsa(store, _client(fake_sleep), NOW1)

    touched = copy.deepcopy(advs)
    touched[0]["updated_at"] = "2099-01-02T00:20:00Z"
    touched[0]["vulnerabilities"].reverse()  # 並び順だけの違いも変化にしない
    _mock(touched)
    result = sync_ghsa(store, _client(fake_sleep), NOW2)
    assert dict(result.events) == {}
    assert store.get_ghsa("GHSA-2099-aaaa-0001")["updated_at"] == "2099-01-02T00:20:00Z"


@respx.mock
def test_duplicates_take_latest_updated(store, fake_sleep):
    first = load_fixture("ghsa_page1_of_2.json")[0]
    later = copy.deepcopy(first)
    later["updated_at"] = "2099-01-01T23:00:00Z"
    later["severity"] = "critical"
    _mock([later, first])
    result = sync_ghsa(store, _client(fake_sleep), NOW1)
    assert result.fetched == 2
    assert dict(result.events) == {"ghsa_first_seen": 1}
    assert store.get_ghsa("GHSA-2099-aaaa-0001")["severity"] == "critical"


@respx.mock
def test_rate_limit_exhausted_fails_immediately(store, fake_sleep):
    route = respx.get(BASE_URL).mock(
        return_value=httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "4070908800"},
        )
    )
    with pytest.raises(GhsaError, match="rate limit") as exc:
        sync_ghsa(store, _client(fake_sleep), NOW1)
    assert "x-ratelimit-reset=4070908800" in str(exc.value)
    assert route.call_count == 1
    assert fake_sleep.calls == []
    state = store.get_sync_state("ghsa")
    assert state["cursor"] is None
    assert "rate limit" in state["last_error"]


@respx.mock
def test_429_without_exhausted_limit_is_retried(fake_sleep):
    route = respx.get(BASE_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "1"}),
            httpx.Response(200, json=[]),
        ]
    )
    _client(fake_sleep).fetch_modified(datetime(2099, 1, 1, tzinfo=UTC), NOW1)
    assert route.call_count == 2
    assert fake_sleep.calls == [10.0]


@respx.mock
def test_token_header_and_not_leaked(store, fake_sleep, caplog):
    route = _mock(load_fixture("ghsa_page1_of_2.json"))
    client = _client(fake_sleep, TOKEN)
    with caplog.at_level(logging.DEBUG):
        sync_ghsa(store, client, NOW1)
        # 例外の文言にトークンが混じっても伏せる
        route.side_effect = [httpx.ConnectError("refused with " + TOKEN)] * 4
        with pytest.raises(GhsaError) as exc:
            sync_ghsa(store, client, NOW2)
    assert route.calls[0].request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in str(exc.value)
    assert TOKEN not in store.get_sync_state("ghsa")["last_error"]
    assert TOKEN not in caplog.text
    assert TOKEN not in repr(client)
    assert TOKEN not in str(route.calls[0].request.url)


@respx.mock
def test_dry_run_does_not_write(store, fake_sleep):
    advs = _all()
    _mock(advs[:1])
    sync_ghsa(store, _client(fake_sleep), NOW1)
    before = _dump(store)

    changed = copy.deepcopy(advs)
    changed[0]["severity"] = "low"
    _mock(changed)
    result = sync_ghsa(store, _client(fake_sleep), NOW2, dry_run=True)
    assert dict(result.events) == {"ghsa_first_seen": 2, "ghsa_severity_changed": 1}
    assert _dump(store) == before


@respx.mock
def test_since_overrides_cursor(store, fake_sleep):
    route = _mock([])
    sync_ghsa(store, _client(fake_sleep), NOW1, since=datetime(2098, 12, 31, tzinfo=UTC))
    assert route.calls[0].request.url.params["modified"].startswith("2098-12-31T00:00:00Z..")
