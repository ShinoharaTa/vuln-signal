import copy
from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import load_fixture

from vuln_signal.sources.epss import BASE_URL, EpssClient, EpssError
from vuln_signal.sources.kev import KevRecord
from vuln_signal.sources.nvd import parse_cve
from vuln_signal.store import Store
from vuln_signal.sync import expected_epss_date, sync_epss

# 14:00 UTC 以降なので期待モデル日は当日
NOW = datetime(2099, 2, 1, 15, 0, tzinfo=UTC)
TODAY = "2099-02-01"


def _client(fake_sleep):
    return EpssClient(sleep=fake_sleep)


def _add_cve(store: Store, cve_id: str, published: str) -> None:
    cve = copy.deepcopy(load_fixture("nvd_two_cves.json")["vulnerabilities"][1]["cve"])
    cve["id"] = cve_id
    cve["published"] = published
    store.upsert_cve(parse_cve(cve), "2099-01-01T00:00:00Z")


def _add_kev(store: Store, cve_id: str) -> None:
    store.upsert_kev(KevRecord(cve_id, "2020-01-01", None, None, None, None, "Unknown"), "x")


def _add_ghsa(store: Store, ghsa_id: str, cve_id: str | None, updated_at: str) -> None:
    store.conn.execute(
        "INSERT INTO ghsa (ghsa_id, cve_id, updated_at) VALUES (?, ?, ?)",
        (ghsa_id, cve_id, updated_at),
    )


def _api(values: dict[str, tuple[float, float]], date: str = TODAY):
    """cve= に含まれる CVE のうち values にあるものだけを返す（未算出は返さない）。"""

    def handler(request: httpx.Request) -> httpx.Response:
        ids = request.url.params["cve"].split(",")
        data = [
            {
                "cve": i,
                "epss": f"{values[i][0]:.9f}",
                "percentile": f"{values[i][1]:.9f}",
                "date": date,
            }
            for i in ids
            if i in values
        ]
        body = {"status": "OK", "total": len(data), "offset": 0, "limit": 100, "data": data}
        return httpx.Response(200, json=body)

    return handler


def _events(store: Store) -> list[tuple]:
    return [
        tuple(r)
        for r in store.conn.execute(
            "SELECT cve_id, kind, before, after, source FROM cve_event ORDER BY id"
        )
    ]


def test_expected_model_date():
    assert expected_epss_date(datetime(2099, 2, 1, 13, 59, tzinfo=UTC)) == "2099-01-31"
    assert expected_epss_date(datetime(2099, 2, 1, 14, 0, tzinfo=UTC)) == "2099-02-01"


@respx.mock
def test_targets_are_recent_cves_kev_and_recent_ghsa(store, fake_sleep):
    _add_cve(store, "CVE-2099-0010", "2099-01-20T00:00:00")  # 30 日以内
    _add_cve(store, "CVE-2098-0001", "2098-12-01T00:00:00")  # 古い
    _add_kev(store, "CVE-2020-0001")
    _add_kev(store, "CVE-2099-0010")  # 重複
    _add_ghsa(store, "GHSA-aaaa-aaaa-aaaa", "CVE-2021-0001", "2099-01-30T00:00:00Z")
    _add_ghsa(store, "GHSA-bbbb-bbbb-bbbb", None, "2099-01-30T00:00:00Z")
    _add_ghsa(store, "GHSA-cccc-cccc-cccc", "CVE-2019-0001", "2098-11-01T00:00:00Z")
    route = respx.get(BASE_URL).mock(side_effect=_api({}))

    result = sync_epss(store, _client(fake_sleep), NOW)

    assert route.call_count == 1
    params = route.calls[0].request.url.params
    assert params["cve"] == "CVE-2020-0001,CVE-2021-0001,CVE-2099-0010"
    assert params["limit"] == "3"
    assert (result.targets, result.fetched) == (3, 0)


@respx.mock
def test_more_than_100_targets_are_split(store, fake_sleep):
    ids = [f"CVE-2020-{i:04d}" for i in range(150)]
    for i in ids:
        _add_kev(store, i)
    route = respx.get(BASE_URL).mock(side_effect=_api(dict.fromkeys(ids, (0.01, 0.1))))

    result = sync_epss(store, _client(fake_sleep), NOW)

    assert route.call_count == 2
    sizes = [len(c.request.url.params["cve"].split(",")) for c in route.calls]
    assert sizes == [100, 50]
    assert [c.request.url.params["limit"] for c in route.calls] == ["100", "50"]
    assert all(len(c.request.url.params["cve"]) <= 2000 for c in route.calls)
    assert result.fetched == 150
    assert store.count_rows("epss") == 150
    # 初めて入れた行はイベントにしない
    assert _events(store) == []
    row = store.get_epss("CVE-2020-0000")
    assert (row["score"], row["percentile"], row["model_date"]) == (0.01, 0.1, TODAY)
    state = store.get_sync_state("epss")
    assert state["cursor"] == TODAY
    assert state["last_ok_at"] == "2099-02-01T15:00:00Z"


@respx.mock
def test_thresholds(store, fake_sleep):
    old = {
        "CVE-2020-0001": (0.1, 0.5),  # +0.2 ちょうど → イベント
        "CVE-2020-0002": (0.1, 0.5),  # +0.19 → 無し
        "CVE-2020-0003": (0.3, 0.89),  # 0.9 を跨ぐ → イベント
        "CVE-2020-0004": (0.3, 0.9),  # 既に 0.9 以上 → 無し
        "CVE-2020-0005": (0.3, 0.85),  # 0.9 未満のまま → 無し
        "CVE-2020-0006": (0.9, 0.99),  # 下がった → 無し
    }
    new = {
        "CVE-2020-0001": (0.3, 0.6),
        "CVE-2020-0002": (0.29, 0.6),
        "CVE-2020-0003": (0.31, 0.9),
        "CVE-2020-0004": (0.31, 0.95),
        "CVE-2020-0005": (0.31, 0.899),
        "CVE-2020-0006": (0.1, 0.5),
    }
    for i in old:
        _add_kev(store, i)
    respx.get(BASE_URL).mock(side_effect=_api(old, date="2099-01-31"))
    sync_epss(store, _client(fake_sleep), NOW)
    assert store.get_sync_state("epss")["cursor"] == "2099-01-31"

    respx.get(BASE_URL).mock(side_effect=_api(new))
    result = sync_epss(store, _client(fake_sleep), NOW)

    assert dict(result.events) == {"epss_changed": 2}
    assert _events(store) == [
        ("CVE-2020-0001", "epss_changed", "0.1000 p0.500", "0.3000 p0.600", "epss"),
        ("CVE-2020-0003", "epss_changed", "0.3000 p0.890", "0.3100 p0.900", "epss"),
    ]
    # イベントにならない変化も上書きされる
    assert store.get_epss("CVE-2020-0006")["score"] == 0.1
    assert store.get_epss("CVE-2020-0006")["model_date"] == TODAY


@respx.mock
def test_skip_when_already_have_expected_date(store, fake_sleep):
    _add_kev(store, "CVE-2020-0001")
    store.mark_sync_ok("epss", "2099-02-01T14:30:00Z", cursor=TODAY)
    before = tuple(store.get_sync_state("epss"))
    route = respx.get(BASE_URL).mock(side_effect=_api({"CVE-2020-0001": (0.5, 0.5)}))

    result = sync_epss(store, _client(fake_sleep), NOW)
    assert result.skipped is True and result.model_date == TODAY
    assert route.call_count == 0
    assert tuple(store.get_sync_state("epss")) == before

    result = sync_epss(store, _client(fake_sleep), NOW, force=True)
    assert result.skipped is False
    assert route.call_count == 1
    assert store.get_epss("CVE-2020-0001")["score"] == 0.5


@respx.mock
def test_older_cursor_does_not_skip(store, fake_sleep):
    store.mark_sync_ok("epss", "2099-01-31T15:00:00Z", cursor="2099-01-31")
    _add_kev(store, "CVE-2020-0001")
    route = respx.get(BASE_URL).mock(side_effect=_api({"CVE-2020-0001": (0.5, 0.5)}))
    assert sync_epss(store, _client(fake_sleep), NOW).skipped is False
    assert route.call_count == 1


@respx.mock
def test_cve_without_epss_is_ignored(store, fake_sleep):
    _add_kev(store, "CVE-2020-0001")
    _add_kev(store, "CVE-2020-0002")
    respx.get(BASE_URL).mock(side_effect=_api({"CVE-2020-0001": (0.5, 0.5)}))
    result = sync_epss(store, _client(fake_sleep), NOW)
    assert (result.targets, result.fetched) == (2, 1)
    assert store.get_epss("CVE-2020-0002") is None
    assert _events(store) == []


@respx.mock
def test_dry_run_does_not_write(store, fake_sleep):
    _add_kev(store, "CVE-2020-0001")
    respx.get(BASE_URL).mock(side_effect=_api({"CVE-2020-0001": (0.1, 0.5)}, "2099-01-31"))
    sync_epss(store, _client(fake_sleep), NOW)
    before = [tuple(store.get_sync_state("epss")), tuple(store.get_epss("CVE-2020-0001"))]

    respx.get(BASE_URL).mock(side_effect=_api({"CVE-2020-0001": (0.5, 0.95)}))
    result = sync_epss(store, _client(fake_sleep), NOW, dry_run=True)
    assert dict(result.events) == {"epss_changed": 1}
    assert result.model_date == TODAY
    after = [tuple(store.get_sync_state("epss")), tuple(store.get_epss("CVE-2020-0001"))]
    assert after == before
    assert _events(store) == []


@respx.mock
def test_failure_keeps_cursor(store, fake_sleep):
    _add_kev(store, "CVE-2020-0001")
    store.mark_sync_ok("epss", "2099-01-31T15:00:00Z", cursor="2099-01-31")
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(503))
    with pytest.raises(EpssError, match="503"):
        sync_epss(store, _client(fake_sleep), NOW)
    assert route.call_count == 4
    assert fake_sleep.calls == [10.0, 30.0, 60.0]
    state = store.get_sync_state("epss")
    assert state["cursor"] == "2099-01-31"
    assert state["last_ok_at"] == "2099-01-31T15:00:00Z"
    assert state["last_run_at"] == "2099-02-01T15:00:00Z"
    assert "503" in state["last_error"]
    assert store.count_rows("epss") == 0
