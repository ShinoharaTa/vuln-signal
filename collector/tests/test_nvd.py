import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from conftest import load_fixture

from vuln_signal.sources.nvd import (
    BASE_URL,
    INTERVAL_NO_KEY,
    INTERVAL_WITH_KEY,
    USER_AGENT,
    NvdClient,
    NvdError,
    format_nvd_time,
    parse_cve,
    split_windows,
)

T0 = datetime(2099, 1, 1, tzinfo=UTC)


def _cves(name: str) -> list[dict]:
    return [v["cve"] for v in load_fixture(name)["vulnerabilities"]]


def test_parse_full_record_prefers_primary():
    rec = parse_cve(_cves("nvd_two_cves.json")[0])
    assert rec.id == "CVE-2099-0001"
    assert rec.published == "2099-01-01T10:15:30Z"
    assert rec.last_modified == "2099-01-01T12:00:00Z"
    assert rec.vuln_status == "Analyzed"
    assert rec.description_en == "Fictional out-of-bounds write in the example driver."
    # v3.1 は Primary を採る
    assert rec.cvss_v31_score == 7.8
    assert rec.cvss_v31_vector == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert rec.cvss_v31_severity == "HIGH"
    # v4.0 は Primary が無いので先頭
    assert rec.cvss_v40_score == 8.5
    assert rec.cvss_v40_vector.startswith("CVSS:4.0/")
    assert rec.cvss_v40_severity == "HIGH"
    assert rec.cwe_ids == ["CWE-125", "CWE-787"]
    assert rec.cpe_criteria == [
        "cpe:2.3:a:example:example_driver:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:o:example:example_os:*:*:*:*:*:*:*:*",
    ]


def test_parse_minimal_record_gives_nulls():
    rec = parse_cve(_cves("nvd_two_cves.json")[1])
    assert rec.description_en is None
    assert rec.cvss_v31_score is None and rec.cvss_v31_vector is None
    assert rec.cvss_v31_severity is None
    assert rec.cvss_v40_score is None and rec.cvss_v40_severity is None
    assert rec.cwe_ids == []
    assert rec.cpe_criteria == []


def test_v31_severity_falls_back_to_parent():
    cve = _cves("nvd_two_cves.json")[1]
    cve["metrics"] = {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "baseSeverity": "CRITICAL",
                "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"},
            }
        ]
    }
    rec = parse_cve(cve)
    assert (rec.cvss_v31_score, rec.cvss_v31_severity) == (9.8, "CRITICAL")


def test_format_nvd_time():
    assert format_nvd_time(datetime(2099, 1, 2, 3, 4, 5, 678900, tzinfo=UTC)) == (
        "2099-01-02T03:04:05.678Z"
    )


def test_split_windows_120_days():
    end = T0 + timedelta(days=250)
    wins = list(split_windows(T0, end))
    assert wins == [
        (T0, T0 + timedelta(days=120)),
        (T0 + timedelta(days=120), T0 + timedelta(days=240)),
        (T0 + timedelta(days=240), end),
    ]


@respx.mock
def test_paging_fetches_all_pages(fake_sleep):
    route = respx.get(BASE_URL).mock(
        side_effect=[
            httpx.Response(200, json=load_fixture("nvd_page1_of_2.json")),
            httpx.Response(200, json=load_fixture("nvd_page2_of_2.json")),
        ]
    )
    client = NvdClient(sleep=fake_sleep, results_per_page=2)
    recs = client.fetch_modified(T0, T0 + timedelta(hours=2))
    assert [r.id for r in recs] == ["CVE-2099-0101", "CVE-2099-0102", "CVE-2099-0103"]
    assert route.call_count == 2
    p1, p2 = (c.request.url.params for c in route.calls)
    assert p1["startIndex"] == "0" and p2["startIndex"] == "2"
    assert p1["resultsPerPage"] == "2"
    assert p1["lastModStartDate"] == "2099-01-01T00:00:00.000Z"
    assert p1["lastModEndDate"] == "2099-01-01T02:00:00.000Z"
    # 2 本目の前にキー無しの間隔だけ待つ
    assert fake_sleep.calls == [INTERVAL_NO_KEY]
    assert route.calls[0].request.headers["User-Agent"] == USER_AGENT


@respx.mock
def test_long_range_is_split_into_windows(fake_sleep):
    empty = {"totalResults": 0, "startIndex": 0, "resultsPerPage": 0, "vulnerabilities": []}
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(200, json=empty))
    client = NvdClient(sleep=fake_sleep)
    client.fetch_modified(T0, T0 + timedelta(days=200))
    assert route.call_count == 2
    starts = [c.request.url.params["lastModStartDate"] for c in route.calls]
    ends = [c.request.url.params["lastModEndDate"] for c in route.calls]
    assert starts == ["2099-01-01T00:00:00.000Z", "2099-05-01T00:00:00.000Z"]
    assert ends == ["2099-05-01T00:00:00.000Z", "2099-07-20T00:00:00.000Z"]


@respx.mock
def test_retry_429_then_success(fake_sleep):
    route = respx.get(BASE_URL).mock(
        side_effect=[
            httpx.Response(429),
            httpx.Response(200, json=load_fixture("nvd_two_cves.json")),
        ]
    )
    client = NvdClient(sleep=fake_sleep)
    recs = client.fetch_modified(T0, T0 + timedelta(hours=1))
    assert len(recs) == 2
    assert route.call_count == 2
    assert fake_sleep.calls == [10.0, INTERVAL_NO_KEY]


@respx.mock
def test_retry_gives_up_after_three(fake_sleep):
    route = respx.get(BASE_URL).mock(
        side_effect=[httpx.ConnectError("boom"), *[httpx.Response(503)] * 3]
    )
    client = NvdClient(sleep=fake_sleep, interval=0)
    with pytest.raises(NvdError, match="503"):
        client.fetch_modified(T0, T0 + timedelta(hours=1))
    assert route.call_count == 4
    assert [s for s in fake_sleep.calls if s] == [10.0, 30.0, 60.0]


@respx.mock
def test_404_fails_immediately(fake_sleep):
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(404))
    client = NvdClient(sleep=fake_sleep)
    with pytest.raises(NvdError, match="404"):
        client.fetch_modified(T0, T0 + timedelta(hours=1))
    assert route.call_count == 1
    assert fake_sleep.calls == []


@respx.mock
def test_api_key_header_and_not_logged(fake_sleep, caplog):
    key = "00000000-test-key-not-real"
    route = respx.get(BASE_URL).mock(
        side_effect=[
            httpx.Response(200, json=load_fixture("nvd_page1_of_2.json")),
            httpx.Response(200, json=load_fixture("nvd_page2_of_2.json")),
        ]
    )
    client = NvdClient(key, sleep=fake_sleep, results_per_page=2)
    with caplog.at_level(logging.DEBUG):
        client.fetch_modified(T0, T0 + timedelta(hours=1))
    assert all(c.request.headers["apiKey"] == key for c in route.calls)
    assert key not in caplog.text
    assert key not in str(route.calls[0].request.url)
    assert key not in repr(client)
    assert fake_sleep.calls == [INTERVAL_WITH_KEY]


@respx.mock
def test_no_api_key_header_without_key(fake_sleep):
    route = respx.get(BASE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("nvd_two_cves.json"))
    )
    NvdClient(sleep=fake_sleep).fetch_modified(T0, T0 + timedelta(hours=1))
    assert "apiKey" not in route.calls[0].request.headers


def test_redact_hides_key():
    client = NvdClient("abc-secret")
    assert client.redact("error with abc-secret inside") == "error with *** inside"
    client.close()
