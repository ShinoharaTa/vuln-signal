"""NVD CVE API 2.0 からの取得と、1 件ごとの項目の取り出し。

https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from vuln_signal.sources.http import TIMEOUT_SECONDS, USER_AGENT

log = logging.getLogger(__name__)

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW = timedelta(days=120)
RESULTS_PER_PAGE = 2000
# NVD の公開上限: キー無し 5 req / 30 秒、キー有り 50 req / 30 秒
INTERVAL_NO_KEY = 6.0
INTERVAL_WITH_KEY = 0.6
RETRY_WAITS = (10.0, 30.0, 60.0)
RETRY_STATUS = {403, 429}

# Linux kernel CNA（kernel.org）の sourceIdentifier。NVD の実応答で確認した値
LINUX_KERNEL_CNA = "416baaa9-dc9f-4396-8d5f-8c081fb06d67"


class NvdError(Exception):
    """NVD からの取得に失敗した（再試行しても回復しなかった）。"""


@dataclass(frozen=True)
class CveRecord:
    id: str
    published: str | None
    last_modified: str | None
    vuln_status: str | None
    source_identifier: str | None
    description_en: str | None
    cvss_v31_score: float | None
    cvss_v31_vector: str | None
    cvss_v31_severity: str | None
    cvss_v40_score: float | None
    cvss_v40_vector: str | None
    cvss_v40_severity: str | None
    cwe_ids: list[str]
    cpe_criteria: list[str]
    # NVD の vulnerabilities[].cve そのもの
    raw: dict[str, Any] = field(repr=False)


def format_nvd_time(dt: datetime) -> str:
    """NVD のクエリ用の日時（UTC、ミリ秒付き、例 2026-11-07T00:00:00.000Z）。"""
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def normalize_time(value: str | None) -> str | None:
    """NVD の日時（タイムゾーン無しの UTC、ミリ秒付き）を 2026-11-07T01:23:45Z 形式にする。"""
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pick_metric(metrics: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    if not metrics:
        return None
    for m in metrics:
        if m.get("type") == "Primary":
            return m
    return metrics[0]


def _cvss(metric: dict[str, Any] | None) -> tuple[float | None, str | None, str | None]:
    if metric is None:
        return None, None, None
    data = metric.get("cvssData") or {}
    score = data.get("baseScore")
    severity = data.get("baseSeverity") or metric.get("baseSeverity")
    return (
        float(score) if score is not None else None,
        data.get("vectorString"),
        severity,
    )


def parse_cve(cve: dict[str, Any]) -> CveRecord:
    """vulnerabilities[].cve を 1 件の CveRecord にする。"""
    metrics = cve.get("metrics") or {}
    v31 = _cvss(_pick_metric(metrics.get("cvssMetricV31")))
    v40 = _cvss(_pick_metric(metrics.get("cvssMetricV40")))

    description = next(
        (d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"),
        None,
    )
    cwe_ids = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses") or []
            for d in w.get("description") or []
            if str(d.get("value", "")).startswith("CWE-")
        }
    )
    cpe_criteria = sorted(
        {
            m["criteria"]
            for c in cve.get("configurations") or []
            for n in c.get("nodes") or []
            for m in n.get("cpeMatch") or []
            if m.get("vulnerable") is True and m.get("criteria")
        }
    )
    return CveRecord(
        id=cve["id"],
        published=normalize_time(cve.get("published")),
        last_modified=normalize_time(cve.get("lastModified")),
        vuln_status=cve.get("vulnStatus"),
        source_identifier=cve.get("sourceIdentifier"),
        description_en=description,
        cvss_v31_score=v31[0],
        cvss_v31_vector=v31[1],
        cvss_v31_severity=v31[2],
        cvss_v40_score=v40[0],
        cvss_v40_vector=v40[1],
        cvss_v40_severity=v40[2],
        cwe_ids=cwe_ids,
        cpe_criteria=cpe_criteria,
        raw=cve,
    )


def split_windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    """[start, end] を MAX_WINDOW 以下の窓に分ける。"""
    cur = start
    while cur < end:
        nxt = min(cur + MAX_WINDOW, end)
        yield cur, nxt
        cur = nxt


class NvdClient:
    def __init__(
        self,
        api_key: str = "",
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        interval: float | None = None,
        results_per_page: int = RESULTS_PER_PAGE,
        base_url: str = BASE_URL,
    ) -> None:
        self._api_key = api_key
        headers = {"User-Agent": USER_AGENT}
        if api_key:
            headers["apiKey"] = api_key
        self._http = http or httpx.Client(timeout=TIMEOUT_SECONDS)
        self._http.headers.update(headers)
        self._sleep = sleep
        if interval is None:
            interval = INTERVAL_WITH_KEY if api_key else INTERVAL_NO_KEY
        self._interval = interval
        self._results_per_page = results_per_page
        self._base_url = base_url
        self._requested = False
        self.request_count = 0

    def __repr__(self) -> str:
        return f"NvdClient(api_key={'set' if self._api_key else 'unset'})"

    def close(self) -> None:
        self._http.close()

    def redact(self, text: str) -> str:
        """文字列から API キーを伏せる（エラー要約の保存用）。"""
        return text.replace(self._api_key, "***") if self._api_key else text

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        attempt = 0
        while True:
            if self._requested:
                self._sleep(self._interval)
            self._requested = True
            self.request_count += 1
            log.info("NVD GET %s", params)
            try:
                resp = self._http.get(self._base_url, params=params, timeout=TIMEOUT_SECONDS)
            except (httpx.TransportError, httpx.TimeoutException) as e:
                reason = f"{type(e).__name__}: {e}"
            else:
                if resp.status_code == 200:
                    return resp.json()
                status = resp.status_code
                # NVD はエラー理由を message ヘッダで返す
                reason = f"HTTP {status} {resp.headers.get('message', '')}".rstrip()
                if not (status in RETRY_STATUS or status >= 500):
                    raise NvdError(self.redact(reason))
            if attempt >= len(RETRY_WAITS):
                raise NvdError(self.redact(f"{reason} (after {attempt} retries)"))
            wait = RETRY_WAITS[attempt]
            attempt += 1
            log.warning("NVD request failed (%s); retry %d in %.0fs", reason, attempt, wait)
            self._sleep(wait)

    def fetch_modified(self, start: datetime, end: datetime) -> list[CveRecord]:
        """lastModified が [start, end] の CVE を全件取る。範囲は 120 日ごと、全ページを辿る。"""
        records: list[CveRecord] = []
        for win_start, win_end in split_windows(start, end):
            start_index = 0
            while True:
                data = self._get(
                    {
                        "lastModStartDate": format_nvd_time(win_start),
                        "lastModEndDate": format_nvd_time(win_end),
                        "resultsPerPage": self._results_per_page,
                        "startIndex": start_index,
                    }
                )
                vulns = data.get("vulnerabilities") or []
                records.extend(parse_cve(v["cve"]) for v in vulns)
                start_index += len(vulns)
                if not vulns or start_index >= int(data.get("totalResults", 0)):
                    break
        return records
