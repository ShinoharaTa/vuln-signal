"""CISA Known Exploited Vulnerabilities（KEV）カタログの取得。

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from vuln_signal.sources.http import RetryingClient, SourceError

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevError(SourceError):
    """KEV の取得に失敗した、または配信内容が壊れている。"""


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    date_added: str | None
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    due_date: str | None
    known_ransomware: str | None
    cwes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KevFetch:
    # 304（前回から変化なし）なら True。そのとき他の項目は空
    not_modified: bool
    etag: str | None = None
    catalog_version: str | None = None
    records: list[KevRecord] = field(default_factory=list)


def parse_kev(v: dict[str, Any]) -> KevRecord:
    """vulnerabilities[] の 1 件を KevRecord にする。"""
    return KevRecord(
        cve_id=v["cveID"],
        date_added=v.get("dateAdded"),
        vendor_project=v.get("vendorProject"),
        product=v.get("product"),
        vulnerability_name=v.get("vulnerabilityName"),
        due_date=v.get("dueDate"),
        known_ransomware=v.get("knownRansomwareCampaignUse"),
        cwes=sorted(v.get("cwes") or []),
    )


class KevClient(RetryingClient):
    error_cls = KevError
    label = "KEV"

    def __init__(
        self,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        url: str = FEED_URL,
    ) -> None:
        super().__init__(http=http, sleep=sleep)
        self._url = url

    def __repr__(self) -> str:
        return "KevClient()"

    def fetch(self, etag: str | None = None) -> KevFetch:
        """カタログ全体を取る。etag を渡すと条件付き GET にし、304 なら not_modified を返す。"""
        headers = {"If-None-Match": etag} if etag else None
        resp = self._get(self._url, headers=headers, ok_status=(200, 304))
        if resp.status_code == 304:
            return KevFetch(not_modified=True)
        data = resp.json()
        return KevFetch(
            not_modified=False,
            etag=resp.headers.get("ETag"),
            catalog_version=data.get("catalogVersion"),
            records=[parse_kev(v) for v in data.get("vulnerabilities") or []],
        )
