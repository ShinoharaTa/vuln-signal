"""FIRST EPSS API からの取得。

https://www.first.org/epss/api
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

import httpx

from vuln_signal.sources.http import RetryingClient, SourceError

BASE_URL = "https://api.first.org/data/v1/epss"
# 1 リクエストあたりの CVE 数。URL の cve 部分が 2,000 字以内に収まる
BATCH_SIZE = 100


class EpssError(SourceError):
    """EPSS の取得に失敗した。"""


@dataclass(frozen=True)
class EpssRecord:
    cve_id: str
    score: float
    percentile: float
    model_date: str  # YYYY-MM-DD


def chunks(items: list[str], size: int) -> Iterator[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


class EpssClient(RetryingClient):
    error_cls = EpssError
    label = "EPSS"

    def __init__(
        self,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        base_url: str = BASE_URL,
        batch_size: int = BATCH_SIZE,
    ) -> None:
        super().__init__(http=http, sleep=sleep)
        self._base_url = base_url
        self._batch_size = batch_size

    def __repr__(self) -> str:
        return "EpssClient()"

    def fetch(self, cve_ids: list[str]) -> list[EpssRecord]:
        """cve_ids の EPSS を取る。EPSS が未算出の CVE は応答に含まれない。"""
        records: list[EpssRecord] = []
        for batch in chunks(cve_ids, self._batch_size):
            resp = self._get(self._base_url, params={"cve": ",".join(batch), "limit": len(batch)})
            data = resp.json()
            if data.get("status") != "OK":
                raise EpssError(f"EPSS status {data.get('status')!r}")
            records.extend(
                EpssRecord(
                    cve_id=d["cve"],
                    score=float(d["epss"]),
                    percentile=float(d["percentile"]),
                    model_date=d["date"],
                )
                for d in data.get("data") or []
            )
        return records
