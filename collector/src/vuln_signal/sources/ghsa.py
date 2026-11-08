"""GitHub Advisory Database（reviewed、npm）の取得。

https://docs.github.com/en/rest/security-advisories/global-advisories
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from vuln_signal.sources.http import RetryingClient, SourceError

BASE_URL = "https://api.github.com/advisories"
API_VERSION = "2022-11-28"
PER_PAGE = 100
# Link を辿る上限（暴走防止）。超えたら失敗にする
MAX_PAGES = 50


class GhsaError(SourceError):
    """GHSA の取得に失敗した。"""


@dataclass(frozen=True)
class GhsaRecord:
    ghsa_id: str
    cve_id: str | None
    severity: str | None
    summary: str | None
    published_at: str | None
    updated_at: str | None
    withdrawn_at: str | None
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    cvss_v4_score: float | None
    cvss_v4_vector: str | None
    # [{name, vulnerable_version_range, first_patched_version}] を name, range で並べたもの
    packages: list[dict[str, str | None]]
    html_url: str | None
    # API 応答の 1 件そのもの
    raw: dict[str, Any] = field(repr=False)


def format_ghsa_time(dt: datetime) -> str:
    """modified= の範囲指定用（UTC、例 2026-11-07T01:23:45Z）。"""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_time(value: str | None) -> str | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return format_ghsa_time(dt)


def _cvss(sev: dict[str, Any] | None) -> tuple[float | None, str | None]:
    if not sev:
        return None, None
    score = sev.get("score")
    vector = sev.get("vector_string")
    # 未評価のとき API は score 0.0 / vector null を返す。無しとみなす
    if vector is None and not score:
        return None, None
    return (float(score) if score is not None else None), vector


def _first_patched(value: Any) -> str | None:
    # global advisories は文字列。古い形式の {"identifier": ...} も受ける
    if isinstance(value, dict):
        return value.get("identifier")
    return value


def parse_advisory(adv: dict[str, Any]) -> GhsaRecord:
    """API 応答の 1 件を GhsaRecord にする。"""
    sev = adv.get("cvss_severities") or {}
    v3 = _cvss(sev.get("cvss_v3"))
    v4 = _cvss(sev.get("cvss_v4"))
    packages = sorted(
        (
            {
                "name": (v.get("package") or {}).get("name"),
                "vulnerable_version_range": v.get("vulnerable_version_range"),
                "first_patched_version": _first_patched(v.get("first_patched_version")),
            }
            for v in adv.get("vulnerabilities") or []
        ),
        key=lambda p: (p["name"] or "", p["vulnerable_version_range"] or ""),
    )
    return GhsaRecord(
        ghsa_id=adv["ghsa_id"],
        cve_id=adv.get("cve_id"),
        severity=adv.get("severity"),
        summary=adv.get("summary"),
        published_at=normalize_time(adv.get("published_at")),
        updated_at=normalize_time(adv.get("updated_at")),
        withdrawn_at=normalize_time(adv.get("withdrawn_at")),
        cvss_v3_score=v3[0],
        cvss_v3_vector=v3[1],
        cvss_v4_score=v4[0],
        cvss_v4_vector=v4[1],
        packages=packages,
        html_url=adv.get("html_url"),
        raw=adv,
    )


class GhsaClient(RetryingClient):
    error_cls = GhsaError
    label = "GHSA"

    def __init__(
        self,
        token: str = "",
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        base_url: str = BASE_URL,
        max_pages: int = MAX_PAGES,
    ) -> None:
        self._token = token
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        super().__init__(http=http, sleep=sleep, headers=headers)
        self._base_url = base_url
        self._max_pages = max_pages

    def __repr__(self) -> str:
        return f"GhsaClient(token={'set' if self._token else 'unset'})"

    def redact(self, text: str) -> str:
        """文字列からトークンを伏せる（エラー要約の保存用）。"""
        return text.replace(self._token, "***") if self._token else text

    def fatal_reason(self, resp: httpx.Response) -> str | None:
        # レート制限切れは待っても数十分戻らないので再試行しない
        if resp.status_code in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0":
            retry_after = resp.headers.get("retry-after")
            reset = resp.headers.get("x-ratelimit-reset")
            return (
                f"HTTP {resp.status_code} rate limit exceeded "
                f"(retry-after={retry_after}, x-ratelimit-reset={reset})"
            )
        return None

    def fetch_modified(self, start: datetime, end: datetime) -> list[GhsaRecord]:
        """modified が [start, end] の npm の reviewed advisory を全ページ取る。"""
        params: dict[str, Any] | None = {
            "ecosystem": "npm",
            "type": "reviewed",
            "modified": f"{format_ghsa_time(start)}..{format_ghsa_time(end)}",
            "per_page": PER_PAGE,
            "sort": "updated",
            "direction": "asc",
        }
        url: str | None = self._base_url
        records: list[GhsaRecord] = []
        pages = 0
        while url is not None:
            if pages >= self._max_pages:
                raise GhsaError(f"more than {self._max_pages} pages; giving up")
            resp = self._get(url, params=params)
            pages += 1
            records.extend(parse_advisory(a) for a in resp.json())
            # 次ページは Link の URL をそのまま使う（クエリも含まれている）
            url = resp.links.get("next", {}).get("url")
            params = None
        return records
