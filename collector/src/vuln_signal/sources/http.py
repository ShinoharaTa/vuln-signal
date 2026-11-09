"""各ソースのクライアントで共通の HTTP まわり（User-Agent、リトライ）。"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Collection
from typing import Any

import httpx

log = logging.getLogger(__name__)

USER_AGENT = "vuln-signal/0.1 (+https://github.com/ShinoharaTa/vuln-signal)"
TIMEOUT_SECONDS = 60.0
# 429 / 5xx / 接続エラーのときの待ち時間。最大 3 回
RETRY_WAITS = (10.0, 30.0, 60.0)


class SourceError(Exception):
    """取得に失敗した（再試行しても回復しなかった）。"""


class RetryingClient:
    """GET / POST を 429 / 5xx / 接続エラーで再試行するクライアントの土台。

    サブクラスは error_cls / label を決め、必要なら redact() / fatal_reason() / retry_wait() を
    上書きする。fatal_reason() で失敗させるときの例外は fatal_error_cls（無ければ error_cls）。
    """

    error_cls: type[SourceError] = SourceError
    fatal_error_cls: type[SourceError] | None = None
    label = "HTTP"

    def __init__(
        self,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._http = http or httpx.Client(timeout=TIMEOUT_SECONDS)
        self._http.headers.update({"User-Agent": USER_AGENT, **(headers or {})})
        self._sleep = sleep or time.sleep
        self.request_count = 0

    def close(self) -> None:
        self._http.close()

    def redact(self, text: str) -> str:
        """文字列から秘密値を伏せる（エラー要約の保存用）。既定では何もしない。"""
        return text

    def fatal_reason(self, resp: httpx.Response) -> str | None:
        """再試行せずに失敗させる応答なら理由を返す。"""
        return None

    def retry_wait(self, resp: httpx.Response | None, attempt: int) -> float:
        """attempt 回目（0 始まり）の再試行までの秒数。resp は接続エラーなら None。"""
        return RETRY_WAITS[attempt]

    def _get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ok_status: Collection[int] = (200,),
    ) -> httpx.Response:
        return self._request("GET", url, params=params, headers=headers, ok_status=ok_status)

    def _post(
        self,
        url: str,
        *,
        json: Any,
        headers: dict[str, str] | None = None,
        ok_status: Collection[int] = (200,),
    ) -> httpx.Response:
        return self._request("POST", url, json=json, headers=headers, ok_status=ok_status)

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        ok_status: Collection[int] = (200,),
    ) -> httpx.Response:
        attempt = 0
        while True:
            self.request_count += 1
            # 本文はログに出さない（POST の本文は送る内容そのもの）
            log.info("%s %s %s %s", self.label, method, url, params or "")
            resp: httpx.Response | None = None
            try:
                resp = self._http.request(
                    method, url, params=params, json=json, headers=headers, timeout=TIMEOUT_SECONDS
                )
            except (httpx.TransportError, httpx.TimeoutException) as e:
                reason = f"{type(e).__name__}: {e}"
            else:
                if resp.status_code in ok_status:
                    return resp
                fatal = self.fatal_reason(resp)
                if fatal is not None:
                    raise (self.fatal_error_cls or self.error_cls)(self.redact(fatal))
                status = resp.status_code
                reason = f"HTTP {status}"
                if not (status == 429 or status >= 500):
                    raise self.error_cls(self.redact(reason))
            if attempt >= len(RETRY_WAITS):
                raise self.error_cls(self.redact(f"{reason} (after {attempt} retries)"))
            wait = self.retry_wait(resp, attempt)
            attempt += 1
            log.warning(
                "%s request failed (%s); retry %d in %.0fs",
                self.label,
                self.redact(reason),
                attempt,
                wait,
            )
            self._sleep(wait)
