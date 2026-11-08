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
    """GET を 429 / 5xx / 接続エラーで再試行するクライアントの土台。

    サブクラスは error_cls / label を決め、必要なら redact() と fatal_reason() を上書きする。
    """

    error_cls: type[SourceError] = SourceError
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

    def _get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ok_status: Collection[int] = (200,),
    ) -> httpx.Response:
        attempt = 0
        while True:
            self.request_count += 1
            log.info("%s GET %s %s", self.label, url, params or "")
            try:
                resp = self._http.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)
            except (httpx.TransportError, httpx.TimeoutException) as e:
                reason = f"{type(e).__name__}: {e}"
            else:
                if resp.status_code in ok_status:
                    return resp
                fatal = self.fatal_reason(resp)
                if fatal is not None:
                    raise self.error_cls(self.redact(fatal))
                status = resp.status_code
                reason = f"HTTP {status}"
                if not (status == 429 or status >= 500):
                    raise self.error_cls(self.redact(reason))
            if attempt >= len(RETRY_WAITS):
                raise self.error_cls(self.redact(f"{reason} (after {attempt} retries)"))
            wait = RETRY_WAITS[attempt]
            attempt += 1
            log.warning(
                "%s request failed (%s); retry %d in %.0fs",
                self.label,
                self.redact(reason),
                attempt,
                wait,
            )
            self._sleep(wait)
