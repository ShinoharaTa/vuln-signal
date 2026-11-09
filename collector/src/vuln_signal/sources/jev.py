"""Jev（TypeSafe）の systemone API。固定選択肢の質問に答えさせる。

https://docs.typesafe.ai/
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from vuln_signal.sources.http import RETRY_WAITS, RetryingClient, SourceError

BASE_URL = "https://api.typesafe.ai/v1/systemone"
# 設定ミス（キー・リクエストの形）なので続けても無駄な応答
FATAL_STATUS = {400, 401, 422}


class JevError(SourceError):
    """1 件の問い合わせに失敗した（再試行切れ・5xx・応答の形が違う）。"""


class JevFatalError(JevError):
    """続けても失敗する（401 / 400 / 422）。"""


@dataclass(frozen=True)
class Question:
    instructions: str
    # 選択肢 -> 説明
    criteria: Mapping[str, str]


@dataclass(frozen=True)
class ChoiceAnswer:
    choice: str
    confidence: float
    probabilities: dict[str, float]


@dataclass(frozen=True)
class JevResponse:
    model: str
    answers: dict[str, ChoiceAnswer]
    input_tokens: int | None


def build_body(model: str, state: str, questions: Mapping[str, Question]) -> dict[str, Any]:
    return {
        "model": model,
        "state": state,
        "questions": {
            name: {"type": "choice", "instructions": q.instructions, "criteria": dict(q.criteria)}
            for name, q in questions.items()
        },
    }


def parse_response(data: Any, questions: Mapping[str, Question], default_model: str) -> JevResponse:
    """応答を JevResponse にする。質問が欠けている・選択肢に無い答えは JevError。"""
    if not isinstance(data, dict):
        raise JevError("response is not an object")
    raw_answers = data.get("answers")
    if not isinstance(raw_answers, dict):
        raise JevError("response has no answers")
    answers: dict[str, ChoiceAnswer] = {}
    for name, q in questions.items():
        ans = raw_answers.get(name)
        if not isinstance(ans, dict):
            raise JevError(f"answer {name} is missing")
        choice = ans.get("choice")
        if choice not in q.criteria:
            raise JevError(f"answer {name} has unknown choice: {choice!r}")
        try:
            confidence = float(ans["confidence"])
            probs = {str(k): float(v) for k, v in (ans.get("probabilities") or {}).items()}
        except (KeyError, TypeError, ValueError) as e:
            raise JevError(f"answer {name} is malformed: {type(e).__name__}") from e
        answers[name] = ChoiceAnswer(choice, confidence, probs)
    usage = data.get("usage") or {}
    tokens = usage.get("input_tokens") if isinstance(usage, dict) else None
    return JevResponse(
        model=str(data.get("model") or default_model),
        answers=answers,
        input_tokens=int(tokens) if isinstance(tokens, int | float) else None,
    )


def _retry_after(resp: httpx.Response | None) -> float | None:
    if resp is None or resp.status_code != 429:
        return None
    value = resp.headers.get("retry-after")
    try:
        seconds = float(value) if value is not None else None
    except ValueError:
        # HTTP-date 形式は扱わずバックオフにする
        return None
    return seconds if seconds is not None and seconds >= 0 else None


class JevClient(RetryingClient):
    error_cls = JevError
    fatal_error_cls = JevFatalError
    label = "Jev"

    def __init__(
        self,
        api_key: str,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        base_url: str = BASE_URL,
    ) -> None:
        self._api_key = api_key
        headers = {"Authorization": f"Bearer {api_key}"}
        super().__init__(http=http, sleep=sleep, headers=headers)
        self._base_url = base_url

    def __repr__(self) -> str:
        return f"JevClient(api_key={'set' if self._api_key else 'unset'})"

    def redact(self, text: str) -> str:
        """文字列から API キーを伏せる（エラー要約の保存用）。"""
        return text.replace(self._api_key, "***") if self._api_key else text

    def fatal_reason(self, resp: httpx.Response) -> str | None:
        if resp.status_code in FATAL_STATUS:
            return f"HTTP {resp.status_code}"
        return None

    def retry_wait(self, resp: httpx.Response | None, attempt: int) -> float:
        # 429 は Retry-After 秒（無ければバックオフ）
        seconds = _retry_after(resp)
        return seconds if seconds is not None else RETRY_WAITS[attempt]

    def ask(self, model: str, state: str, questions: Mapping[str, Question]) -> JevResponse:
        """1 つの state に複数の質問をまとめて 1 リクエストで聞く。"""
        resp = self._post(self._base_url, json=build_body(model, state, questions))
        try:
            data = resp.json()
        except ValueError as e:
            raise JevError(f"response is not JSON: {type(e).__name__}") from e
        return parse_response(data, questions, model)
