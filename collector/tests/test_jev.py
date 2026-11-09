import json

import httpx
import pytest
import respx

from vuln_signal.sources.http import USER_AGENT
from vuln_signal.sources.jev import (
    BASE_URL,
    JevClient,
    JevError,
    JevFatalError,
    Question,
    parse_response,
)

KEY = "test-key-not-real-0000"
QUESTIONS = {
    "kind": Question("What kind", {"library": "lib", "other": "other"}),
    "stack": Question("Which", {"npm_package": "npm", "none": "none"}),
}


def _answer(kind="library", stack="npm_package", conf=0.8, model="jev-1.14.0", tokens=42):
    return {
        "model": model,
        "answers": {
            "kind": {
                "type": "choice",
                "choice": kind,
                "confidence": 0.9,
                "probabilities": {"library": 0.9, "other": 0.1},
            },
            "stack": {
                "type": "choice",
                "choice": stack,
                "confidence": conf,
                "probabilities": {"npm_package": conf, "none": round(1 - conf, 3)},
            },
        },
        "usage": {"input_tokens": tokens, "output_tokens": 2},
    }


def _client(fake_sleep, key=KEY):
    return JevClient(key, sleep=fake_sleep)


@respx.mock
def test_ask_sends_body_and_parses(fake_sleep):
    route = respx.post(BASE_URL).mock(return_value=httpx.Response(200, json=_answer()))
    res = _client(fake_sleep).ask("jev-latest", "some text", QUESTIONS)

    req = route.calls[0].request
    assert req.headers["Authorization"] == f"Bearer {KEY}"
    assert req.headers["Content-Type"] == "application/json"
    assert req.headers["User-Agent"] == USER_AGENT
    assert json.loads(req.content) == {
        "model": "jev-latest",
        "state": "some text",
        "questions": {
            "kind": {
                "type": "choice",
                "instructions": "What kind",
                "criteria": {"library": "lib", "other": "other"},
            },
            "stack": {
                "type": "choice",
                "instructions": "Which",
                "criteria": {"npm_package": "npm", "none": "none"},
            },
        },
    }
    assert res.model == "jev-1.14.0"
    assert res.input_tokens == 42
    assert res.answers["stack"].choice == "npm_package"
    assert res.answers["stack"].confidence == 0.8
    assert res.answers["kind"].probabilities == {"library": 0.9, "other": 0.1}


@respx.mock
def test_429_waits_retry_after_then_succeeds(fake_sleep):
    route = respx.post(BASE_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(429),
            httpx.Response(529),
            httpx.Response(200, json=_answer()),
        ]
    )
    client = _client(fake_sleep)
    client.ask("m", "s", QUESTIONS)
    assert route.call_count == 4
    # Retry-After があればその秒数、無ければバックオフ
    assert fake_sleep.calls == [7.0, 30.0, 60.0]
    assert client.request_count == 4


@respx.mock
def test_retry_gives_up(fake_sleep):
    respx.post(BASE_URL).mock(return_value=httpx.Response(503))
    with pytest.raises(JevError, match="HTTP 503 .after 3 retries") as exc:
        _client(fake_sleep).ask("m", "s", QUESTIONS)
    assert not isinstance(exc.value, JevFatalError)


@pytest.mark.parametrize("status", [400, 401, 422])
@respx.mock
def test_config_errors_are_fatal_without_retry(fake_sleep, status):
    route = respx.post(BASE_URL).mock(return_value=httpx.Response(status))
    with pytest.raises(JevFatalError, match=f"HTTP {status}"):
        _client(fake_sleep).ask("m", "s", QUESTIONS)
    assert route.call_count == 1
    assert fake_sleep.calls == []


@respx.mock
def test_413_fails_one_request_only(fake_sleep):
    respx.post(BASE_URL).mock(return_value=httpx.Response(413))
    with pytest.raises(JevError) as exc:
        _client(fake_sleep).ask("m", "s", QUESTIONS)
    assert not isinstance(exc.value, JevFatalError)
    assert fake_sleep.calls == []


@respx.mock
def test_key_not_in_errors_or_repr(fake_sleep, caplog):
    respx.post(BASE_URL).mock(side_effect=httpx.ConnectError("refused " + KEY))
    client = _client(fake_sleep)
    with caplog.at_level("INFO"), pytest.raises(JevError) as exc:
        client.ask("m", "secret description", QUESTIONS)
    assert KEY not in str(exc.value)
    assert "***" in str(exc.value)
    assert KEY not in caplog.text
    # 本文（説明文）もログに出さない
    assert "secret description" not in caplog.text
    assert KEY not in repr(client)


def test_parse_response_rejects_unknown_choice_and_missing():
    with pytest.raises(JevError, match="unknown choice"):
        parse_response(_answer(stack="nodejs_core"), QUESTIONS, "m")
    data = _answer()
    del data["answers"]["kind"]
    with pytest.raises(JevError, match="kind is missing"):
        parse_response(data, QUESTIONS, "m")
    with pytest.raises(JevError, match="no answers"):
        parse_response({"model": "x"}, QUESTIONS, "m")


def test_parse_response_defaults():
    data = _answer()
    del data["model"]
    del data["usage"]
    res = parse_response(data, QUESTIONS, "jev-latest")
    assert res.model == "jev-latest"
    assert res.input_tokens is None
