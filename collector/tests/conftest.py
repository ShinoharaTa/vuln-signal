import json
from pathlib import Path

import pytest

from vuln_signal.store import Store

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def store(tmp_path):
    s = Store.open(tmp_path / "data")
    yield s
    s.close()


class FakeSleep:
    """sleep の代わり。待った秒数を記録するだけ。"""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def fake_sleep():
    return FakeSleep()
