import json
from pathlib import Path

import pytest

from vuln_signal.sources.ghsa import GhsaRecord
from vuln_signal.sources.nvd import CveRecord
from vuln_signal.store import Store

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def make_cve(cve_id: str, **kw) -> CveRecord:
    """テスト用の CveRecord。指定しない項目は空。"""
    base = dict(
        id=cve_id,
        published=None,
        last_modified=None,
        vuln_status="Analyzed",
        source_identifier="cna@example.invalid",
        description_en=None,
        cvss_v31_score=None,
        cvss_v31_vector=None,
        cvss_v31_severity=None,
        cvss_v40_score=None,
        cvss_v40_vector=None,
        cvss_v40_severity=None,
        cwe_ids=[],
        cpe_criteria=[],
        raw={},
    )
    base.update(kw)
    return CveRecord(**base)


def make_ghsa(ghsa_id, cve_id, severity, *, v3=None, v4=None, withdrawn=None) -> GhsaRecord:
    """テスト用の GhsaRecord。"""
    return GhsaRecord(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        severity=severity,
        summary=None,
        published_at=None,
        updated_at=None,
        withdrawn_at=withdrawn,
        cvss_v3_score=v3,
        cvss_v3_vector=None,
        cvss_v4_score=v4,
        cvss_v4_vector=None,
        packages=[],
        html_url=None,
        raw={},
    )


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
