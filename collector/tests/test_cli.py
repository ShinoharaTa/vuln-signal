import httpx
import respx
from conftest import load_fixture
from typer.testing import CliRunner

from vuln_signal import cli
from vuln_signal.sources.nvd import BASE_URL


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_SIGNAL_ENV_FILE", str(tmp_path / "nope"))
    monkeypatch.setenv("VULN_SIGNAL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)


@respx.mock
def test_sync_nvd_dry_run_ok(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    respx.get(BASE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("nvd_two_cves.json"))
    )
    res = CliRunner().invoke(
        cli.app, ["sync", "nvd", "--since", "2026-11-06T00:00:00Z", "--dry-run"]
    )
    assert res.exit_code == 0, res.output
    assert "fetched: 2" in res.output
    assert "event first_seen: 2" in res.output
    # フィクスチャの published は 2099 年で窓の外
    assert "new: 0" in res.output


@respx.mock
def test_sync_nvd_failure_exit_1(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    respx.get(BASE_URL).mock(return_value=httpx.Response(404))
    res = CliRunner().invoke(cli.app, ["sync", "nvd"])
    assert res.exit_code == 1
    assert "404" in res.output


def test_sync_nvd_bad_since(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    res = CliRunner().invoke(cli.app, ["sync", "nvd", "--since", "yesterday"])
    assert res.exit_code == 2
