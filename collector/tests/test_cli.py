import httpx
import respx
from conftest import load_fixture, make_cve
from typer.testing import CliRunner

from vuln_signal import cli
from vuln_signal.sources import epss, ghsa, kev
from vuln_signal.sources.nvd import BASE_URL
from vuln_signal.store import Store

NPM_PKG = "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:node.js:*:*"


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_SIGNAL_ENV_FILE", str(tmp_path / "nope"))
    monkeypatch.setenv("VULN_SIGNAL_DATA_DIR", str(tmp_path / "data"))
    # 明示したファイルは存在が必要なので空の rules.toml を置く（既定値になる）
    (tmp_path / "rules.toml").write_text("", encoding="utf-8")
    monkeypatch.setenv("VULN_SIGNAL_RULES_FILE", str(tmp_path / "rules.toml"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


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


def _no_sleep(monkeypatch):
    monkeypatch.setattr("vuln_signal.sources.http.time.sleep", lambda s: None)


@respx.mock
def test_sync_kev_bootstrap_and_dry_run(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    respx.get(kev.FEED_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("kev_catalog.json"))
    )
    res = CliRunner().invoke(cli.app, ["sync", "kev", "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "kev catalogVersion 2099.01.01 (dry-run, not written)" in res.output
    assert "bootstrap: true" in res.output
    assert "fetched: 3" in res.output
    s = Store.open(tmp_path / "data")
    try:
        assert s.count_rows("kev") == 0
    finally:
        s.close()

    res = CliRunner().invoke(cli.app, ["sync", "kev"])
    assert res.exit_code == 0, res.output
    assert "requests: 1" in res.output


@respx.mock
def test_sync_epss_skip_and_force(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    s = Store.open(tmp_path / "data")
    s.mark_sync_ok("epss", "2000-01-01T00:00:00Z", cursor="9999-12-31")
    s.upsert_kev(kev.KevRecord("CVE-2020-0001", None, None, None, None, None, None), "x")
    s.close()
    body = {
        "status": "OK",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {"cve": "CVE-2020-0001", "epss": "0.5", "percentile": "0.9", "date": "2099-01-01"}
        ],
    }
    route = respx.get(epss.BASE_URL).mock(return_value=httpx.Response(200, json=body))
    res = CliRunner().invoke(cli.app, ["sync", "epss"])
    assert res.exit_code == 0, res.output
    assert "epss skipped: already have 9999-12-31" in res.output
    assert route.call_count == 0

    res = CliRunner().invoke(cli.app, ["sync", "epss", "--force", "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "epss model_date 2099-01-01 (dry-run, not written)" in res.output
    assert "targets: 1" in res.output and "fetched: 1" in res.output


@respx.mock
def test_sync_ghsa_with_since(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    route = respx.get(ghsa.BASE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("ghsa_page1_of_2.json"))
    )
    res = CliRunner().invoke(
        cli.app, ["sync", "ghsa", "--since", "2026-11-06T00:00:00Z", "--dry-run"]
    )
    assert res.exit_code == 0, res.output
    assert res.output.startswith("ghsa 2026-11-06T00:00:00Z .. ")
    assert "event ghsa_first_seen: 2" in res.output
    assert route.calls[0].request.url.params["modified"].startswith("2026-11-06T00:00:00Z..")


@respx.mock
def test_sync_ghsa_failure_hides_token(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    token = "test-token-not-real-1111"
    monkeypatch.setenv("GITHUB_TOKEN", token)
    _no_sleep(monkeypatch)
    respx.get(ghsa.BASE_URL).mock(side_effect=httpx.ConnectError("refused " + token))
    res = CliRunner().invoke(cli.app, ["sync", "ghsa"])
    assert res.exit_code == 1
    assert "sync ghsa failed" in res.output
    assert token not in res.output


@respx.mock
def test_sync_all_continues_after_failure(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _no_sleep(monkeypatch)
    nvd = respx.get(BASE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("nvd_two_cves.json"))
    )
    kev_route = respx.get(kev.FEED_URL).mock(return_value=httpx.Response(500))
    ghsa_route = respx.get(ghsa.BASE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("ghsa_page2_of_2.json"))
    )
    epss_route = respx.get(epss.BASE_URL).mock(
        return_value=httpx.Response(
            200, json={"status": "OK", "total": 0, "offset": 0, "limit": 100, "data": []}
        )
    )
    res = CliRunner().invoke(cli.app, ["sync", "all"])
    assert res.exit_code == 1
    assert nvd.call_count == 1
    assert kev_route.call_count == 4
    assert ghsa_route.call_count == 1
    # NVD の 2 件（published 2099 年）と GHSA の CVE が対象
    assert epss_route.call_count == 1
    out = res.output
    assert (
        out.index("nvd ")
        < out.index("sync kev failed")
        < out.index("ghsa ")
        < out.index("epss model_date")
        < out.index("classify diff")
    )
    s = Store.open(tmp_path / "data")
    try:
        assert s.get_sync_state("kev")["last_error"].startswith("KevError: HTTP 500")
        assert s.get_sync_state("nvd")["last_error"] is None
        assert s.get_sync_state("ghsa")["last_error"] is None
        epss_state = s.get_sync_state("epss")
        assert epss_state["last_error"] is None
        # 応答 0 件なので cursor は None のまま（時刻を入れない）
        assert epss_state["cursor"] is None
        # kev が失敗しても classify は走る
        assert s.get_sync_state("classify")["last_error"] is None
    finally:
        s.close()


@respx.mock
def test_sync_all_ok_dry_run(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    respx.get(BASE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("nvd_two_cves.json"))
    )
    respx.get(kev.FEED_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("kev_catalog.json"))
    )
    respx.get(ghsa.BASE_URL).mock(return_value=httpx.Response(200, json=[]))
    res = CliRunner().invoke(cli.app, ["sync", "all", "--dry-run"])
    assert res.exit_code == 0, res.output
    assert res.output.count("(dry-run, not written)") == 5
    assert "classify diff rules_version" in res.output
    s = Store.open(tmp_path / "data")
    try:
        assert s.list_sync_state() == []
    finally:
        s.close()


def _mock_all_ok():
    routes = {
        "nvd": respx.get(BASE_URL).mock(
            return_value=httpx.Response(200, json=load_fixture("nvd_two_cves.json"))
        ),
        "kev": respx.get(kev.FEED_URL).mock(
            return_value=httpx.Response(200, json=load_fixture("kev_catalog.json"))
        ),
        "ghsa": respx.get(ghsa.BASE_URL).mock(return_value=httpx.Response(200, json=[])),
        "epss": respx.get(epss.BASE_URL).mock(
            return_value=httpx.Response(
                200, json={"status": "OK", "total": 0, "offset": 0, "limit": 100, "data": []}
            )
        ),
    }
    return routes


@respx.mock
def test_sync_all_continues_when_store_open_fails(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    routes = _mock_all_ok()
    orig = Store.open
    calls = {"n": 0}

    def flaky_open(data_dir):
        calls["n"] += 1
        # 2 番目（kev）だけ開けない
        if calls["n"] == 2:
            raise OSError("database is locked")
        return orig(data_dir)

    monkeypatch.setattr(cli.Store, "open", flaky_open)
    res = CliRunner().invoke(cli.app, ["sync", "all"])
    assert res.exit_code == 1
    assert "sync kev failed: OSError: database is locked" in res.output
    assert routes["kev"].call_count == 0
    assert routes["nvd"].call_count == routes["ghsa"].call_count == 1
    assert "ghsa " in res.output and "epss model_date" in res.output


@respx.mock
def test_sync_all_continues_when_client_creation_fails(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    token = "test-token-not-real-2222"
    monkeypatch.setenv("GITHUB_TOKEN", token)
    routes = _mock_all_ok()

    def broken_client(t):
        raise ValueError("bad token " + t)

    monkeypatch.setattr(cli, "GhsaClient", broken_client)
    res = CliRunner().invoke(cli.app, ["sync", "all"])
    assert res.exit_code == 1
    assert "sync ghsa failed: ValueError: bad token ***" in res.output
    assert token not in res.output
    assert routes["nvd"].call_count == routes["kev"].call_count == 1
    assert "epss model_date" in res.output


def _seed_classify(tmp_path):
    s = Store.open(tmp_path / "data")
    try:
        s.upsert_cve(make_cve("CVE-2099-0001", cvss_v31_score=9.8, cpe_criteria=[NPM_PKG]), "x")
        s.add_event("CVE-2099-0001", "x", "first_seen", None, None, "nvd")
        s.upsert_cve(make_cve("CVE-2099-0002", cvss_v31_score=9.8), "x")
        s.add_event("CVE-2099-0002", "x", "first_seen", None, None, "nvd")
    finally:
        s.close()


def test_classify_dry_run_then_write(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _seed_classify(tmp_path)
    res = CliRunner().invoke(cli.app, ["classify", "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "(dry-run, not written)" in res.output
    assert "targets: 2" in res.output
    assert "tier P1: 1" in res.output and "tier excluded: 1" in res.output
    assert "tier_changed new: 1" in res.output
    s = Store.open(tmp_path / "data")
    try:
        assert s.count_rows("tier") == 0
    finally:
        s.close()

    res = CliRunner().invoke(cli.app, ["classify"])
    assert res.exit_code == 0, res.output
    assert res.output.startswith("classify diff rules_version ")
    res = CliRunner().invoke(cli.app, ["classify"])
    assert "targets: 0" in res.output
    res = CliRunner().invoke(cli.app, ["classify", "--all"])
    assert res.output.startswith("classify all ")
    assert "targets: 2" in res.output and "tier_changed new: 0" in res.output


def test_classify_bad_rules_file_exit_1(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rules = tmp_path / "rules.toml"
    rules.write_text("[thresholds]\nunknown = 1\n", encoding="utf-8")
    monkeypatch.setenv("VULN_SIGNAL_RULES_FILE", str(rules))
    res = CliRunner().invoke(cli.app, ["classify"])
    assert res.exit_code == 1
    assert "classify failed: RulesError: unknown key in thresholds: unknown" in res.output
    s = Store.open(tmp_path / "data")
    try:
        state = s.get_sync_state("classify")
        assert state["last_error"] == "RulesError: unknown key in thresholds: unknown"
        assert state["last_ok_at"] is None
    finally:
        s.close()

    # dry-run では書かない
    rules.write_text("[thresholds]\nother = 1\n", encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["classify", "--dry-run"])
    assert res.exit_code == 1
    s = Store.open(tmp_path / "data")
    try:
        assert "unknown" in s.get_sync_state("classify")["last_error"]
        assert "other" not in s.get_sync_state("classify")["last_error"]
    finally:
        s.close()


def test_classify_explicit_rules_file_missing_exit_1(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setenv("VULN_SIGNAL_RULES_FILE", str(tmp_path / "missing.toml"))
    res = CliRunner().invoke(cli.app, ["classify"])
    assert res.exit_code == 1
    assert "classify failed: RulesError: rules file not found" in res.output
