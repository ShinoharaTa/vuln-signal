import copy
from datetime import UTC, datetime

from conftest import load_fixture
from typer.testing import CliRunner

from vuln_signal.report import build_report, format_report
from vuln_signal.sources.nvd import LINUX_KERNEL_CNA, parse_cve

NOW = datetime(2099, 1, 10, 0, 0, tzinfo=UTC)
IN_WINDOW = "2099-01-09T12:00:00Z"
OLD = "2099-01-05T00:00:00Z"


def _add(store, cve_id, severity, source_identifier, observed_at, published=None):
    base = load_fixture("nvd_two_cves.json")["vulnerabilities"][1]["cve"]
    cve = copy.deepcopy(base)
    cve["id"] = cve_id
    cve["sourceIdentifier"] = source_identifier
    cve["published"] = published or observed_at.removesuffix("Z")
    if severity:
        cve["metrics"] = {
            "cvssMetricV31": [
                {"type": "Primary", "cvssData": {"baseScore": 5.0, "baseSeverity": severity}}
            ]
        }
    rec = parse_cve(cve)
    store.upsert_cve(rec, observed_at)
    store.add_event(cve_id, observed_at, "first_seen", None, rec.published, "nvd")


def _seed(store):
    _add(store, "CVE-2099-1001", "CRITICAL", "cna@example.invalid", IN_WINDOW)
    _add(store, "CVE-2099-1002", "HIGH", LINUX_KERNEL_CNA, IN_WINDOW)
    _add(store, "CVE-2099-1003", "HIGH", "cna@example.invalid", IN_WINDOW)
    _add(store, "CVE-2099-1004", None, LINUX_KERNEL_CNA, IN_WINDOW)
    # 昔公開されて最近更新された CVE: 初出には数えるが新規公開には数えない
    _add(store, "CVE-2019-0001", "CRITICAL", LINUX_KERNEL_CNA, IN_WINDOW, "2019-05-01T00:00:00")
    # 窓の外（集計に入らない）
    _add(store, "CVE-2099-1005", "LOW", LINUX_KERNEL_CNA, OLD)
    store.add_event("CVE-2099-1005", IN_WINDOW, "cvss_v31_changed", "5.0", "9.0", "nvd")
    store.add_event("CVE-2099-1005", IN_WINDOW, "status_changed", "Received", "Rejected", "nvd")
    store.add_event("CVE-2099-1001", OLD, "status_changed", "Received", "Analyzed", "nvd")
    store.mark_sync_ok("nvd", "2099-01-09T23:30:00Z")


def test_report_numbers(store):
    _seed(store)
    rep = build_report(store, NOW, days=1)
    assert rep.since == "2099-01-09T00:00:00Z"
    assert rep.until == "2099-01-10T00:00:00Z"
    assert rep.new_count == 4
    assert rep.first_seen_count == 5
    assert rep.events == {"cvss_v31_changed": 1, "first_seen": 5, "status_changed": 1}
    assert rep.new_by_severity == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "(none)": 1}
    assert rep.new_kernel_cna == 2
    assert rep.sync_state == [("nvd", "2099-01-09T23:30:00Z", None)]

    wide = build_report(store, NOW, days=7)
    assert wide.new_count == 5
    assert wide.first_seen_count == 6
    assert wide.new_kernel_cna == 3
    assert wide.events["status_changed"] == 2


def test_format_report_is_plain_table(store):
    _seed(store)
    text = format_report(build_report(store, NOW, days=1))
    lines = text.splitlines()
    assert lines[0] == "period: 2099-01-09T00:00:00Z .. 2099-01-10T00:00:00Z"
    assert any(line.startswith("new CVEs") and line.split()[-1] == "4" for line in lines)
    assert any(line.split() == ["CRITICAL", "1"] for line in lines)
    assert any(line.split() == ["nvd", "2099-01-09T23:30:00Z"] for line in lines)


def test_report_empty_db(store):
    text = format_report(build_report(store, NOW, days=1))
    assert "(none)" in text


def test_cli_db_path_and_report(tmp_path, monkeypatch):
    from vuln_signal.cli import app

    monkeypatch.setenv("VULN_SIGNAL_ENV_FILE", str(tmp_path / "nope"))
    monkeypatch.setenv("VULN_SIGNAL_DATA_DIR", str(tmp_path / "data"))
    runner = CliRunner()
    res = runner.invoke(app, ["db", "path"])
    assert res.exit_code == 0
    assert res.output.strip() == str(tmp_path / "data" / "work.sqlite3")
    res = runner.invoke(app, ["report", "--days", "1"])
    assert res.exit_code == 0, res.output
    assert "new CVEs" in res.output
