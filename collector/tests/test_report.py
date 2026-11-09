import copy
from datetime import UTC, datetime

from conftest import load_fixture
from typer.testing import CliRunner

from vuln_signal.report import build_report, format_report
from vuln_signal.sources.kev import KevRecord
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
    # 新しいソースのイベントもそのまま集計に出る
    store.add_event("CVE-2098-0001", IN_WINDOW, "kev_added", None, "2099-01-09", "kev")
    store.add_event("GHSA-xxxx-xxxx-xxxx", IN_WINDOW, "ghsa_first_seen", None, "g", "ghsa")
    for cve_id in ("CVE-2098-0001", "CVE-2098-0002"):
        store.upsert_kev(KevRecord(cve_id, "2099-01-09", None, None, None, None, "Unknown"), "x")
    store.conn.execute("INSERT INTO ghsa (ghsa_id) VALUES ('GHSA-xxxx-xxxx-xxxx')")
    store.mark_sync_ok("kev", "2099-01-09T23:40:00Z", cursor="2099.01.09")


def test_report_numbers(store):
    _seed(store)
    rep = build_report(store, NOW, days=1)
    assert rep.since == "2099-01-09T00:00:00Z"
    assert rep.until == "2099-01-10T00:00:00Z"
    assert rep.new_count == 4
    assert rep.first_seen_count == 5
    assert rep.events == {
        "cvss_v31_changed": 1,
        "first_seen": 5,
        "ghsa_first_seen": 1,
        "kev_added": 1,
        "status_changed": 1,
    }
    assert rep.new_by_severity == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "(none)": 1}
    assert rep.new_kernel_cna == 2
    assert rep.sync_state == [
        ("kev", "2099-01-09T23:40:00Z", None),
        ("nvd", "2099-01-09T23:30:00Z", None),
    ]
    assert (rep.kev_total, rep.epss_rows, rep.ghsa_rows) == (2, 0, 1)

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
    assert any(line.split() == ["kev", "2099-01-09T23:40:00Z"] for line in lines)
    assert "kev total: 2" in lines
    assert "epss rows: 0" in lines
    assert "ghsa rows: 1" in lines


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


def _tier(store, subject, tier, reasons=("in_stack",)):
    store.upsert_tier(subject, tier, ["npm"], list(reasons), {}, "v", IN_WINDOW)


def test_report_tier_rows(store):
    _seed(store)
    _tier(store, "CVE-2099-1001", "P0", ["kev"])
    _tier(store, "CVE-2099-1003", "P1", ["cvss"])
    _tier(store, "CVE-2099-1002", "P3", ["cvss", "kernel_thinned"])
    _tier(store, "GHSA-xxxx-xxxx-xxxx", "P1", ["ghsa_severity"])
    # 窓の外に初出したもの: current だけに数える
    _tier(store, "CVE-2099-1005", "P0", ["kev"])
    _tier(store, "CVE-2099-1004", "P2")
    ev = [
        ("CVE-2099-1001", None, "P0"),  # 新規で P0: 上がった
        ("CVE-2099-1003", None, "P2"),  # 新規で P2: 数えない
        ("CVE-2099-1003", "P2", "P1"),  # 上がった
        ("CVE-2099-1004", "P1", "P2"),  # 下がった
        ("CVE-2099-1004", "P1", None),  # 対象外へ
    ]
    for subject, before, after in ev:
        store.add_event(subject, IN_WINDOW, "tier_changed", before, after, "rules")
    store.add_event("CVE-2099-1005", OLD, "tier_changed", "P1", "P0", "rules")

    rep = build_report(store, NOW, days=2)
    assert rep.tier_current == {"P0": 2, "P1": 2, "P2": 1, "P3": 1}
    assert rep.tier_new == {"P0": 1, "P1": 2, "P2": 1, "P3": 1}
    assert rep.p0_p1_new_per_day == 1.5
    assert rep.tier_upgrades == 2
    assert rep.kernel_thinned == 1

    lines = format_report(rep).splitlines()
    assert ["P0", "2", "1"] in [line.split() for line in lines]
    assert "P0+P1 new per day: 1.5" in lines
    assert "tier upgrades in window: 2" in lines
    assert "kernel thinned (P3) in window: 1" in lines


def test_report_tier_rows_empty(store):
    lines = format_report(build_report(store, NOW, days=3)).splitlines()
    assert ["P1", "0", "0"] in [line.split() for line in lines]
    assert "P0+P1 new per day: 0.0" in lines
