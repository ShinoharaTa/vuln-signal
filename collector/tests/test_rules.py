import pytest
from conftest import make_cve, make_ghsa

from vuln_signal.config import ExtraStack, Rules, parse_rules
from vuln_signal.rules import (
    Inputs,
    collect_inputs,
    decide_tier,
    detect_stacks,
    evaluate,
    representative_cvss,
)
from vuln_signal.sources.epss import EpssRecord
from vuln_signal.sources.kev import KevRecord
from vuln_signal.sources.nvd import LINUX_KERNEL_CNA

RULES = Rules()
NODE_CORE = "cpe:2.3:a:nodejs:node.js:20.0.0:*:*:*:*:*:*:*"
NPM_PKG = "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:node.js:*:*"
KERNEL = "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"
NGINX = "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*"
OTHER = "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*"


def _npm(**kw) -> Inputs:
    """npm スタックに当たる CVE（GHSA あり）。"""
    return Inputs("CVE-2099-0001", ghsa_count=1, **kw)


def _kernel(**kw) -> Inputs:
    return Inputs("CVE-2099-0002", source_identifier=LINUX_KERNEL_CNA, **kw)


def _tier(inp: Inputs, rules: Rules = RULES) -> tuple[str, list[str]] | None:
    d = evaluate(inp, rules)
    return None if d is None else (d.tier, list(d.reasons))


# --- スタック ---


def test_stack_nodejs_core_not_npm():
    inp = Inputs("CVE-1", cpe_criteria=(NODE_CORE,))
    assert detect_stacks(inp, RULES) == ("nodejs_core",)


def test_stack_npm_by_ghsa_or_target_sw():
    assert detect_stacks(Inputs("CVE-1", ghsa_count=1), RULES) == ("npm",)
    assert detect_stacks(Inputs("CVE-1", cpe_criteria=(NPM_PKG,)), RULES) == ("npm",)
    # エスケープされた ":" は区切りにしない
    escaped = r"cpe:2.3:a:acme:wid\:get:1.0.0:*:*:*:*:node.js:*:*"
    assert detect_stacks(Inputs("CVE-1", cpe_criteria=(escaped,)), RULES) == ("npm",)


def test_stack_linux_kernel_by_cna_or_cpe():
    assert detect_stacks(_kernel(), RULES) == ("linux_kernel",)
    assert detect_stacks(Inputs("CVE-1", cpe_criteria=(KERNEL,)), RULES) == ("linux_kernel",)


def test_stack_extra_and_multiple():
    rules = Rules(extra_stacks=(ExtraStack("nginx", "cpe:2.3:a:f5:nginx:"),))
    inp = Inputs("CVE-1", cpe_criteria=(NGINX, KERNEL), ghsa_count=1)
    assert detect_stacks(inp, rules) == ("extra:nginx", "linux_kernel", "npm")
    assert detect_stacks(Inputs("CVE-1", cpe_criteria=(NGINX,)), RULES) == ()


def test_unrelated_is_out_of_scope():
    inp = Inputs("CVE-1", cpe_criteria=(OTHER,), cvss=10.0, kev=True)
    assert detect_stacks(inp, RULES) == ()
    assert evaluate(inp, RULES) is None


# --- tier ---


def test_p0_kev():
    assert _tier(_npm(kev=True)) == ("P0", ["kev"])


@pytest.mark.parametrize(
    ("cvss", "epss", "tier"),
    [(9.0, 0.10, "P0"), (8.99, 0.10, "P1"), (9.0, 0.09, "P1")],
)
def test_p0_cvss_epss_boundary(cvss, epss, tier):
    assert _tier(_npm(cvss=cvss, epss_score=epss))[0] == tier


def test_p0_reasons_all_listed():
    got = _tier(Inputs("CVE-1", cpe_criteria=(NODE_CORE,), kev=True, cvss=9.8, epss_score=0.5))
    assert got == ("P0", ["kev", "cvss_epss", "nodejs_core_high"])


@pytest.mark.parametrize(("cvss", "tier"), [(7.0, "P0"), (6.99, "P2")])
def test_p0_nodejs_core_high_boundary(cvss, tier):
    assert _tier(Inputs("CVE-1", cpe_criteria=(NODE_CORE,), cvss=cvss))[0] == tier


def test_p0_nodejs_core_without_cvss_uses_ghsa_severity():
    inp = Inputs("CVE-1", cpe_criteria=(NODE_CORE,), ghsa_count=1, ghsa_severity="high")
    assert _tier(inp) == ("P0", ["nodejs_core_high"])
    inp = Inputs("CVE-1", cpe_criteria=(NODE_CORE,), ghsa_count=1, ghsa_severity="medium")
    assert _tier(inp) == ("P2", ["in_stack"])


@pytest.mark.parametrize(("cvss", "tier"), [(7.0, "P1"), (6.99, "P2")])
def test_p1_cvss_boundary(cvss, tier):
    assert _tier(_npm(cvss=cvss))[0] == tier


@pytest.mark.parametrize(("pct", "tier"), [(0.90, "P1"), (0.89, "P2")])
def test_p1_epss_percentile_boundary(pct, tier):
    assert _tier(_npm(epss_percentile=pct))[0] == tier


def test_p1_ghsa_severity_only_without_cvss():
    assert _tier(_npm(ghsa_severity="high")) == ("P1", ["ghsa_severity"])
    assert _tier(_npm(ghsa_severity="critical")) == ("P1", ["ghsa_severity"])
    # cvss があれば severity は見ない
    assert _tier(_npm(cvss=5.0, ghsa_severity="high")) == ("P2", ["in_stack"])


def test_p2_in_stack():
    assert _tier(_npm(cvss=5.0)) == ("P2", ["in_stack"])


def test_rejected_is_p3_first():
    assert _tier(_npm(vuln_status="Rejected", kev=True, cvss=9.8)) == ("P3", ["rejected"])


def test_deferred():
    assert _tier(_npm(vuln_status="Deferred", cvss=9.8, epss_score=0.5)) == (
        "P3",
        ["cvss_epss", "deferred"],
    )
    assert _tier(_npm(vuln_status="Deferred", kev=True)) == ("P0", ["kev"])


def test_ghsa_only_subject(store):
    store.upsert_ghsa(make_ghsa("GHSA-aaaa-0001", None, "high", v3=None), "t")
    assert _tier(collect_inputs(store, "GHSA-aaaa-0001")) == ("P1", ["ghsa_severity"])


def test_withdrawn_ghsa_subject(store):
    store.upsert_ghsa(
        make_ghsa("GHSA-aaaa-0002", None, "critical", withdrawn="2099-01-01T00:00:00Z"), "t"
    )
    assert _tier(collect_inputs(store, "GHSA-aaaa-0002")) == ("P3", ["withdrawn"])


def test_kernel_thinning():
    assert _tier(_kernel(cvss=7.5)) == ("P3", ["cvss", "kernel_thinned"])
    assert _tier(_kernel(cvss=8.0)) == ("P1", ["cvss"])
    assert _tier(_kernel(cvss=5.0)) == ("P3", ["in_stack", "kernel_thinned"])
    assert _tier(_kernel(cvss=5.0, epss_percentile=0.95)) == ("P1", ["epss_percentile"])
    assert _tier(_kernel(cvss=5.0, kev=True)) == ("P0", ["kev"])
    # 他のスタックと併存なら間引かない
    both = _kernel(cvss=7.5, ghsa_count=1)
    assert _tier(both) == ("P1", ["cvss"])


def test_thresholds_from_rules():
    rules = parse_rules({"thresholds": {"p1_cvss": 5.0}})
    assert _tier(_npm(cvss=5.0), rules) == ("P1", ["cvss"])
    assert decide_tier(_npm(cvss=5.0), ("npm",), RULES) == ("P2", ["in_stack"])


# --- cvss 代表値 / 入力の収集 ---


def test_representative_cvss():
    assert representative_cvss((9.8, 6.0), []) == 6.0
    assert representative_cvss((9.8, None), [(5.0, None)]) == 9.8
    assert representative_cvss((5.0, None), [(9.0, 7.0), (6.0, None)]) == 7.0
    assert representative_cvss(None, [(None, None)]) is None
    assert representative_cvss(None, []) is None


def test_collect_inputs_for_cve(store):
    store.upsert_cve(
        make_cve(
            "CVE-2099-0001", cvss_v31_score=6.0, cpe_criteria=[NPM_PKG], vuln_status="Deferred"
        ),
        "t",
    )
    store.upsert_kev(KevRecord("CVE-2099-0001", None, None, None, None, None, None), "t")
    store.upsert_epss(EpssRecord("CVE-2099-0001", 0.2, 0.95, "2099-01-01"), "t")
    store.upsert_ghsa(make_ghsa("GHSA-a", "CVE-2099-0001", "medium", v3=8.1), "t")
    store.upsert_ghsa(make_ghsa("GHSA-b", "CVE-2099-0001", "high", v4=7.0, v3=9.9), "t")
    # withdrawn は数えない
    store.upsert_ghsa(make_ghsa("GHSA-c", "CVE-2099-0001", "critical", v3=10.0, withdrawn="x"), "t")
    inp = collect_inputs(store, "CVE-2099-0001")
    assert inp == Inputs(
        "CVE-2099-0001",
        vuln_status="Deferred",
        source_identifier="cna@example.invalid",
        cpe_criteria=(NPM_PKG,),
        kev=True,
        epss_score=0.2,
        epss_percentile=0.95,
        ghsa_count=2,
        cvss=8.1,
        ghsa_severity="high",
    )
    assert inp.as_json() == {
        "cvss": 8.1,
        "epss": 0.2,
        "percentile": 0.95,
        "kev": True,
        "vuln_status": "Deferred",
        "ghsa_severity": "high",
    }


def test_collect_inputs_kev_only_and_missing(store):
    store.upsert_kev(KevRecord("CVE-2099-0003", None, None, None, None, None, None), "t")
    assert collect_inputs(store, "CVE-2099-0003") == Inputs("CVE-2099-0003", kev=True)
    # KEV だけではスタックが分からないので対象外
    assert evaluate(collect_inputs(store, "CVE-2099-0003"), RULES) is None
    assert collect_inputs(store, "CVE-2099-9999") == Inputs("CVE-2099-9999")


def test_collect_inputs_ghsa_with_cve_is_not_ghsa_subject(store):
    store.upsert_ghsa(make_ghsa("GHSA-d", "CVE-2099-0004", "high"), "t")
    assert collect_inputs(store, "GHSA-d") == Inputs("GHSA-d")
