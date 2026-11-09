"""スタック判定と tier 判定（shadow）。

collect_inputs だけが作業 DB を読み、それ以外は Inputs と Rules からの純粋関数。
subject は CVE ID か、CVE の無い GHSA の GHSA ID。
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from vuln_signal.config import Rules
from vuln_signal.sources.nvd import LINUX_KERNEL_CNA
from vuln_signal.store import Store

TIERS = ("P0", "P1", "P2", "P3")
GHSA_PREFIX = "GHSA-"
SEVERITY_ORDER = ("low", "medium", "high", "critical")
NODEJS_CORE_CPE = "cpe:2.3:a:nodejs:node.js:"
LINUX_KERNEL_CPE = "cpe:2.3:o:linux:linux_kernel:"
# CPE 2.3 の target_sw（":" 区切りで 0 始まり 10 番目）
_TARGET_SW_INDEX = 10
# エスケープされていない ":" で区切る
_CPE_SPLIT = re.compile(r"(?<!\\):")
# 浮動小数の誤差で閾値ちょうどを取りこぼさないための幅
_EPS = 1e-9


@dataclass(frozen=True)
class Inputs:
    """判定に使う値。無いものは None / 空。"""

    subject_id: str
    vuln_status: str | None = None
    source_identifier: str | None = None
    cpe_criteria: tuple[str, ...] = ()
    kev: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    # withdrawn でない GHSA の件数
    ghsa_count: int = 0
    # subject が GHSA ID で withdrawn 済み
    withdrawn: bool = False
    # 代表 CVSS（各ソースで v4.0 優先、NVD と GHSA の最大）
    cvss: float | None = None
    # 有効な GHSA の severity の最大
    ghsa_severity: str | None = None

    def as_json(self) -> dict[str, Any]:
        """tier.inputs に入れる値。"""
        return {
            "cvss": self.cvss,
            "epss": self.epss_score,
            "percentile": self.epss_percentile,
            "kev": self.kev,
            "vuln_status": self.vuln_status,
            "ghsa_severity": self.ghsa_severity,
        }


@dataclass(frozen=True)
class Decision:
    tier: str
    stacks: tuple[str, ...]  # ソート済み
    reasons: tuple[str, ...]  # 判定順


def is_ghsa_id(subject_id: str) -> bool:
    return subject_id.startswith(GHSA_PREFIX)


def _prefer_v4(v4: float | None, v3: float | None) -> float | None:
    return v4 if v4 is not None else v3


# (v3.x, v4.0) のスコア
ScorePair = tuple[float | None, float | None]


def representative_cvss(nvd: ScorePair | None, ghsa: list[ScorePair]) -> float | None:
    """NVD と GHSA の (v3.x, v4.0) から代表値。各ソースで v4.0 優先、その中の最大。"""
    scores: list[float] = []
    if nvd is not None:
        score = _prefer_v4(nvd[1], nvd[0])
        if score is not None:
            scores.append(score)
    for v3, v4 in ghsa:
        score = _prefer_v4(v4, v3)
        if score is not None:
            scores.append(score)
    return max(scores, default=None)


def max_severity(severities: list[str | None]) -> str | None:
    known = [s.lower() for s in severities if s and s.lower() in SEVERITY_ORDER]
    return max(known, key=SEVERITY_ORDER.index, default=None)


def collect_inputs(store: Store, subject_id: str) -> Inputs:
    """作業 DB から subject の判定入力を集める。"""
    conn = store.conn
    if is_ghsa_id(subject_id):
        # CVE が付いた GHSA は CVE 側の subject になるので、ここでは CVE の無いものだけ
        row = conn.execute(
            "SELECT * FROM ghsa WHERE ghsa_id = ? AND cve_id IS NULL", (subject_id,)
        ).fetchone()
        if row is None:
            return Inputs(subject_id)
        if row["withdrawn_at"] is not None:
            return Inputs(subject_id, withdrawn=True)
        return Inputs(
            subject_id,
            ghsa_count=1,
            cvss=representative_cvss(None, [(row["cvss_v3_score"], row["cvss_v4_score"])]),
            ghsa_severity=max_severity([row["severity"]]),
        )

    cve = store.get_cve(subject_id)
    epss = store.get_epss(subject_id)
    kev = conn.execute("SELECT 1 FROM kev WHERE cve_id = ?", (subject_id,)).fetchone()
    ghsa = conn.execute(
        "SELECT * FROM ghsa WHERE cve_id = ? AND withdrawn_at IS NULL", (subject_id,)
    ).fetchall()
    nvd = (cve["cvss_v31_score"], cve["cvss_v40_score"]) if cve is not None else None
    return Inputs(
        subject_id,
        vuln_status=cve["vuln_status"] if cve is not None else None,
        source_identifier=cve["source_identifier"] if cve is not None else None,
        cpe_criteria=tuple(json.loads(cve["cpe_criteria"] or "[]")) if cve is not None else (),
        kev=kev is not None,
        epss_score=epss["score"] if epss is not None else None,
        epss_percentile=epss["percentile"] if epss is not None else None,
        ghsa_count=len(ghsa),
        cvss=representative_cvss(nvd, [(g["cvss_v3_score"], g["cvss_v4_score"]) for g in ghsa]),
        ghsa_severity=max_severity([g["severity"] for g in ghsa]),
    )


# --- スタック判定 ---


def _target_sw(cpe: str) -> str | None:
    parts = _CPE_SPLIT.split(cpe)
    return parts[_TARGET_SW_INDEX] if len(parts) > _TARGET_SW_INDEX else None


def _nodejs_core(inp: Inputs) -> bool:
    return any(c.startswith(NODEJS_CORE_CPE) for c in inp.cpe_criteria)


def _npm(inp: Inputs) -> bool:
    # GHSA は npm だけ取っている。withdrawn の GHSA subject は P3 にするため npm に入れる
    if inp.ghsa_count > 0 or inp.withdrawn:
        return True
    return any(
        not c.startswith(NODEJS_CORE_CPE) and _target_sw(c) == "node.js" for c in inp.cpe_criteria
    )


def _linux_kernel(inp: Inputs) -> bool:
    if inp.source_identifier == LINUX_KERNEL_CNA:
        return True
    return any(c.startswith(LINUX_KERNEL_CPE) for c in inp.cpe_criteria)


# 組み込みのスタック。ディストリ（#8）はここに足す
BUILTIN_STACKS: tuple[tuple[str, Callable[[Inputs], bool]], ...] = (
    ("nodejs_core", _nodejs_core),
    ("npm", _npm),
    ("linux_kernel", _linux_kernel),
)


def detect_stacks(inp: Inputs, rules: Rules) -> tuple[str, ...]:
    """当たったスタックをソートして返す。extra は extra:<name>。"""
    stacks = {name for name, match in BUILTIN_STACKS if match(inp)}
    for extra in rules.extra_stacks:
        if any(c.startswith(extra.cpe_prefix) for c in inp.cpe_criteria):
            stacks.add(f"extra:{extra.name}")
    return tuple(sorted(stacks))


# --- tier 判定 ---


def _ge(value: float | None, threshold: float) -> bool:
    return value is not None and value >= threshold - _EPS


def _severity_high(severity: str | None) -> bool:
    return severity is not None and SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index("high")


def decide_tier(inp: Inputs, stacks: tuple[str, ...], rules: Rules) -> tuple[str, list[str]]:
    """(tier, reasons)。stacks は空でない前提。"""
    t = rules.thresholds
    if inp.vuln_status == "Rejected":
        return "P3", ["rejected"]
    if inp.withdrawn:
        return "P3", ["withdrawn"]

    # cvss が無いときは GHSA の severity で代える
    if inp.cvss is not None:
        core_high = _ge(inp.cvss, t.nodejs_core_cvss)
    else:
        core_high = _severity_high(inp.ghsa_severity)
    p0 = []
    if inp.kev:
        p0.append("kev")
    if _ge(inp.cvss, t.p0_cvss) and _ge(inp.epss_score, t.p0_epss):
        p0.append("cvss_epss")
    if "nodejs_core" in stacks and core_high:
        p0.append("nodejs_core_high")

    p1 = []
    if _ge(inp.cvss, t.p1_cvss):
        p1.append("cvss")
    if inp.cvss is None and _severity_high(inp.ghsa_severity):
        p1.append("ghsa_severity")
    if _ge(inp.epss_percentile, t.p1_epss_percentile):
        p1.append("epss_percentile")

    if p0:
        tier, reasons = "P0", p0
    elif p1:
        tier, reasons = "P1", p1
    else:
        tier, reasons = "P2", ["in_stack"]

    if inp.vuln_status == "Deferred" and not inp.kev:
        tier = "P3"
        reasons.append("deferred")

    if (
        stacks == ("linux_kernel",)
        and tier in ("P1", "P2")
        and not (
            inp.kev
            or _ge(inp.epss_percentile, t.kernel_epss_percentile)
            or _ge(inp.cvss, t.kernel_cvss)
        )
    ):
        tier = "P3"
        reasons.append("kernel_thinned")
    return tier, reasons


def evaluate(inp: Inputs, rules: Rules) -> Decision | None:
    """スタックが空なら None（対象外）。"""
    stacks = detect_stacks(inp, rules)
    if not stacks:
        return None
    tier, reasons = decide_tier(inp, stacks, rules)
    return Decision(tier, stacks, tuple(reasons))
