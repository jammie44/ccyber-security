from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

FORMULA_VERSION = "1.0"

DATA_SENSITIVITY = {
    "public": 0.10, "internal": 0.30, "confidential": 0.60,
    "restricted": 0.85, "secret": 1.00,
}

EXPOSURE_BASE = {
    "internet": 1.00, "partner": 0.65, "internal": 0.35, "isolated": 0.10,
}

DEFAULT_WEIGHTS = {
    "vulnerability": 0.35,
    "exposure": 0.25,
    "business": 0.20,
    "posture": 0.15,
    "blast_radius": 0.05,
}


@dataclass
class RiskInput:
    asset_id: str
    criticality_score: float = 5.0
    business_impact_score: float = 5.0
    data_classification: str = "internal"
    exposure_level: str = "internal"
    is_in_compliance_scope: bool = False
    is_internet_facing: bool = False
    blast_radius_score: float = 0.0
    security_health_score: float = 70.0
    last_assessment_age_days: Optional[int] = None
    critical_control_failures: int = 0
    vuln_count_critical: int = 0
    vuln_count_high: int = 0
    vuln_count_medium: int = 0
    vuln_count_low: int = 0
    has_kev_vuln: bool = False
    has_weaponized_exploit: bool = False
    sla_breached_count: int = 0
    days_oldest_critical_open: int = 0


@dataclass
class ComponentScore:
    score: float
    weight: float
    contribution: float
    drivers: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class RiskOutput:
    risk_score: float
    risk_band: str
    confidence: float
    components: Dict[str, ComponentScore]
    formula_version: str = FORMULA_VERSION


def validate_weights(weights: Dict[str, float]) -> None:
    total = sum(weights.values())
    if abs(total - 1.0) >= 0.001:
        raise ValueError(f"weights must sum to 1.0, got {total:.4f}")


def _band(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


def _confidence(inp: RiskInput) -> float:
    c = 100.0
    if inp.last_assessment_age_days is None:
        c -= 40
    elif inp.last_assessment_age_days > 180:
        c -= 30
    elif inp.last_assessment_age_days > 90:
        c -= 20
    return max(0.0, round(c, 2))


def compute_risk_score(inp: RiskInput, weights: Optional[Dict[str, float]] = None) -> RiskOutput:
    w = weights or DEFAULT_WEIGHTS
    validate_weights(w)

    # ── Vulnerability component ──────────────────────────────────────────
    vuln_raw = (
        inp.vuln_count_critical * 25
        + inp.vuln_count_high * 12
        + inp.vuln_count_medium * 4
        + inp.vuln_count_low * 1
    )
    vuln_drivers: List[Dict[str, str]] = []
    if inp.vuln_count_critical > 0:
        vuln_drivers.append({"type": "critical_vulns", "detail": f"{inp.vuln_count_critical} critical open vulnerabilities"})
    if inp.has_kev_vuln:
        vuln_raw = min(100, vuln_raw * 1.5)
        vuln_drivers.append({"type": "kev_vulnerability", "detail": "CISA KEV vulnerability present — actively exploited"})
    if inp.has_weaponized_exploit:
        vuln_raw = min(100, vuln_raw * 1.3)
        vuln_drivers.append({"type": "weaponized_exploit", "detail": "Weaponized public exploit available"})
    if inp.sla_breached_count > 0:
        vuln_raw = min(100, vuln_raw + inp.sla_breached_count * 5)
        vuln_drivers.append({"type": "sla_breach", "detail": f"{inp.sla_breached_count} vulnerability SLAs breached"})
    if inp.days_oldest_critical_open > 90:
        vuln_raw = min(100, vuln_raw * 1.2)
        vuln_drivers.append({"type": "stale_critical", "detail": f"Critical vulnerability open {inp.days_oldest_critical_open} days"})
    vuln_score = min(100.0, max(0.0, vuln_raw))

    # ── Exposure component ───────────────────────────────────────────────
    exposure_base = EXPOSURE_BASE.get(inp.exposure_level, 0.35)
    exposure_raw = exposure_base * 100
    exposure_drivers = [{"type": "exposure_level", "detail": f"Asset exposure: {inp.exposure_level}"}]
    if inp.is_internet_facing and inp.exposure_level != "internet":
        exposure_raw = min(100, exposure_raw * 1.4)
        exposure_drivers.append({"type": "indirect_internet_path", "detail": "Reachable from internet via network path"})
    exposure_score = min(100.0, max(0.0, exposure_raw))

    # ── Business component ───────────────────────────────────────────────
    data_sens = DATA_SENSITIVITY.get(inp.data_classification, 0.30)
    compliance_mult = 1.3 if inp.is_in_compliance_scope else 1.0
    business_raw = (
        (inp.criticality_score / 10.0 * 0.40)
        + (inp.business_impact_score / 10.0 * 0.35)
        + (data_sens * 0.25)
    ) * 100 * compliance_mult
    business_score = min(100.0, max(0.0, business_raw))
    business_drivers = [
        {"type": "asset_criticality", "detail": f"Criticality score {inp.criticality_score}/10"},
        {"type": "data_classification", "detail": f"Data classification: {inp.data_classification}"},
    ]
    if inp.is_in_compliance_scope:
        business_drivers.append({"type": "compliance_scope", "detail": "In regulatory compliance scope (+30%)"})

    # ── Posture component ────────────────────────────────────────────────
    posture_raw = 100 - inp.security_health_score
    posture_drivers: List[Dict[str, str]] = []
    if inp.last_assessment_age_days is None:
        posture_raw = min(100, posture_raw * 1.4)
        posture_drivers.append({"type": "never_assessed", "detail": "Asset has never been security-assessed"})
    elif inp.last_assessment_age_days > 180:
        posture_raw = min(100, posture_raw * 1.4)
        posture_drivers.append({"type": "very_stale_assessment", "detail": f"Last assessed {inp.last_assessment_age_days} days ago"})
    elif inp.last_assessment_age_days > 90:
        posture_raw = min(100, posture_raw * 1.2)
        posture_drivers.append({"type": "stale_assessment", "detail": f"Last assessed {inp.last_assessment_age_days} days ago"})
    if inp.critical_control_failures > 0:
        posture_raw = min(100, posture_raw + inp.critical_control_failures * 3)
        posture_drivers.append({"type": "control_failures", "detail": f"{inp.critical_control_failures} critical controls failing"})
    posture_score = min(100.0, max(0.0, posture_raw))

    # ── Blast radius component ───────────────────────────────────────────
    blast_score = min(100.0, inp.blast_radius_score * 10)
    blast_drivers: List[Dict[str, str]] = []

    # ── Final weighted score ─────────────────────────────────────────────
    final = (
        vuln_score * w["vulnerability"]
        + exposure_score * w["exposure"]
        + business_score * w["business"]
        + posture_score * w["posture"]
        + blast_score * w["blast_radius"]
    )
    final = round(max(0.0, min(100.0, final)), 2)

    components = {
        "vulnerability": ComponentScore(round(vuln_score, 2), w["vulnerability"], round(vuln_score * w["vulnerability"], 2), vuln_drivers),
        "exposure": ComponentScore(round(exposure_score, 2), w["exposure"], round(exposure_score * w["exposure"], 2), exposure_drivers),
        "business": ComponentScore(round(business_score, 2), w["business"], round(business_score * w["business"], 2), business_drivers),
        "posture": ComponentScore(round(posture_score, 2), w["posture"], round(posture_score * w["posture"], 2), posture_drivers),
        "blast_radius": ComponentScore(round(blast_score, 2), w["blast_radius"], round(blast_score * w["blast_radius"], 2), blast_drivers),
    }

    return RiskOutput(
        risk_score=final,
        risk_band=_band(final),
        confidence=_confidence(inp),
        components=components,
    )
