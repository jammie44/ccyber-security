"""
Unit tests for app.services.risk_scoring_engine.

Run from backend/ with: pytest ../tests/backend/unit/test_risk_scoring_engine.py
(or add backend/ to PYTHONPATH).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "backend"))

import pytest

from app.services.risk_scoring_engine import (
    DEFAULT_WEIGHTS,
    RiskInput,
    compute_risk_score,
    validate_weights,
)


def test_weights_sum_validation_passes():
    validate_weights(DEFAULT_WEIGHTS)  # should not raise


def test_weights_sum_validation_fails():
    bad_weights = {"vulnerability": 0.5, "exposure": 0.5, "business": 0.5, "posture": 0.1, "blast_radius": 0.1}
    with pytest.raises(ValueError):
        validate_weights(bad_weights)


def test_minimal_risk_input_produces_low_score():
    inp = RiskInput(
        asset_id="a1",
        criticality_score=1.0,
        business_impact_score=1.0,
        data_classification="public",
        exposure_level="isolated",
        security_health_score=95.0,
        last_assessment_age_days=5,
    )
    out = compute_risk_score(inp)
    assert out.risk_score < 30
    assert out.risk_band in ("minimal", "low")


def test_critical_kev_internet_facing_produces_high_score():
    inp = RiskInput(
        asset_id="a2",
        criticality_score=9.5,
        business_impact_score=9.0,
        data_classification="restricted",
        exposure_level="internet",
        is_in_compliance_scope=True,
        is_internet_facing=True,
        security_health_score=30.0,
        vuln_count_critical=3,
        vuln_count_high=5,
        has_kev_vuln=True,
        has_weaponized_exploit=True,
        sla_breached_count=2,
        days_oldest_critical_open=120,
        last_assessment_age_days=200,
        critical_control_failures=4,
    )
    out = compute_risk_score(inp)
    assert out.risk_score >= 80
    assert out.risk_band == "critical"


def test_kev_escalation_increases_vuln_component():
    base = RiskInput(asset_id="a3", vuln_count_critical=2)
    with_kev = RiskInput(asset_id="a3", vuln_count_critical=2, has_kev_vuln=True)

    out_base = compute_risk_score(base)
    out_kev = compute_risk_score(with_kev)

    assert out_kev.components["vulnerability"].score > out_base.components["vulnerability"].score


def test_score_is_bounded_0_100():
    extreme = RiskInput(
        asset_id="a4",
        criticality_score=10,
        business_impact_score=10,
        data_classification="secret",
        exposure_level="internet",
        is_in_compliance_scope=True,
        is_internet_facing=True,
        security_health_score=0,
        vuln_count_critical=50,
        vuln_count_high=50,
        has_kev_vuln=True,
        has_weaponized_exploit=True,
        sla_breached_count=20,
        days_oldest_critical_open=400,
        critical_control_failures=20,
        last_assessment_age_days=400,
    )
    out = compute_risk_score(extreme)
    assert 0.0 <= out.risk_score <= 100.0
    for comp in out.components.values():
        assert 0.0 <= comp.score <= 100.0


def test_custom_weights_change_outcome():
    # Use an input where vulnerability and exposure components land at different
    # raw scores, so re-weighting them is guaranteed to change the final blended score.
    inp = RiskInput(asset_id="a5", vuln_count_critical=4, exposure_level="isolated")
    vuln_heavy = {"vulnerability": 0.70, "exposure": 0.10, "business": 0.10, "posture": 0.05, "blast_radius": 0.05}
    exposure_heavy = {"vulnerability": 0.10, "exposure": 0.70, "business": 0.10, "posture": 0.05, "blast_radius": 0.05}

    out_vuln_heavy = compute_risk_score(inp, vuln_heavy)
    out_exposure_heavy = compute_risk_score(inp, exposure_heavy)

    # Different weight profiles should produce different final scores
    # when the underlying component scores differ from each other.
    assert out_vuln_heavy.risk_score != out_exposure_heavy.risk_score
    # Sanity check on direction: weighting toward the higher-scoring component
    # (vulnerability, driven by 4 critical open vulns) should yield a higher total
    # than weighting toward the lower-scoring component (isolated exposure).
    assert out_vuln_heavy.risk_score > out_exposure_heavy.risk_score


def test_confidence_drops_with_no_assessment_data():
    never_assessed = RiskInput(asset_id="a6", last_assessment_age_days=None)
    recently_assessed = RiskInput(asset_id="a6", last_assessment_age_days=10)

    out_never = compute_risk_score(never_assessed)
    out_recent = compute_risk_score(recently_assessed)

    assert out_never.confidence < out_recent.confidence


def test_band_thresholds():
    from app.services.risk_scoring_engine import _band

    assert _band(85) == "critical"
    assert _band(65) == "high"
    assert _band(45) == "medium"
    assert _band(25) == "low"
    assert _band(5) == "minimal"


def test_drivers_present_for_critical_vulns():
    inp = RiskInput(asset_id="a7", vuln_count_critical=3, has_kev_vuln=True)
    out = compute_risk_score(inp)
    driver_types = {d["type"] for d in out.components["vulnerability"].drivers}
    assert "critical_vulns" in driver_types
    assert "kev_vulnerability" in driver_types
