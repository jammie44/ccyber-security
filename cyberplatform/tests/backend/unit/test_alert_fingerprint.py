import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "backend"))

from app.services.alert_service import AlertService


def _make_rule(dedup_fields):
    return SimpleNamespace(id=uuid.uuid4(), dedup_key_fields=dedup_fields, dedup_window_minutes=60)


def test_fingerprint_deterministic_for_same_input():
    service = AlertService(db=None)  # type: ignore[arg-type]
    rule = _make_rule(["asset_id", "event_type"])
    event_data = {"asset_id": "abc-123", "event_type": "config_drift"}

    fp1 = service._compute_fingerprint(rule, event_data)
    fp2 = service._compute_fingerprint(rule, event_data)
    assert fp1 == fp2


def test_fingerprint_differs_for_different_assets():
    service = AlertService(db=None)  # type: ignore[arg-type]
    rule = _make_rule(["asset_id", "event_type"])

    fp1 = service._compute_fingerprint(rule, {"asset_id": "abc-123", "event_type": "config_drift"})
    fp2 = service._compute_fingerprint(rule, {"asset_id": "xyz-789", "event_type": "config_drift"})
    assert fp1 != fp2


def test_fingerprint_differs_across_rules():
    service = AlertService(db=None)  # type: ignore[arg-type]
    rule_a = _make_rule(["asset_id"])
    rule_b = _make_rule(["asset_id"])
    event_data = {"asset_id": "abc-123"}

    fp_a = service._compute_fingerprint(rule_a, event_data)
    fp_b = service._compute_fingerprint(rule_b, event_data)
    # Different rule IDs must produce different fingerprints even with identical event data
    assert fp_a != fp_b


def test_fingerprint_ignores_unlisted_fields():
    service = AlertService(db=None)  # type: ignore[arg-type]
    rule = _make_rule(["asset_id"])

    fp1 = service._compute_fingerprint(rule, {"asset_id": "abc-123", "noise": "value-1"})
    fp2 = service._compute_fingerprint(rule, {"asset_id": "abc-123", "noise": "value-2"})
    assert fp1 == fp2
