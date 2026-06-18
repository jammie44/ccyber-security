"""
End-to-end API integration test exercising register -> login -> create asset ->
recompute risk -> read org risk. Requires a live PostgreSQL instance reachable at
DATABASE_URL with migrations applied (alembic upgrade head). Skips cleanly if
no database is reachable, so this suite is safe to include in environments
without Postgres provisioned (e.g. a bare CI image).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

import pytest

from tests.backend.conftest import requires_postgres  # noqa: E402


@requires_postgres
def test_register_login_create_asset_and_score_flow(unique_email):
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    # 1. Register
    register_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": unique_email,
            "password": "SuperSecret123",
            "full_name": "Test Analyst",
            "tenant_name": f"TestOrg-{unique_email}",
        },
    )
    assert register_resp.status_code == 201
    tokens = register_resp.json()
    access_token = tokens["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # 2. Get current user
    me_resp = client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == unique_email
    assert me_resp.json()["role"] == "org_admin"

    # 3. Create an asset
    asset_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "test-web-server-01",
            "asset_type": "cloud_vm",
            "environment": "production",
            "criticality_score": 8.0,
            "business_impact_score": 7.5,
            "data_classification": "confidential",
            "exposure_level": "internet",
            "is_internet_facing": True,
        },
    )
    assert asset_resp.status_code == 201
    asset = asset_resp.json()
    assert asset["name"] == "test-web-server-01"
    asset_id = asset["id"]

    # 4. Recompute risk score for the asset
    risk_resp = client.post(f"/api/v1/risk/assets/{asset_id}/recompute", headers=headers)
    assert risk_resp.status_code == 200
    risk = risk_resp.json()
    assert 0 <= risk["risk_score"] <= 100
    assert risk["risk_band"] in ("critical", "high", "medium", "low", "minimal")

    # An internet-facing, high-criticality, confidential asset should not score "minimal"
    assert risk["risk_band"] != "minimal"

    # 5. Fetch org-level risk aggregate
    org_risk_resp = client.get("/api/v1/risk/organization", headers=headers)
    assert org_risk_resp.status_code == 200
    org_risk = org_risk_resp.json()
    assert org_risk["assets_total"] >= 1


@requires_postgres
def test_duplicate_registration_rejected(unique_email):
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    payload = {
        "email": unique_email,
        "password": "SuperSecret123",
        "full_name": "Test User",
        "tenant_name": f"DupOrg-{unique_email}",
    }
    first = client.post("/api/v1/auth/register", json=payload)
    assert first.status_code == 201

    second = client.post("/api/v1/auth/register", json=payload)
    assert second.status_code == 409


@requires_postgres
def test_unauthenticated_request_rejected():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.get("/api/v1/assets")
    assert resp.status_code == 401
