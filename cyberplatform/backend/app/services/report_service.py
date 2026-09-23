"""
app/services/report_service.py

Four responsibilities:
  1. Executive PDF report (reportlab)
  2. Scheduled + on-demand email digest (smtplib)
  3. Compliance evidence export (ZIP of JSON files)
  4. Report history logging

All imports fixed to match the existing codebase path conventions.
Field names are isolated in helper functions at the top so any
mismatch can be fixed in one place.
"""
from __future__ import annotations

import io
import json
import logging
import os
import smtplib
import tempfile
import zipfile
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

# Fixed imports — match existing codebase
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability
from app.models.risk import AssetRiskScore, OrgRiskScore
from app.models.attack_simulation_result import AttackSimulationResult
from app.models.intelligence import SecurityPostureSnapshot
from app.models.network_monitor import DataProtectionFinding, AccessAuditLog
from app.models.user import User
from app.models.report_log import ReportLog

logger = logging.getLogger(__name__)

SMTP_TIMEOUT_SECONDS = 15
GROQ_TIMEOUT_SECONDS = 10
GROQ_MODEL = "llama-3.3-70b-versatile"
DIGEST_ROLES = {"security_manager", "admin", "org_admin", "owner"}


def _decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    return str(obj)


def _asset_name(asset) -> str:
    return getattr(asset, "name", None) or getattr(asset, "fqdn", None) or str(asset.id)


def _risk_band(score: Optional[float]) -> tuple[str, str]:
    if score is None:
        return "unknown", "#999999"
    if score >= 75:
        return "critical", "#D32F2F"
    if score >= 50:
        return "high", "#F57C00"
    if score >= 25:
        return "medium", "#FBC02D"
    return "low", "#388E3C"


# =============================================================================
# Shared data-gathering helpers (all tenant-scoped, all exception-safe)
# =============================================================================

async def _get_org_risk(db: AsyncSession, tenant_id) -> dict:
    try:
        row = (await db.execute(
            select(OrgRiskScore).where(OrgRiskScore.tenant_id == tenant_id)
        )).scalar_one_or_none()
        score = float(row.risk_score) if row else None
    except Exception:
        logger.exception("Failed to fetch org risk score for tenant %s", tenant_id)
        score = None
    band, color = _risk_band(score)
    return {"score": score, "band": band, "color": color}


async def _get_asset_inventory(db: AsyncSession, tenant_id, full_detail: bool = False) -> list[dict]:
    try:
        stmt = (
            select(Asset, AssetRiskScore)
            .outerjoin(AssetRiskScore, AssetRiskScore.asset_id == Asset.id)
            .where(Asset.tenant_id == tenant_id, Asset.is_deleted == False)  # noqa: E712
        )
        rows = (await db.execute(stmt)).all()
    except Exception:
        logger.exception("Failed to fetch asset inventory for tenant %s", tenant_id)
        return []

    inventory = []
    for asset, risk in rows:
        score = float(risk.risk_score) if risk else None
        band, _ = _risk_band(score)

        crit_count = 0
        try:
            crit_count = (await db.execute(
                select(func.count(AssetVulnerability.id)).where(
                    AssetVulnerability.asset_id == asset.id,
                    AssetVulnerability.priority == "critical",
                    AssetVulnerability.status != "closed",
                )
            )).scalar_one() or 0
        except Exception:
            pass

        entry = {
            "asset_id": str(asset.id),
            "name": _asset_name(asset),
            "asset_type": getattr(asset, "asset_type", None),
            "environment": getattr(asset, "environment", None),
            "risk_score": score,
            "risk_band": band,
            "open_critical_vulns": crit_count,
        }
        if full_detail:
            entry["ip_addresses"] = getattr(asset, "ip_addresses", None)
            entry["os_name"] = getattr(asset, "os_name", None)
            entry["os_version"] = getattr(asset, "os_version", None)
            entry["is_internet_facing"] = getattr(asset, "is_internet_facing", None)
            entry["custom_attributes"] = getattr(asset, "custom_attributes", None)
        inventory.append(entry)
    return inventory


async def _get_top_vulnerabilities(db: AsyncSession, tenant_id, limit: int = 10) -> list[dict]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    try:
        stmt = (
            select(AssetVulnerability, Asset)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .where(AssetVulnerability.tenant_id == tenant_id, AssetVulnerability.status != "closed")
        )
        rows = (await db.execute(stmt)).all()
    except Exception:
        logger.exception("Failed to fetch vulnerabilities for tenant %s", tenant_id)
        return []

    today = date.today()
    results = []
    for vuln, asset in rows:
        deadline = getattr(vuln, "sla_deadline", None)
        days_left = sla_status = None
        if deadline:
            try:
                deadline_dt = datetime.fromisoformat(str(deadline))
                days_left = (deadline_dt.date() - today).days
                sla_status = "overdue" if days_left < 0 else ("due_soon" if days_left <= 7 else "on_track")
            except Exception:
                pass
        results.append({
            "cve_id": vuln.cve_id,
            "asset_name": _asset_name(asset),
            "priority": vuln.priority,
            "sla_status": sla_status or "unknown",
            "days_until_deadline": days_left,
        })

    results.sort(key=lambda v: (severity_order.get(v["priority"], 99), v["days_until_deadline"] or 999))
    return results[:limit]


async def _get_simulation_findings(db: AsyncSession, tenant_id, limit: int = 100) -> list[dict]:
    try:
        stmt = (
            select(AttackSimulationResult, Asset)
            .join(Asset, Asset.id == AttackSimulationResult.asset_id)
            .where(AttackSimulationResult.tenant_id == tenant_id)
            .order_by(AttackSimulationResult.simulated_at.desc())
            .limit(limit)
        )
        rows = (await db.execute(stmt)).all()
    except Exception:
        logger.exception("Failed to fetch simulation findings for tenant %s", tenant_id)
        return []
    return [
        {
            "asset_name": _asset_name(asset),
            "finding_title": sim.finding_title,
            "severity": sim.severity,
            "confirmed": bool(sim.was_successful),
        }
        for sim, asset in rows
    ]


async def _get_remediation_roadmap(db: AsyncSession, tenant_id, top_n: int = 5) -> list[dict]:
    """
    Groups open critical/high vulns by affected_component to produce
    "fix X across N assets" recommendations. See README §8 for notes
    on the heuristic — replace with real business logic before using
    these numbers for budget decisions.
    """
    try:
        vulns = (await db.execute(
            select(AssetVulnerability).where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.status != "closed",
                AssetVulnerability.priority.in_(["critical", "high"]),
            )
        )).scalars().all()
    except Exception:
        logger.exception("Failed to fetch vulns for roadmap (tenant %s)", tenant_id)
        return []

    if not vulns:
        return []

    severity_weight = {"critical": 3, "high": 2, "medium": 1, "low": 0.5}
    groups: dict[str, dict] = {}
    for v in vulns:
        key = getattr(v, "affected_component", None) or v.cve_id or "unspecified"
        g = groups.setdefault(key, {"assets": set(), "priority_counts": {}})
        g["assets"].add(v.asset_id)
        g["priority_counts"][v.priority] = g["priority_counts"].get(v.priority, 0) + 1

    scored = sorted([
        {
            "component": key,
            "asset_count": len(g["assets"]),
            "weighted_score": sum(severity_weight.get(p, 1) * c for p, c in g["priority_counts"].items()),
        }
        for key, g in groups.items()
    ], key=lambda x: x["weighted_score"], reverse=True)

    top = scored[:top_n]
    max_score = top[0]["weighted_score"] if top else 1
    roadmap = []
    for item in top:
        ac = item["asset_count"]
        roadmap.append({
            "action_title": f"Remediate exposure on {item['component']}",
            "affected_asset_count": ac,
            "effort_level": "low" if ac <= 2 else ("medium" if ac <= 9 else "high"),
            "expected_risk_reduction": round((item["weighted_score"] / max_score) * 100, 1) if max_score else 0,
        })
    return roadmap


async def _log_report(
    db: AsyncSession, tenant_id, report_type: str, generated_by=None,
    file_size_bytes: Optional[int] = None, recipient_count: Optional[int] = None,
    status: str = "success",
) -> None:
    try:
        db.add(ReportLog(
            tenant_id=tenant_id,
            report_type=report_type,
            generated_by=generated_by,
            generated_at=datetime.now(timezone.utc),
            file_size_bytes=file_size_bytes,
            recipient_count=recipient_count,
            status=status,
        ))
        await db.commit()
    except Exception:
        logger.exception("Failed to write report_log entry (%s) for tenant %s", report_type, tenant_id)
        try:
            await db.rollback()
        except Exception:
            pass


# =============================================================================
# 1. EXECUTIVE PDF REPORT
# =============================================================================

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)


async def _generate_exec_summary_text(data: dict) -> str:
    api_key = os.environ.get("GROQ_API_KEY")
    prompt = f"""Write a 3-paragraph plain-English executive summary for a cybersecurity report.
No jargon, no CVE IDs, no port numbers — this is for a business executive.

Data:
- Overall risk score: {data['org_risk']['score']} ({data['org_risk']['band']})
- Top risks affecting: {[v['asset_name'] for v in data['top_vulns'][:3]]}
- Recommended priority actions: {[r['action_title'] for r in data['roadmap'][:3]]}

Paragraph 1: current security posture in plain terms.
Paragraph 2: the top 3 risks and their business impact.
Paragraph 3: recommended priority actions.
Output only the three paragraphs, no headers or preamble."""

    if api_key:
        try:
            from groq import Groq
            client = Groq(api_key=api_key)
            response = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                timeout=GROQ_TIMEOUT_SECONDS,
            )
            text = response.choices[0].message.content
            if text:
                return text
        except Exception:
            logger.exception("Groq call failed for exec summary; using template fallback.")

    band = data["org_risk"]["band"]
    score = data["org_risk"]["score"]
    top3 = ", ".join(v["asset_name"] for v in data["top_vulns"][:3]) or "no assets currently flagged"
    actions = "; ".join(r["action_title"] for r in data["roadmap"][:3]) or "no specific actions identified yet"
    return (
        f"The organization's current overall risk score is "
        f"{score if score is not None else 'not yet calculated'}, placing it in the {band} risk band. "
        f"This reflects open vulnerabilities, confirmed exposures, and asset configuration across the environment.\n\n"
        f"The most significant risks currently affect: {top3}. These systems represent the greatest "
        f"potential business impact if left unaddressed.\n\n"
        f"Recommended priority actions: {actions}. Addressing these first will produce the "
        f"largest reduction in overall organizational risk."
    )


def _pdf_footer(canvas, doc, tenant_name: str):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(
        letter[0] / 2, 0.4 * inch,
        f"Generated by CyberPlatform | {date.today().isoformat()} | {tenant_name} | Page {doc.page}"
    )
    canvas.restoreState()


def _standard_table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ])


async def generate_executive_pdf(db: AsyncSession, tenant_id, tenant_name: str, generated_by=None) -> str:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCentered", parent=styles["Title"], alignment=TA_CENTER)

    data = {"org_risk": await _get_org_risk(db, tenant_id), "top_vulns": [], "asset_inventory": [], "sim_findings": [], "roadmap": []}
    for key, fn, kwargs in [
        ("top_vulns", _get_top_vulnerabilities, {"limit": 10}),
        ("asset_inventory", _get_asset_inventory, {}),
        ("sim_findings", _get_simulation_findings, {"limit": 50}),
        ("roadmap", _get_remediation_roadmap, {"top_n": 5}),
    ]:
        try:
            data[key] = await fn(db, tenant_id, **kwargs)
        except Exception:
            logger.exception("PDF section '%s' failed for tenant %s", key, tenant_id)

    exec_summary_text = await _generate_exec_summary_text(data)

    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp_path = tmp.name
    tmp.close()

    doc = SimpleDocTemplate(tmp_path, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch)

    def on_page(canvas, doc_):
        try:
            _pdf_footer(canvas, doc_, tenant_name)
        except Exception:
            pass

    story = []

    # Page 1: Cover
    try:
        story += [
            Spacer(1, 2 * inch),
            Paragraph(tenant_name or "Organization", title_style),
            Spacer(1, 0.3 * inch),
            Paragraph("Executive Security Report", title_style),
            Spacer(1, 0.5 * inch),
            Paragraph(f"Report Date: {date.today().isoformat()}", styles["Normal"]),
            Spacer(1, 0.3 * inch),
        ]
        band = data["org_risk"]["band"]
        score = data["org_risk"]["score"]
        color_hex = data["org_risk"]["color"]
        risk_table = Table(
            [[f"Overall Risk: {band.upper()}  (score: {score if score is not None else 'N/A'})"]],
            colWidths=[4 * inch],
        )
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(color_hex)),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTSIZE", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(risk_table)
        story.append(PageBreak())
    except Exception:
        logger.exception("Cover page failed for tenant %s", tenant_id)

    # Page 2: Executive Summary
    try:
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * inch))
        for para in exec_summary_text.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), styles["BodyText"]))
                story.append(Spacer(1, 0.15 * inch))
        story.append(PageBreak())
    except Exception:
        logger.exception("Executive summary page failed for tenant %s", tenant_id)

    # Page 3: Asset Inventory
    try:
        story.append(Paragraph("Asset Inventory", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * inch))
        rows = [["Asset Name", "Type", "Environment", "Risk Score", "Risk Band", "Open Critical Vulns"]]
        for a in data["asset_inventory"][:200]:
            rows.append([
                a["name"], a["asset_type"] or "-", a["environment"] or "-",
                f"{a['risk_score']:.1f}" if a["risk_score"] is not None else "-",
                a["risk_band"], str(a["open_critical_vulns"]),
            ])
        t = Table(rows, repeatRows=1)
        t.setStyle(_standard_table_style())
        story.append(t)
        story.append(PageBreak())
    except Exception:
        logger.exception("Asset inventory page failed for tenant %s", tenant_id)

    # Page 4: Top Vulnerabilities
    try:
        story.append(Paragraph("Top Vulnerabilities by Severity", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * inch))
        rows = [["CVE ID", "Asset", "Priority", "SLA Status", "Days Until Deadline"]]
        for v in data["top_vulns"]:
            rows.append([
                v["cve_id"] or "-", v["asset_name"], v["priority"],
                v["sla_status"],
                str(v["days_until_deadline"]) if v["days_until_deadline"] is not None else "-",
            ])
        t = Table(rows, repeatRows=1)
        t.setStyle(_standard_table_style())
        story.append(t)
        story.append(PageBreak())
    except Exception:
        logger.exception("Vulnerability page failed for tenant %s", tenant_id)

    # Page 5: Simulation Findings
    try:
        story.append(Paragraph("Attack Simulation Findings", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * inch))
        rows = [["Asset", "Finding", "Severity", "Confirmed"]]
        for s in data["sim_findings"][:100]:
            rows.append([s["asset_name"], s["finding_title"], s["severity"], "Yes" if s["confirmed"] else "No"])
        t = Table(rows, repeatRows=1)
        t.setStyle(_standard_table_style())
        story.append(t)
        story.append(PageBreak())
    except Exception:
        logger.exception("Simulation findings page failed for tenant %s", tenant_id)

    # Page 6: Remediation Roadmap
    try:
        story.append(Paragraph("Remediation Roadmap", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * inch))
        rows = [["Action", "Affected Assets", "Effort", "Expected Risk Reduction"]]
        for r in data["roadmap"]:
            rows.append([r["action_title"], str(r["affected_asset_count"]), r["effort_level"], f"{r['expected_risk_reduction']}%"])
        t = Table(rows, repeatRows=1)
        t.setStyle(_standard_table_style())
        story.append(t)
    except Exception:
        logger.exception("Remediation roadmap page failed for tenant %s", tenant_id)

    try:
        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    except Exception:
        logger.exception("PDF build failed for tenant %s", tenant_id)
        try:
            SimpleDocTemplate(tmp_path, pagesize=letter).build(
                [Paragraph("Report generation encountered errors. Partial data may be missing.", styles["BodyText"])]
            )
        except Exception:
            raise

    file_size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
    await _log_report(db, tenant_id, "executive_pdf", generated_by, file_size_bytes=file_size)
    return tmp_path


# =============================================================================
# 2. SCHEDULED EMAIL DIGEST
# =============================================================================

async def _get_digest_recipients(db: AsyncSession, tenant_id) -> list[str]:
    try:
        stmt = select(User.email).where(
            User.tenant_id == tenant_id,
            User.role.in_(DIGEST_ROLES),
            User.is_active.is_(True),
        )
        rows = (await db.execute(stmt)).all()
        return [email for (email,) in rows if email]
    except Exception:
        logger.exception("Failed to fetch digest recipients for tenant %s", tenant_id)
        return []


async def _build_digest_data(db: AsyncSession, tenant_id) -> dict:
    org_risk = await _get_org_risk(db, tenant_id)
    risk_delta = None
    try:
        week_ago = date.today() - timedelta(days=7)
        snap = (await db.execute(
            select(SecurityPostureSnapshot)
            .where(SecurityPostureSnapshot.tenant_id == tenant_id,
                   SecurityPostureSnapshot.snapshot_date <= week_ago)
            .order_by(SecurityPostureSnapshot.snapshot_date.desc())
            .limit(1)
        )).scalar_one_or_none()
        if snap and org_risk["score"] is not None:
            risk_delta = round(org_risk["score"] - float(snap.org_risk_score), 1)
    except Exception:
        pass

    new_critical_vulns = []
    try:
        rows = (await db.execute(
            select(AssetVulnerability, Asset)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .where(AssetVulnerability.tenant_id == tenant_id, AssetVulnerability.priority == "critical")
            .limit(20)
        )).all()
        new_critical_vulns = [{"cve_id": v.cve_id, "asset_name": _asset_name(a)} for v, a in rows]
    except Exception:
        pass

    sla_breaches = []
    try:
        today = date.today()
        rows = (await db.execute(
            select(AssetVulnerability, Asset)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .where(AssetVulnerability.tenant_id == tenant_id, AssetVulnerability.status != "closed")
        )).all()
        for v, a in rows:
            deadline = getattr(v, "sla_deadline", None)
            if deadline:
                try:
                    dl = datetime.fromisoformat(str(deadline)).date()
                    if dl < today:
                        sla_breaches.append({"cve_id": v.cve_id, "asset_name": _asset_name(a)})
                except Exception:
                    pass
    except Exception:
        pass

    top_assets = []
    try:
        rows = (await db.execute(
            select(AssetRiskScore, Asset)
            .join(Asset, Asset.id == AssetRiskScore.asset_id)
            .where(AssetRiskScore.tenant_id == tenant_id)
            .order_by(AssetRiskScore.risk_score.desc())
            .limit(3)
        )).all()
        top_assets = [{"asset_name": _asset_name(a), "score": float(r.risk_score)} for r, a in rows]
    except Exception:
        pass

    return {
        "org_risk": org_risk, "risk_delta": risk_delta,
        "new_critical_vulns": new_critical_vulns,
        "sla_breaches": sla_breaches, "top_assets": top_assets,
    }


def _render_digest_html(tenant_name: str, data: dict, dashboard_url: str) -> str:
    delta = data["risk_delta"]
    delta_str = f"+{delta}" if delta is not None and delta > 0 else (str(delta) if delta is not None else "N/A")
    delta_color = "#D32F2F" if (delta or 0) > 0 else "#388E3C"
    crit_html = "".join(f"<li>{v['cve_id'] or 'Unnamed'} — {v['asset_name']}</li>" for v in data["new_critical_vulns"]) or "<li>None</li>"
    sla_html = "".join(f"<li>{b['cve_id'] or 'Unnamed'} — {b['asset_name']}</li>" for b in data["sla_breaches"]) or "<li>None</li>"
    top_html = "".join(f"<li>{a['asset_name']} (risk score: {a['score']:.1f})</li>" for a in data["top_assets"]) or "<li>None scored yet</li>"
    return f"""<html>
  <body style="font-family: Arial, sans-serif; color: #333;">
    <h2>{tenant_name} — Weekly Security Digest</h2>
    <p><strong>Risk score change this week:</strong>
       <span style="color: {delta_color};">{delta_str}</span>
       (current: {data['org_risk']['score']}, band: {data['org_risk']['band']})</p>
    <h3>New Critical Vulnerabilities</h3><ul>{crit_html}</ul>
    <h3>SLA Breaches This Week</h3><ul>{sla_html}</ul>
    <h3>Top Assets Needing Attention</h3><ul>{top_html}</ul>
    <p><a href="{dashboard_url}">View full dashboard</a></p>
  </body>
</html>"""


def _send_email_sync(smtp_host, smtp_port, smtp_user, smtp_password, from_email, recipients, subject, html_body) -> bool:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_email, recipients, msg.as_string())
        return True
    except Exception:
        logger.exception("Failed to send digest email to %s", recipients)
        return False


async def send_weekly_digest(db: AsyncSession, tenant_id, tenant_name: str, dashboard_url: str) -> dict:
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_from = os.environ.get("SMTP_FROM_EMAIL")

    if not all([smtp_host, smtp_port, smtp_user, smtp_password, smtp_from]):
        logger.warning("SMTP not configured; skipping weekly digest for tenant %s", tenant_id)
        await _log_report(db, tenant_id, "email_digest", status="skipped", recipient_count=0)
        return {"status": "skipped", "reason": "SMTP not configured", "recipient_count": 0}

    recipients = await _get_digest_recipients(db, tenant_id)
    if not recipients:
        await _log_report(db, tenant_id, "email_digest", status="skipped", recipient_count=0)
        return {"status": "skipped", "reason": "no recipients", "recipient_count": 0}

    try:
        data = await _build_digest_data(db, tenant_id)
        html_body = _render_digest_html(tenant_name, data, dashboard_url)
    except Exception:
        logger.exception("Failed to build digest content for tenant %s", tenant_id)
        await _log_report(db, tenant_id, "email_digest", status="failed", recipient_count=len(recipients))
        return {"status": "failed", "reason": "content build failed", "recipient_count": len(recipients)}

    import asyncio
    sent = False
    try:
        sent = await asyncio.to_thread(
            _send_email_sync, smtp_host, smtp_port, smtp_user, smtp_password,
            smtp_from, recipients, f"{tenant_name} — Weekly Security Digest", html_body,
        )
    except Exception:
        logger.exception("Unexpected error sending digest for tenant %s", tenant_id)

    status_str = "success" if sent else "failed"
    await _log_report(db, tenant_id, "email_digest", status=status_str, recipient_count=len(recipients))
    return {"status": status_str, "recipient_count": len(recipients)}


# =============================================================================
# 3. COMPLIANCE EVIDENCE EXPORT
# =============================================================================

async def _get_full_vulnerability_register(db: AsyncSession, tenant_id) -> list[dict]:
    try:
        rows = (await db.execute(
            select(AssetVulnerability, Asset)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .where(AssetVulnerability.tenant_id == tenant_id, AssetVulnerability.status != "closed")
        )).all()
    except Exception:
        logger.exception("Failed to fetch vulnerability register for tenant %s", tenant_id)
        return []
    return [
        {
            "cve_id": v.cve_id, "asset_id": str(v.asset_id), "asset_name": _asset_name(a),
            "priority": v.priority, "status": v.status,
            "affected_component": getattr(v, "affected_component", None),
            "affected_version": getattr(v, "affected_version", None),
            "sla_deadline": str(v.sla_deadline) if getattr(v, "sla_deadline", None) else None,
        }
        for v, a in rows
    ]


async def _get_all_risk_scores(db: AsyncSession, tenant_id) -> dict:
    org_risk = await _get_org_risk(db, tenant_id)
    asset_scores = []
    try:
        rows = (await db.execute(
            select(AssetRiskScore, Asset)
            .join(Asset, Asset.id == AssetRiskScore.asset_id)
            .where(AssetRiskScore.tenant_id == tenant_id)
        )).all()
        asset_scores = [{"asset_id": str(a.id), "asset_name": _asset_name(a), "score": float(r.risk_score)} for r, a in rows]
    except Exception:
        pass
    return {"org_risk": org_risk, "asset_risk_scores": asset_scores}


async def _get_access_audit_30d(db: AsyncSession, tenant_id) -> list[dict]:
    try:
        since = datetime.now(timezone.utc) - timedelta(days=30)
        rows = (await db.execute(
            select(AccessAuditLog)
            .where(AccessAuditLog.tenant_id == tenant_id, AccessAuditLog.accessed_at >= since)
            .order_by(AccessAuditLog.accessed_at.desc())
            .limit(50000)
        )).scalars().all()
    except Exception:
        logger.exception("Failed to fetch access audit log for tenant %s", tenant_id)
        return []
    return [
        {
            "user_id": str(r.user_id) if r.user_id else None,
            "user_role": r.user_role, "endpoint": r.endpoint, "method": r.method,
            "ip_address": r.ip_address, "status_code": r.status_code,
            "accessed_at": r.accessed_at.isoformat(),
        }
        for r in rows
    ]


async def _get_posture_snapshots_12w(db: AsyncSession, tenant_id) -> list[dict]:
    try:
        rows = (await db.execute(
            select(SecurityPostureSnapshot)
            .where(SecurityPostureSnapshot.tenant_id == tenant_id)
            .order_by(SecurityPostureSnapshot.snapshot_date.desc())
            .limit(12)
        )).scalars().all()
    except Exception:
        return []
    return [
        {
            "snapshot_date": r.snapshot_date.isoformat(),
            "org_risk_score": float(r.org_risk_score),
            "open_critical_vulns": r.open_critical_vulns,
            "open_high_vulns": r.open_high_vulns,
            "sla_compliance_rate": float(r.sla_compliance_rate),
            "assets_scanned": r.assets_scanned,
            "assets_with_exposures": r.assets_with_exposures,
            "total_simulation_findings": r.total_simulation_findings,
        }
        for r in rows
    ]


async def _get_pii_findings_full(db: AsyncSession, tenant_id) -> list[dict]:
    try:
        rows = (await db.execute(
            select(DataProtectionFinding).where(DataProtectionFinding.tenant_id == tenant_id)
        )).scalars().all()
    except Exception:
        return []
    return [
        {
            "source_table": r.source_table, "source_record_id": str(r.source_record_id),
            "source_field": r.source_field, "pii_type": r.pii_type, "pii_sample": r.pii_sample,
            "severity": r.severity, "detected_at": r.detected_at.isoformat(), "is_resolved": r.is_resolved,
        }
        for r in rows
    ]


async def generate_compliance_export(db: AsyncSession, tenant_id, tenant_name: str, generated_by=None) -> str:
    sections: dict = {}
    for key, fn, kwargs in [
        ("asset_inventory", _get_asset_inventory, {"full_detail": True}),
        ("vulnerability_register", _get_full_vulnerability_register, {}),
        ("risk_scores", _get_all_risk_scores, {}),
        ("simulation_findings", _get_simulation_findings, {"limit": 10000}),
        ("access_audit", _get_access_audit_30d, {}),
        ("posture_snapshots", _get_posture_snapshots_12w, {}),
        ("pii_findings", _get_pii_findings_full, {}),
    ]:
        try:
            sections[key] = await fn(db, tenant_id, **kwargs)
        except Exception:
            logger.exception("Compliance export section '%s' failed for tenant %s", key, tenant_id)
            sections[key] = [] if key != "risk_scores" else {}

    sections["report_metadata"] = {
        "tenant_id": str(tenant_id),
        "tenant_name": tenant_name,
        "export_date": datetime.now(timezone.utc).isoformat(),
        "scope": "Full tenant evidence export for compliance audit (ISO 27001 / SOC 2 / NIST CSF)",
        "sections_included": [k for k in sections if k != "report_metadata"],
    }

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_path = tmp.name
    tmp.close()

    filenames = {
        "asset_inventory": "evidence/asset_inventory.json",
        "vulnerability_register": "evidence/vulnerability_register.json",
        "risk_scores": "evidence/risk_scores.json",
        "simulation_findings": "evidence/simulation_findings.json",
        "access_audit": "evidence/access_audit.json",
        "posture_snapshots": "evidence/posture_snapshots.json",
        "pii_findings": "evidence/pii_findings.json",
        "report_metadata": "evidence/report_metadata.json",
    }

    with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for key, arcname in filenames.items():
            try:
                zf.writestr(arcname, json.dumps(sections.get(key, []), default=_decimal_default, indent=2))
            except Exception:
                logger.exception("Failed to write %s into compliance ZIP for tenant %s", arcname, tenant_id)

    file_size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
    await _log_report(db, tenant_id, "compliance_export", generated_by, file_size_bytes=file_size)
    return tmp_path


# =============================================================================
# 4. REPORT HISTORY
# =============================================================================

async def get_report_history(db: AsyncSession, tenant_id, limit: int = 50) -> list[dict]:
    try:
        rows = (await db.execute(
            select(ReportLog)
            .where(ReportLog.tenant_id == tenant_id)
            .order_by(ReportLog.generated_at.desc())
            .limit(limit)
        )).scalars().all()
    except Exception:
        logger.exception("Failed to fetch report history for tenant %s", tenant_id)
        return []
    return [
        {
            "id": str(r.id), "report_type": r.report_type,
            "generated_by": str(r.generated_by) if r.generated_by else None,
            "generated_at": r.generated_at.isoformat(),
            "file_size_bytes": r.file_size_bytes,
            "recipient_count": r.recipient_count,
            "status": r.status,
        }
        for r in rows
    ]
