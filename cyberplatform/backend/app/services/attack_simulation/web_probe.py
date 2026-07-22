"""
web_probe.py
Passive web checks: looks for commonly-exposed paths, missing security
headers, and TLS certificate issues. Every request is a plain GET/HEAD —
nothing here attempts authentication, injects payloads, or modifies
anything on the target.

Place in: app/services/attack_simulation/web_probe.py
"""
from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 3.0  # seconds, per requirement

# Paths that commonly indicate an exposed admin surface or leaked config.
# We only check for existence (status code), never submit data.
PROBE_PATHS = [
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/adminer",
    "/.env",
    "/config.php",
    "/backup",
    "/api/swagger",
    "/swagger-ui.html",
    "/.git/config",
]

REQUIRED_HEADERS = {
    "x-frame-options": "Clickjacking protection missing (X-Frame-Options).",
    "content-security-policy": "No Content-Security-Policy set; increases XSS blast radius.",
    "x-content-type-options": "X-Content-Type-Options missing; browser may MIME-sniff responses.",
    "strict-transport-security": "HSTS missing; browser won't enforce HTTPS on repeat visits.",
}


@dataclass
class WebFinding:
    target_port: int
    finding_title: str
    finding_detail: str
    severity: str  # critical/high/medium/low
    was_successful: bool  # True only for "the exposure is confirmed present"
    context_data: dict


def _base_url(ip_or_host: str, port: int) -> str:
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{ip_or_host}:{port}"


async def _check_paths(client: httpx.AsyncClient, base_url: str, port: int) -> list[WebFinding]:
    findings: list[WebFinding] = []
    for path in PROBE_PATHS:
        url = base_url + path
        try:
            resp = await client.get(url, timeout=CONNECT_TIMEOUT, follow_redirects=False)
        except Exception as e:
            logger.info("Path probe %s failed (treated as not-exposed): %s", url, e)
            continue

        # A 200 (or 401/403, which still confirms the path exists and is
        # handled specially rather than 404ing) suggests something is there.
        if resp.status_code in (200, 401, 403):
            exposed = resp.status_code == 200
            findings.append(
                WebFinding(
                    target_port=port,
                    finding_title=f"Potentially sensitive path reachable: {path}",
                    finding_detail=(
                        f"GET {url} returned HTTP {resp.status_code}. "
                        f"{'Path is directly accessible without authentication.' if exposed else 'Path exists but appears to require authentication.'}"
                    ),
                    severity="high" if exposed else "medium",
                    was_successful=exposed,
                    context_data={"path": path, "status_code": resp.status_code, "url": url},
                )
            )
        logger.debug("Probed %s -> %s", url, resp.status_code)
    return findings


async def _check_headers(client: httpx.AsyncClient, base_url: str, port: int) -> list[WebFinding]:
    findings: list[WebFinding] = []
    try:
        resp = await client.get(base_url + "/", timeout=CONNECT_TIMEOUT, follow_redirects=True)
    except Exception as e:
        logger.info("Header check failed for %s: %s", base_url, e)
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header, explanation in REQUIRED_HEADERS.items():
        if header not in headers_lower:
            findings.append(
                WebFinding(
                    target_port=port,
                    finding_title=f"Missing security header: {header}",
                    finding_detail=explanation,
                    severity="medium",
                    was_successful=True,  # "successful" = confirmed the gap exists
                    context_data={"missing_header": header, "url": base_url},
                )
            )
    return findings


def _check_tls(host: str, port: int) -> list[WebFinding]:
    """Synchronous — ssl/socket don't have great async equivalents in stdlib.
    Called via asyncio.to_thread from the orchestrator to avoid blocking."""
    findings: list[WebFinding] = []
    if port != 443:
        return findings

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
    except Exception as e:
        logger.info("TLS check failed for %s:%s -> %s", host, port, e)
        return findings

    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append(
            WebFinding(
                target_port=port,
                finding_title=f"Outdated TLS version in use: {tls_version}",
                finding_detail=f"Server negotiated {tls_version}, which is deprecated and vulnerable to known downgrade/cipher attacks.",
                severity="high",
                was_successful=True,
                context_data={"tls_version": tls_version},
            )
        )

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            if days_left < 0:
                findings.append(
                    WebFinding(
                        target_port=port,
                        finding_title="TLS certificate has expired",
                        finding_detail=f"Certificate expired on {expiry.isoformat()} ({abs(days_left)} days ago).",
                        severity="critical",
                        was_successful=True,
                        context_data={"expired_on": expiry.isoformat()},
                    )
                )
            elif days_left <= 30:
                findings.append(
                    WebFinding(
                        target_port=port,
                        finding_title="TLS certificate expiring soon",
                        finding_detail=f"Certificate expires {expiry.isoformat()} ({days_left} days remaining).",
                        severity="medium",
                        was_successful=True,
                        context_data={"expires_on": expiry.isoformat(), "days_left": days_left},
                    )
                )
        except ValueError:
            logger.warning("Could not parse certificate expiry '%s' for %s:%s", not_after, host, port)

    return findings


async def probe_web_service(host: str, port: int) -> list[WebFinding]:
    """
    Runs all web checks against host:port. Every sub-check is wrapped so
    one failure (timeout, connection refused, TLS error) never aborts
    the others.
    """
    if not host:
        return []

    base_url = _base_url(host, port)
    findings: list[WebFinding] = []

    async with httpx.AsyncClient(verify=False) as client:  # noqa: S501 -- intentionally lenient; we're probing, not trusting the target
        try:
            findings.extend(await _check_paths(client, base_url, port))
        except Exception:
            logger.exception("Path probing crashed for %s", base_url)

        try:
            findings.extend(await _check_headers(client, base_url, port))
        except Exception:
            logger.exception("Header check crashed for %s", base_url)

    if port == 443:
        try:
            import asyncio
            findings.extend(await asyncio.to_thread(_check_tls, host, port))
        except Exception:
            logger.exception("TLS check crashed for %s:%s", host, port)

    return findings
