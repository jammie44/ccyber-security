"""
exposure_check.py
Verifies that ports the scanner (Module 1) recorded as open are actually
reachable, and flags mismatches. This is a plain TCP connect() attempt —
no data is sent, no protocol handshake beyond the initial SYN/ACK.

Place in: app/services/attack_simulation/exposure_check.py
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 3.0  # seconds


@dataclass
class ExposureFinding:
    target_port: int
    finding_title: str
    finding_detail: str
    severity: str
    was_successful: bool  # True = port confirmed reachable as expected
    context_data: dict


async def _port_reachable(host: str, port: int) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=CONNECT_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug("Port %s:%s not reachable: %s", host, port, e)
        return False
    except Exception:
        logger.exception("Unexpected error checking %s:%s", host, port)
        return False


async def validate_exposure(
    host: str, open_ports: list[int], asset_marked_internet_facing: bool
) -> list[ExposureFinding]:
    """
    For each port the discovery scan (Module 1) reported as open, attempts
    a real connection from wherever this service is running and compares
    against expectations. Every attempt is individually try/except'd so
    one hung/refused connection never aborts the batch.

    NOTE ON DEPLOYMENT: this check is only meaningful for "internet-facing"
    validation if the process running it has a real path from the public
    internet to the target (i.e. it should run from a host outside the
    target's network, same constraint discussed in Module 1). If this
    runs from inside the same LAN as the asset, "reachable" will be true
    regardless of whether the asset is actually internet-facing --
    treat results accordingly and log where the check was run from.
    """
    findings: list[ExposureFinding] = []
    if not host:
        return findings

    results = await asyncio.gather(
        *[_port_reachable(host, port) for port in open_ports],
        return_exceptions=False,
    )

    for port, reachable in zip(open_ports, results):
        if asset_marked_internet_facing and not reachable:
            findings.append(
                ExposureFinding(
                    target_port=port,
                    finding_title=f"Port {port} recorded as open but not reachable",
                    finding_detail=(
                        f"Asset is marked internet-facing and discovery scan recorded port {port} "
                        f"as open, but a live connection attempt from this simulation could not "
                        f"reach it. This may indicate the port was closed since the last scan, a "
                        f"firewall/NAT rule changed, or scan data is stale."
                    ),
                    severity="low",
                    was_successful=False,
                    context_data={"expected_open": True, "actually_reachable": False},
                )
            )
        elif not asset_marked_internet_facing and reachable:
            findings.append(
                ExposureFinding(
                    target_port=port,
                    finding_title=f"Port {port} unexpectedly reachable from outside",
                    finding_detail=(
                        f"Asset is NOT marked internet-facing, but port {port} responded to a "
                        f"connection attempt. This may indicate an unintended firewall rule, "
                        f"port-forward, or incorrect internet-facing classification."
                    ),
                    severity="high",
                    was_successful=True,
                    context_data={"expected_open": False, "actually_reachable": True},
                )
            )
        # Cases that match expectations (internet-facing+reachable, or
        # internal+unreachable) are not findings -- nothing to flag.

    return findings
