"""
scanner_service.py
Core network discovery logic using python-nmap.

DEPLOYMENT NOTE:
nmap cannot reach private LAN ranges (192.168.x.x) from Render's cloud.
Two ways to use this:
  1. Run the FastAPI app locally on a machine on your target network
     and hit POST /api/v1/discovery/scan directly.
  2. Use the lightweight agent script (agent/scanner_agent.py) on any
     machine on the target network — it scans locally and POSTs results
     back to POST /api/v1/discovery/ingest on your Render deployment.
"""
from __future__ import annotations

import logging
import time
from typing import List, Tuple

from .schemas import DiscoveredDevice, OpenPort

logger = logging.getLogger(__name__)


class ScannerError(Exception):
    """Raised when nmap fails or is not installed on this host."""


class NetworkScanner:
    def __init__(self):
        try:
            import nmap
            self._nm = nmap.PortScanner()
            self._nmap = nmap
        except ImportError:
            raise ScannerError(
                "python-nmap is not installed. Run: pip install python-nmap"
            )
        except Exception as e:
            raise ScannerError(
                f"nmap binary not found on this host. "
                f"Install nmap first: sudo apt-get install nmap (Linux) "
                f"or brew install nmap (macOS). Error: {e}"
            )

    def scan(
        self, ip_range: str, ports: str, fast: bool = True
    ) -> Tuple[List[DiscoveredDevice], float]:
        """
        Scans ip_range and returns (discovered_devices, duration_seconds).

        fast=True  -> -T4 -F --open       (quick, no root needed)
        fast=False -> -T4 -A --open       (OS detection, needs root/CAP_NET_RAW)
        """
        start = time.monotonic()
        arguments = f"-T4 -F --open -p {ports}" if fast else f"-T4 -A --open -p {ports}"

        logger.info("Starting nmap scan: %s args='%s'", ip_range, arguments)

        try:
            self._nm.scan(hosts=ip_range, arguments=arguments)
        except Exception as e:
            raise ScannerError(f"nmap scan failed: {e}") from e

        devices: List[DiscoveredDevice] = []

        for host in self._nm.all_hosts():
            host_data = self._nm[host]
            if host_data.state() != "up":
                continue

            # Hostname
            hostname = None
            if host_data.hostnames():
                names = [h["name"] for h in host_data.hostnames() if h.get("name")]
                hostname = names[0] if names else None

            # MAC and vendor
            mac_address = vendor = None
            if "mac" in host_data.get("addresses", {}):
                mac_address = host_data["addresses"]["mac"]
                vendor = host_data.get("vendor", {}).get(mac_address)

            # OS detection (only available with -A / root)
            os_name = os_accuracy = None
            if host_data.get("osmatch"):
                best = host_data["osmatch"][0]
                os_name = best.get("name")
                try:
                    os_accuracy = int(best.get("accuracy", 0))
                except (TypeError, ValueError):
                    pass

            # Open ports
            open_ports: List[OpenPort] = []
            for proto in ("tcp", "udp"):
                if proto not in host_data:
                    continue
                for port_num, port_info in host_data[proto].items():
                    if port_info.get("state") != "open":
                        continue
                    open_ports.append(OpenPort(
                        port=int(port_num),
                        protocol=proto,
                        state=port_info.get("state", "open"),
                        service=port_info.get("name") or None,
                        product=port_info.get("product") or None,
                        version=port_info.get("version") or None,
                    ))

            devices.append(DiscoveredDevice(
                ip_address=host,
                hostname=hostname,
                mac_address=mac_address,
                vendor=vendor,
                os_name=os_name,
                os_accuracy=os_accuracy,
                status="up",
                open_ports=open_ports,
            ))

        duration = time.monotonic() - start
        logger.info("Scan complete: %d hosts in %.2fs", len(devices), duration)
        return devices, duration


# Module-level singleton — one PortScanner per process
_scanner: NetworkScanner | None = None


def get_scanner() -> NetworkScanner:
    global _scanner
    if _scanner is None:
        _scanner = NetworkScanner()
    return _scanner


def is_nmap_available() -> bool:
    """Returns True if nmap is installed and functional on this host."""
    try:
        get_scanner()
        return True
    except ScannerError:
        return False
