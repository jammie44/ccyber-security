#!/usr/bin/env python3
"""
CyberPlatform On-Premises Scanner Agent
========================================
Run this on any machine that is physically connected to the network
you want to scan (your office WiFi, home network, client LAN etc.).

It scans the network using nmap, then POSTs the results to your
CyberPlatform deployment on Render so assets appear in the dashboard.

SETUP (one time):
  1. Install nmap:
       Linux:  sudo apt-get install nmap
       macOS:  brew install nmap
       Windows: https://nmap.org/download.html

  2. Install Python dependencies:
       pip install python-nmap requests

  3. Get your JWT token:
       Log into your CyberPlatform website
       Open browser developer tools (F12)
       Go to Application tab -> Local Storage -> your site URL
       Copy the value of accessToken from cyberplatform-auth

USAGE:
  # Scan your local WiFi network (most common home/office range):
  python scanner_agent.py --range 192.168.1.0/24 --api-url https://cyberplatform-api.onrender.com --token YOUR_JWT_TOKEN

  # Scan a different range:
  python scanner_agent.py --range 10.0.0.0/24 --api-url https://cyberplatform-api.onrender.com --token YOUR_JWT_TOKEN

  # Full scan with OS detection (needs sudo/admin):
  sudo python scanner_agent.py --range 192.168.1.0/24 --api-url https://cyberplatform-api.onrender.com --token YOUR_JWT_TOKEN --full

  # Find your network range first (if you don't know it):
  #   Linux/macOS: ip route  OR  ifconfig
  #   Windows:     ipconfig
  #   Look for your IP like 192.168.1.x — your range is 192.168.1.0/24
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("cyberplatform-agent")


def check_nmap_installed() -> bool:
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def scan_network(ip_range: str, ports: str, full_scan: bool = False) -> tuple[list, float]:
    """Scan the network using python-nmap and return discovered devices."""
    try:
        import nmap
    except ImportError:
        logger.error("python-nmap not installed. Run: pip install python-nmap")
        sys.exit(1)

    nm = nmap.PortScanner()
    arguments = f"-T4 -A --open -p {ports}" if full_scan else f"-T4 -F --open -p {ports}"

    logger.info("Scanning %s with args: %s", ip_range, arguments)
    logger.info("This may take 30-90 seconds for a /24 range...")

    start = time.monotonic()
    try:
        nm.scan(hosts=ip_range, arguments=arguments)
    except Exception as e:
        logger.error("Scan failed: %s", e)
        sys.exit(1)

    devices = []
    for host in nm.all_hosts():
        host_data = nm[host]
        if host_data.state() != "up":
            continue

        hostname = None
        if host_data.hostnames():
            names = [h["name"] for h in host_data.hostnames() if h.get("name")]
            hostname = names[0] if names else None

        # Try reverse DNS if nmap didn't get a hostname
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception:
                pass

        mac_address = vendor = None
        if "mac" in host_data.get("addresses", {}):
            mac_address = host_data["addresses"]["mac"]
            vendor = host_data.get("vendor", {}).get(mac_address)

        os_name = os_accuracy = None
        if host_data.get("osmatch"):
            best = host_data["osmatch"][0]
            os_name = best.get("name")
            try:
                os_accuracy = int(best.get("accuracy", 0))
            except (TypeError, ValueError):
                pass

        open_ports = []
        for proto in ("tcp", "udp"):
            if proto not in host_data:
                continue
            for port_num, port_info in host_data[proto].items():
                if port_info.get("state") != "open":
                    continue
                open_ports.append({
                    "port": int(port_num),
                    "protocol": proto,
                    "state": port_info.get("state", "open"),
                    "service": port_info.get("name") or None,
                    "product": port_info.get("product") or None,
                    "version": port_info.get("version") or None,
                })

        devices.append({
            "ip_address": host,
            "hostname": hostname,
            "mac_address": mac_address,
            "vendor": vendor,
            "os_name": os_name,
            "os_accuracy": os_accuracy,
            "status": "up",
            "open_ports": open_ports,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        })

        logger.info(
            "Found: %s%s%s — %d open ports",
            host,
            f" ({hostname})" if hostname else "",
            f" [{os_name}]" if os_name else "",
            len(open_ports),
        )

    duration = time.monotonic() - start
    logger.info("Scan complete: %d hosts found in %.1f seconds", len(devices), duration)
    return devices, duration


def post_results(api_url: str, token: str, ip_range: str, devices: list, duration: float) -> dict:
    """POST scan results to the CyberPlatform API."""
    try:
        import requests
    except ImportError:
        logger.error("requests not installed. Run: pip install requests")
        sys.exit(1)

    payload = {
        "ip_range": ip_range,
        "devices": devices,
        "scan_duration_seconds": round(duration, 2),
    }

    url = f"{api_url.rstrip('/')}/api/v1/discovery/ingest"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    logger.info("Sending %d devices to %s...", len(devices), url)

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to %s — is the API URL correct?", api_url)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        logger.error("API returned error %s: %s", response.status_code, response.text)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="CyberPlatform Network Scanner Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner_agent.py --range 192.168.1.0/24 --api-url https://cyberplatform-api.onrender.com --token eyJ...
  python scanner_agent.py --range 10.0.0.0/24 --api-url https://cyberplatform-api.onrender.com --token eyJ... --full
        """
    )
    parser.add_argument("--range", required=True, help="IP range to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--api-url", required=True, help="Your CyberPlatform API URL, e.g. https://cyberplatform-api.onrender.com")
    parser.add_argument("--token", required=True, help="Your JWT access token (from browser local storage after login)")
    parser.add_argument("--ports", default="21-23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443", help="Ports to scan")
    parser.add_argument("--full", action="store_true", help="Full scan with OS detection (requires sudo/admin)")
    parser.add_argument("--dry-run", action="store_true", help="Scan but don't send to API — just print results")
    args = parser.parse_args()

    # Check nmap is installed
    if not check_nmap_installed():
        logger.error("nmap is not installed on this machine.")
        logger.error("Install it with:")
        logger.error("  Linux:   sudo apt-get install nmap")
        logger.error("  macOS:   brew install nmap")
        logger.error("  Windows: https://nmap.org/download.html")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("CyberPlatform Network Scanner Agent")
    logger.info("=" * 60)
    logger.info("Target range: %s", args.range)
    logger.info("API URL:      %s", args.api_url)
    logger.info("Scan mode:    %s", "Full (OS detection)" if args.full else "Fast")
    logger.info("=" * 60)

    # Scan
    devices, duration = scan_network(args.range, args.ports, args.full)

    if not devices:
        logger.warning("No devices found. Check that:")
        logger.warning("  1. Your --range matches your actual network (run 'ip route' or 'ipconfig')")
        logger.warning("  2. You are connected to the network you want to scan")
        logger.warning("  3. Your firewall is not blocking nmap")
        return

    # Print results
    logger.info("")
    logger.info("DISCOVERED DEVICES:")
    logger.info("-" * 60)
    for d in devices:
        ports_str = ", ".join(str(p["port"]) for p in d["open_ports"][:5])
        if len(d["open_ports"]) > 5:
            ports_str += f" +{len(d['open_ports'])-5} more"
        logger.info(
            "%-16s %-30s %-20s Ports: %s",
            d["ip_address"],
            (d["hostname"] or "unknown")[:30],
            (d["os_name"] or "unknown OS")[:20],
            ports_str or "none",
        )
    logger.info("-" * 60)

    if args.dry_run:
        logger.info("Dry run — not sending to API. Results above.")
        print(json.dumps(devices, indent=2))
        return

    # Send to API
    result = post_results(args.api_url, args.token, args.range, devices, duration)

    logger.info("")
    logger.info("=" * 60)
    logger.info("RESULTS SENT TO CYBERPLATFORM:")
    logger.info("  Devices found:   %d", result.get("devices_found", len(devices)))
    logger.info("  Assets created:  %d (new devices added to inventory)", result.get("assets_created", 0))
    logger.info("  Assets updated:  %d (existing devices refreshed)", result.get("assets_updated", 0))
    logger.info("=" * 60)
    logger.info("Open your CyberPlatform dashboard to see the discovered assets.")
    logger.info("URL: %s", args.api_url.replace("-api.", "-web.").replace("onrender.com", "onrender.com"))


if __name__ == "__main__":
    main()
