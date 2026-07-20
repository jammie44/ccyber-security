"""
Discovery module schemas.
Pydantic models for network scan requests and responses.
"""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_network
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    ip_range: str = Field(..., description="CIDR range to scan, e.g. 192.168.1.0/24")
    ports: Optional[str] = Field(
        default="21-23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443",
        description="Nmap port spec. Defaults to common ports for speed.",
    )
    fast: bool = Field(
        default=True,
        description="If true, uses -T4 -F (fast). If false, uses -A (OS detection, slower).",
    )

    @field_validator("ip_range")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            net = ip_network(v, strict=False)
            # Prevent scanning huge ranges that would time out
            if net.num_addresses > 1024:
                raise ValueError("Range too large — maximum /22 (1024 hosts) per scan")
        except ValueError as e:
            raise ValueError(f"Invalid CIDR range '{v}': {e}")
        return v


class OpenPort(BaseModel):
    port: int
    protocol: str       # tcp / udp
    state: str          # open / closed / filtered
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class DiscoveredDevice(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    status: str = "up"
    open_ports: List[OpenPort] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanResponse(BaseModel):
    ip_range: str
    devices_found: int
    devices: List[DiscoveredDevice]
    scan_duration_seconds: float
    assets_created: int
    assets_updated: int


class IngestRequest(BaseModel):
    """
    Used by the on-premises agent to POST results back to the platform
    after scanning a local network that Render cannot reach directly.
    """
    ip_range: str
    devices: List[DiscoveredDevice]
    scan_duration_seconds: float
