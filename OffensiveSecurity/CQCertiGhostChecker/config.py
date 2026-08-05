"""
CertiConfig — configuration for CQCertiGhostChecker (CVE-2026-54121).
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class CertiConfig:
    domain: str = ""
    username: str = ""
    password: str = ""
    dc_ip: str = ""
    ca_name: Optional[str] = None
    target_dc: Optional[str] = None
    machine_account_name: str = "ATTACKER$"
    ca_ip: Optional[str] = None
    ldap_port: int = 389
    template: str = "Machine"
    machine_account_ou: str = "CN=Computers"
    output_file: str = "dc.ccache"
    verbose: bool = False
    dry_run: bool = False
