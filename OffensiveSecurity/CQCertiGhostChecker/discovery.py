"""
Discovery module -- AD infrastructure discovery (CA, DC, SID, GUID).

Connects via LDAP to a Domain Controller and enumerates:
- Enterprise CA (objectClass=certificationAuthority)
- Domain Controller (SERVER_TRUST_ACCOUNT in userAccountControl)
- Domain SID and GUID from root DSE
"""

import logging
from typing import Any

logger = logging.getLogger("certighost.discovery")

# userAccountControl bit: SERVER_TRUST_ACCOUNT = 8192
UAC_SERVER_TRUST_ACCOUNT = 8192


def _build_search_base(domain: str) -> str:
    """Build LDAP search base from domain name (e.g. 'cqure.lab' -> 'DC=cqure,DC=lab')."""
    return ",".join([f"DC={part}" for part in domain.split(".")])


async def discover_ad(
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
) -> dict[str, Any]:
    """
    Discover AD infrastructure via LDAP.

    Returns:
        dict with keys: ca, dc, domain_sid, domain_guid, ca_dn, dc_dn, dc_dns_hostname
    """
    logger.debug(f"Connecting to LDAP at ldap://{dc_ip}/{domain}")

    try:
        from ldap3 import Server, Connection, NTLM, SUBTREE

        server = Server(f"ldap://{dc_ip}", get_info=None)
        # NTLM requires domain\username; chr(92) avoids escape sequence issues
        bind_dn = f"{domain}{chr(92)}{username}"
        conn = Connection(server, user=bind_dn, password=password, authentication=NTLM)
        conn.auto_referrals = False  # Disable referrals to avoid RecursionError
        conn.bind()

        if not conn.result["result"] == 0:
            raise ConnectionError(
                f"LDAP bind failed: {conn.result['message']} "
                f"(code={conn.result['result']})"
            )

        logger.debug("LDAP bind successful")

        # ========================================
        # Discover Domain Controller
        # ========================================
        logger.debug("Searching for Domain Controllers...")
        search_base = _build_search_base(domain)
        logger.debug(f"Search base: {search_base}")

        dc_filter_computer = (
            "(&(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        )

        conn.search(
            search_base=search_base,
            search_filter=dc_filter_computer,
            search_scope=SUBTREE,
            attributes=["dNSHostName", "objectSid", "objectClass", "distinguishedName",
                         "userAccountControl", "servicePrincipalName"],
        )

        dc_entries = conn.entries
        logger.debug(f"Found {len(dc_entries)} computer entries")
        
        if not dc_entries:
            # Fallback: search root DSE
            logger.debug("No DC found, trying root DSE...")
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["defaultNamingContext", "rootDomainNamingContext"],
            )
            raise ConnectionError(
                f"No Domain Controller found in {domain}. "
                f"Entries: {len(dc_entries)}, Filter: {dc_filter_computer}"
            )

        dc_entry = dc_entries[0]
        sid_raw = dc_entry.objectSid.value
        dc_info = {
            "dn": str(dc_entry.distinguishedName.value),
            "dns_hostname": str(dc_entry.dNSHostName.value),
            "sid": _parse_sid(sid_raw),
            "sid_bin": sid_raw if isinstance(sid_raw, bytes) else sid_raw.encode("utf-8"),
            "uac": int(dc_entry.userAccountControl.value),
            "spns": [str(spn) for spn in dc_entry.servicePrincipalName.values]
                     if hasattr(dc_entry, "servicePrincipalName") and dc_entry.servicePrincipalName
                     else [],
        }
        logger.debug(f"DC found: {dc_info['dns_hostname']} ({dc_info['dn']})")
        logger.debug(f"DC SID: {dc_info['sid']}")
        logger.debug(f"DC UAC: {dc_info['uac']} (SERVER_TRUST_ACCOUNT={bool(dc_info['uac'] & UAC_SERVER_TRUST_ACCOUNT)})")

        # ========================================
        # Discover Enterprise CA
        # ========================================
        logger.debug("Searching for Enterprise CA (pKIEnrollmentService)...")
        enroll_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{search_base}"
        conn.search(
            search_base=enroll_base,
            search_filter="(objectClass=pKIEnrollmentService)",
            search_scope=SUBTREE,
            attributes=["cn", "distinguishedName", "dNSHostName",
                         "certificateTemplates"],
        )

        ca_entries = conn.entries
        if not ca_entries:
            logger.debug("No pKIEnrollmentService found, falling back to certificationAuthority...")
            conn.search(
                search_base=f"CN=Configuration,{search_base}",
                search_filter="(objectClass=certificationAuthority)",
                search_scope=SUBTREE,
                attributes=["name", "distinguishedName", "dNSHostName"],
            )
            ca_entries = conn.entries

        ca_info = {}
        if ca_entries:
            ca_entry = ca_entries[0]
            ca_name_attr = (
                str(ca_entry.cn.value) if hasattr(ca_entry, "cn") and ca_entry.cn
                else str(ca_entry.name.value) if hasattr(ca_entry, "name") and ca_entry.name
                else "ADCS"
            )
            ca_info = {
                "dn": str(ca_entry.distinguishedName.value),
                "name": ca_name_attr,
                "dns_hostname": str(ca_entry.dNSHostName.value)
                    if hasattr(ca_entry, "dNSHostName") and ca_entry.dNSHostName
                    else None,
            }
            logger.debug(f"CA found: {ca_info['name']} (host: {ca_info['dns_hostname'] or 'unknown'})")
        else:
            ca_info = {
                "dn": f"CN=ADCS,CN=Public Key Services,CN=Services,CN=Configuration,{search_base}",
                "name": "ADCS",
                "dns_hostname": None,
            }
            logger.debug("CA using default values")

        # ========================================
        # Read domain SID and GUID from root DSE
        # ========================================
        logger.debug("Reading domain SID and GUID from root DSE...")
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["defaultNamingContext", "rootDomainNamingContext",
                         "forestFunctionality", "domainFunctionality"],
        )

        root_dse = conn.entries[0] if conn.entries else None
        domain_sid = _extract_domain_sid(dc_info["sid"])

        # Query domain object for objectGUID (root DSE doesn't carry it)
        domain_guid = "00000000-0000-0000-0000-000000000000"
        conn.search(
            search_base=search_base,
            search_filter="(objectClass=domain)",
            search_scope="BASE",
            attributes=["objectGUID"],
        )
        if conn.entries:
            domain_guid = _extract_domain_guid(conn.entries[0])

        conn.unbind()

        result = {
            "ca": ca_info,
            "dc": dc_info,
            "domain_sid": domain_sid,
            "domain_guid": domain_guid,
            "ca_dn": ca_info["dn"],
            "dc_dn": dc_info["dn"],
            "dc_dns_hostname": dc_info["dns_hostname"],
        }

        logger.debug(f"Discovery complete. Domain SID: {domain_sid}, GUID: {domain_guid}")
        return result

    except ImportError as e:
        raise ImportError(
            f"LDAP dependency missing: {e}. "
            f"Install with: pip install ldap3"
        ) from e
    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        raise


def _parse_sid(sid_value) -> str:
    """Parse SID from LDAP entry (bytes or str) to string format."""
    if isinstance(sid_value, str):
        return sid_value  # ldap3 already parsed it
    if isinstance(sid_value, bytes):
        import struct
        rev = sid_value[0]
        sub_cnt = sid_value[1]
        auth = int.from_bytes(sid_value[2:8], "big")
        subs = struct.unpack_from(f"<{sub_cnt}I", sid_value, 8)
        return f"S-{rev}-{auth}-" + "-".join(str(s) for s in subs)
    return str(sid_value)


def _extract_domain_sid(dc_sid: str) -> str:
    """Extract domain SID from DC SID by stripping the RID (last component)."""
    if dc_sid and "-" in dc_sid:
        parts = dc_sid.rsplit("-", 1)
        if len(parts) == 2:
            return parts[0]
    return dc_sid


def _extract_domain_guid(domain_entry) -> str:
    """Extract domain GUID from the domain object (objectGUID attribute)."""
    if domain_entry and hasattr(domain_entry, "objectGUID") and domain_entry.objectGUID:
        guid_val = domain_entry.objectGUID.value
        if isinstance(guid_val, str):
            return guid_val  # ldap3 already formatted it
        if isinstance(guid_val, bytes) and len(guid_val) == 16:
            import struct
            # Microsoft GUID binary layout: first 3 groups are little-endian,
            # last 2 groups are big-endian (network byte order)
            d1, d2, d3 = struct.unpack_from("<IHH", guid_val, 0)
            d4 = guid_val[8:10]
            d5 = guid_val[10:16]
            return (
                f"{d1:08x}-{d2:04x}-{d3:04x}-"
                f"{d4.hex()}-{d5.hex()}"
            )
    return "00000000-0000-0000-0000-000000000000"


