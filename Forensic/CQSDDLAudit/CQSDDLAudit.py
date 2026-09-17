#!/usr/bin/env python3
"""CQSDDLAudit, offline auditing of Windows security descriptors in SDDL form.

SDDL is the text serialization of a security descriptor, and it is the only
representation that is complete: the Security tab cannot render generic rights,
it sorts entries for display and so hides the one property that decides access,
and for services it shows nothing at all. This tool parses SDDL positionally and
reports what the GUI cannot.

    services  the service report: every service, interpreted, hidden ones flagged
    decode    one descriptor, every ACE in real order, canonical verdict
    order     canonical-order violations across a collection
    generic   ACEs carrying GA/GR/GW/GX, and inherit-only deferred grants
    risk      pattern findings with severity
    access    access-check simulator: which ACE decided, which never ran
    diff      order-aware comparison against a baseline

Services are the primary surface, for two reasons. SDDL is the only way to see
their permissions at all, and a service can be hidden from you: denying
SERVICE_QUERY_STATUS (LC) removes it from enumeration, so `sc query`,
services.msc and Get-Service all report a machine that does not have it. The
usual form is a Deny of DCLC, often DCLCWPDTSD, aimed at Interactive, Service
and Administrators at once.

The answer is not to enumerate through the SCM. Collect-Sddl.ps1 enumerates
HKLM\\SYSTEM\\CurrentControlSet\\Services instead and reads each Security value
directly, so a service that denies its own enumeration still appears, and the
difference between the two lists is itself the finding.

Collection and analysis are separate steps, so this runs against preserved
evidence on an examiner box. It also runs on a live system: point the collector
at the local machine and feed its CSV straight back in.

Examples
--------
    powershell -File Collect-Sddl.ps1 -OutFile services.csv        # live, elevated
    py -3 CQSDDLAudit.py services --input services.csv --html report.html
    py -3 CQSDDLAudit.py services --input services.csv --only-hidden
    py -3 CQSDDLAudit.py decode   --sddl "D:(A;;FA;;;BU)(D;;FA;;;BU)" --object-type file
    py -3 CQSDDLAudit.py risk     --input services.csv --min-severity high
    py -3 CQSDDLAudit.py access   --sddl "D:(A;;CCLCSWRPWP;;;BU)" --token BU --want WP \\
                                  --object-type service --explain
    py -3 CQSDDLAudit.py diff     --input current.csv --baseline baseline.csv

Every subcommand prints a table and can also write --csv / --json.

Author: Paula Januszkiewicz | CQURE
License: Apache License 2.0
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


def _use_utf8_streams() -> None:
    """Force UTF-8 on stdout and stderr where the runtime allows it.

    Descriptors carry account names and file paths, both of which can hold
    characters a cp1252 console cannot render. Without this a single non-ASCII
    name turns into '?' or aborts the run.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


_use_utf8_streams()


# --------------------------------------------------------------------------
# Alias tables
#
# Two-letter tokens collide across fields. FA is FAILED_ACCESS in the flags
# field and FILE_ALL_ACCESS in the rights field. WD is WRITE_DAC in rights and
# Everyone in the SID field. CC is CREATE_CHILD on a directory object and
# SERVICE_QUERY_CONFIG on a service. Nothing here is resolved by lookup alone,
# every table is applied only to the field it belongs to, and the rights tables
# are additionally selected by object type.
# --------------------------------------------------------------------------

ACE_TYPES: Dict[str, str] = {
    "A":  "ACCESS_ALLOWED",
    "D":  "ACCESS_DENIED",
    "OA": "ACCESS_ALLOWED_OBJECT",
    "OD": "ACCESS_DENIED_OBJECT",
    "AU": "SYSTEM_AUDIT",
    "AL": "SYSTEM_ALARM",
    "OU": "SYSTEM_AUDIT_OBJECT",
    "OL": "SYSTEM_ALARM_OBJECT",
    "ML": "SYSTEM_MANDATORY_LABEL",
    "XA": "ACCESS_ALLOWED_CALLBACK",
    "XD": "ACCESS_DENIED_CALLBACK",
    "ZA": "ACCESS_ALLOWED_CALLBACK_OBJECT",
    "XU": "SYSTEM_AUDIT_CALLBACK",
    "RA": "SYSTEM_RESOURCE_ATTRIBUTE",
    "SP": "SYSTEM_SCOPED_POLICY_ID",
    "TL": "SYSTEM_PROCESS_TRUST_LABEL",
    "FL": "SYSTEM_ACCESS_FILTER",
}

DENY_TYPES = {"D", "OD", "XD"}
ALLOW_TYPES = {"A", "OA", "XA", "ZA"}
AUDIT_TYPES = {"AU", "OU", "XU", "AL", "OL"}

ACE_FLAGS: Dict[str, str] = {
    "CI": "CONTAINER_INHERIT",
    "OI": "OBJECT_INHERIT",
    "NP": "NO_PROPAGATE_INHERIT",
    "IO": "INHERIT_ONLY",
    "ID": "INHERITED",
    "SA": "SUCCESSFUL_ACCESS_AUDIT",
    "FA": "FAILED_ACCESS_AUDIT",
    "TP": "TRUST_PROTECTED_FILTER",
    "CR": "CRITICAL",
}

ACL_FLAGS: Dict[str, str] = {
    "P":  "PROTECTED",
    "AI": "AUTO_INHERITED",
    "AR": "AUTO_INHERIT_REQ",
}

# Standard rights, meaningful on every object type.
RIGHTS_STANDARD: Dict[str, Tuple[int, str]] = {
    "RC": (0x00020000, "READ_CONTROL"),
    "SD": (0x00010000, "DELETE"),
    "WD": (0x00040000, "WRITE_DAC"),
    "WO": (0x00080000, "WRITE_OWNER"),
}

RIGHTS_GENERIC: Dict[str, Tuple[int, str]] = {
    "GA": (0x10000000, "GENERIC_ALL"),
    "GX": (0x20000000, "GENERIC_EXECUTE"),
    "GW": (0x40000000, "GENERIC_WRITE"),
    "GR": (0x80000000, "GENERIC_READ"),
}

RIGHTS_FILE: Dict[str, Tuple[int, str]] = {
    "FA": (0x001F01FF, "FILE_ALL_ACCESS"),
    "FR": (0x00120089, "FILE_GENERIC_READ"),
    "FW": (0x00120116, "FILE_GENERIC_WRITE"),
    "FX": (0x001200A0, "FILE_GENERIC_EXECUTE"),
}

RIGHTS_REGISTRY: Dict[str, Tuple[int, str]] = {
    "KA": (0x000F003F, "KEY_ALL_ACCESS"),
    "KR": (0x00020019, "KEY_READ"),
    "KW": (0x00020006, "KEY_WRITE"),
    "KX": (0x00020019, "KEY_EXECUTE"),
}

# Bit positions 0x01..0x0100 are object-type specific. Same letters, different
# meanings, which is exactly why --object-type is not cosmetic.
RIGHTS_SERVICE: Dict[str, Tuple[int, str]] = {
    "CC": (0x0001, "SERVICE_QUERY_CONFIG"),
    "DC": (0x0002, "SERVICE_CHANGE_CONFIG"),
    "LC": (0x0004, "SERVICE_QUERY_STATUS"),
    "SW": (0x0008, "SERVICE_ENUMERATE_DEPENDENTS"),
    "RP": (0x0010, "SERVICE_START"),
    "WP": (0x0020, "SERVICE_STOP"),
    "DT": (0x0040, "SERVICE_PAUSE_CONTINUE"),
    "LO": (0x0080, "SERVICE_INTERROGATE"),
    "CR": (0x0100, "SERVICE_USER_DEFINED_CONTROL"),
}

RIGHTS_DS: Dict[str, Tuple[int, str]] = {
    "CC": (0x0001, "DS_CREATE_CHILD"),
    "DC": (0x0002, "DS_DELETE_CHILD"),
    "LC": (0x0004, "DS_LIST_CONTENTS"),
    "SW": (0x0008, "DS_SELF_WRITE"),
    "RP": (0x0010, "DS_READ_PROPERTY"),
    "WP": (0x0020, "DS_WRITE_PROPERTY"),
    "DT": (0x0040, "DS_DELETE_TREE"),
    "LO": (0x0080, "DS_LIST_OBJECT"),
    "CR": (0x0100, "DS_CONTROL_ACCESS"),
}

RIGHTS_LABEL: Dict[str, Tuple[int, str]] = {
    "NR": (0x1, "NO_READ_UP"),
    "NW": (0x2, "NO_WRITE_UP"),
    "NX": (0x4, "NO_EXECUTE_UP"),
}

# Per-bit names for a readable decode of the low word.
BITS_FILE: List[Tuple[int, str]] = [
    (0x0001, "READ_DATA/LIST_DIRECTORY"),
    (0x0002, "WRITE_DATA/ADD_FILE"),
    (0x0004, "APPEND_DATA/ADD_SUBDIRECTORY"),
    (0x0008, "READ_EA"),
    (0x0010, "WRITE_EA"),
    (0x0020, "EXECUTE/TRAVERSE"),
    (0x0040, "DELETE_CHILD"),
    (0x0080, "READ_ATTRIBUTES"),
    (0x0100, "WRITE_ATTRIBUTES"),
]

BITS_REGISTRY: List[Tuple[int, str]] = [
    (0x0001, "QUERY_VALUE"),
    (0x0002, "SET_VALUE"),
    (0x0004, "CREATE_SUB_KEY"),
    (0x0008, "ENUMERATE_SUB_KEYS"),
    (0x0010, "NOTIFY"),
    (0x0020, "CREATE_LINK"),
]

BITS_STANDARD: List[Tuple[int, str]] = [
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
    (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x10000000, "GENERIC_ALL"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
]

OBJECT_TYPES = ("file", "directory", "registry", "service", "ds", "generic")

# Aliases whose meaning is stable and documented. Anything not here is reported
# as unresolved rather than guessed, because a wrong account name in an audit
# report is worse than an honest blank.
SID_ALIASES: Dict[str, Tuple[str, str]] = {
    "AN": ("S-1-5-7",        "Anonymous Logon"),
    "AO": ("",               "Account Operators"),
    "AU": ("S-1-5-11",       "Authenticated Users"),
    "BA": ("S-1-5-32-544",   "Administrators"),
    "BG": ("S-1-5-32-546",   "Guests"),
    "BO": ("S-1-5-32-551",   "Backup Operators"),
    "BU": ("S-1-5-32-545",   "Users"),
    "CG": ("S-1-3-1",        "Creator Group"),
    "CO": ("S-1-3-0",        "Creator Owner"),
    "DA": ("",               "Domain Admins"),
    "DC": ("",               "Domain Computers"),
    "DD": ("",               "Domain Controllers"),
    "DG": ("",               "Domain Guests"),
    "DU": ("",               "Domain Users"),
    "EA": ("",               "Enterprise Admins"),
    "ED": ("S-1-5-9",        "Enterprise Domain Controllers"),
    "IU": ("S-1-5-4",        "Interactive"),
    "LA": ("",               "Local Administrator"),
    "LG": ("",               "Local Guest"),
    "LS": ("S-1-5-19",       "Local Service"),
    "NS": ("S-1-5-20",       "Network Service"),
    "NU": ("S-1-5-2",        "Network"),
    "PS": ("S-1-5-10",       "Principal Self"),
    "PU": ("S-1-5-32-547",   "Power Users"),
    "RC": ("S-1-5-12",       "Restricted Code"),
    "RD": ("S-1-5-32-555",   "Remote Desktop Users"),
    "RE": ("S-1-5-32-552",   "Replicator"),
    "SO": ("S-1-5-32-549",   "Server Operators"),
    "SU": ("S-1-5-6",        "Service"),
    "SY": ("S-1-5-18",       "Local System"),
    "WD": ("S-1-1-0",        "Everyone"),
    "WR": ("S-1-5-33",       "Write Restricted Code"),
    "AC": ("S-1-15-2-1",     "All Application Packages"),
    "LW": ("S-1-16-4096",    "Low Mandatory Level"),
    "ME": ("S-1-16-8192",    "Medium Mandatory Level"),
    "HI": ("S-1-16-12288",   "High Mandatory Level"),
    "SI": ("S-1-16-16384",   "System Mandatory Level"),
}

WELL_KNOWN_SIDS: Dict[str, str] = {
    "S-1-1-0":      "Everyone",
    "S-1-5-7":      "Anonymous Logon",
    "S-1-5-11":     "Authenticated Users",
    "S-1-5-18":     "Local System",
    "S-1-5-19":     "Local Service",
    "S-1-5-20":     "Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
                    "NT SERVICE\\TrustedInstaller",
}

# Principals that make an over-broad grant a finding rather than a design choice.
BROAD_PRINCIPALS = {"WD", "BU", "AU", "AN", "IU", "NU", "S-1-1-0", "S-1-5-11", "S-1-5-7",
                    "S-1-5-32-545", "S-1-5-4", "S-1-5-2"}

# Principals Windows itself grants full control to on nearly every object.
# Their holding WRITE_DAC or WRITE_OWNER is the default, not a finding.
TRUSTED_INSTALLER = ("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
DEFAULT_CONTROL_PRINCIPALS = {"BA", "SY", "LA", "S-1-5-32-544", "S-1-5-18", TRUSTED_INSTALLER}

# Denying these principals blocks legitimate administration, which is what an
# anti-tamper descriptor is for. Denying Guests or Anonymous is the opposite:
# Windows ships exactly that on several of its own services.
ADMIN_DENY_TARGETS = {"BA", "SY", "LA", "WD", "AU", "IU", "BU",
                      "S-1-5-32-544", "S-1-5-18", "S-1-1-0", "S-1-5-11",
                      "S-1-5-4", "S-1-5-32-545"}

# Broad principals where even start or stop is worth a row. Interactive and
# Authenticated Users hold those on plenty of services Windows ships, so
# flagging them produces a hundred rows of noise per host.
UNRESTRICTED_PRINCIPALS = {"WD", "AN", "S-1-1-0", "S-1-5-7"}

SEVERITIES = ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

class SddlError(ValueError):
    """Raised when a descriptor cannot be parsed. Carries the offending text."""


@dataclass
class Ace:
    position: int                      # index within its ACL, 0 based, real order
    raw: str
    ace_type: str
    flags: List[str]
    rights_raw: str
    mask: int
    rights: List[str]                  # decoded names, object-type aware
    object_guid: str
    inherit_object_guid: str
    sid: str
    condition: str = ""
    unresolved_rights: List[str] = field(default_factory=list)

    @property
    def is_deny(self) -> bool:
        return self.ace_type in DENY_TYPES

    @property
    def is_allow(self) -> bool:
        return self.ace_type in ALLOW_TYPES

    @property
    def is_audit(self) -> bool:
        return self.ace_type in AUDIT_TYPES

    @property
    def is_inherited(self) -> bool:
        return "ID" in self.flags

    @property
    def is_inherit_only(self) -> bool:
        return "IO" in self.flags

    @property
    def has_generic(self) -> bool:
        return bool(self.mask & 0xF0000000)

    def sid_label(self) -> str:
        return resolve_sid(self.sid)

    def rights_label(self) -> str:
        parts = list(self.rights)
        parts.extend("?" + tok for tok in self.unresolved_rights)
        return ",".join(parts) if parts else "(none)"


@dataclass
class Descriptor:
    source: str
    object_type: str
    raw: str
    owner: str = ""
    group: str = ""
    dacl_flags: List[str] = field(default_factory=list)
    sacl_flags: List[str] = field(default_factory=list)
    dacl: List[Ace] = field(default_factory=list)
    sacl: List[Ace] = field(default_factory=list)
    dacl_present: bool = False
    sacl_present: bool = False
    dacl_null: bool = False            # "D:NO_ACCESS_CONTROL" or a bare D: with no ACEs
    extra: Dict[str, str] = field(default_factory=dict)   # everything else the collector wrote

    @property
    def dacl_empty(self) -> bool:
        return self.dacl_present and not self.dacl_null and not self.dacl


def split_top_level(text: str) -> List[str]:
    """Split "(...)(...)" into ACE bodies, respecting nesting.

    Conditional ACEs carry parenthesised expressions in the last field, so a
    naive split on ')(' tears them in half. This counts depth instead.
    """
    out: List[str] = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "(":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                out.append(text[start:i])
            elif depth < 0:
                raise SddlError("unbalanced ')' at offset %d" % i)
    if depth != 0:
        raise SddlError("unbalanced '(' in ACE list")
    return out


def split_ace_fields(body: str) -> List[str]:
    """Split one ACE body on ';', ignoring separators inside parentheses."""
    fields: List[str] = []
    depth = 0
    buf: List[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == ";" and depth == 0:
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    fields.append("".join(buf))
    return fields


def _rights_table(object_type: str) -> Dict[str, Tuple[int, str]]:
    table: Dict[str, Tuple[int, str]] = {}
    table.update(RIGHTS_STANDARD)
    table.update(RIGHTS_GENERIC)
    if object_type in ("file", "directory"):
        table.update(RIGHTS_FILE)
    elif object_type == "registry":
        table.update(RIGHTS_REGISTRY)
    elif object_type == "service":
        table.update(RIGHTS_SERVICE)
    elif object_type == "ds":
        table.update(RIGHTS_DS)
    else:
        # generic: offer the file set, the most common surface, but the caller
        # is told the interpretation is unqualified.
        table.update(RIGHTS_FILE)
    return table


def parse_rights(text: str, object_type: str, ace_type: str) -> Tuple[int, List[str], List[str]]:
    """Return (mask, decoded names, unresolved two-letter tokens).

    Accepts hex (0x1200a9), decimal, or a run of two-letter aliases.
    """
    text = text.strip()
    if not text:
        return 0, [], []

    if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
        mask = int(text, 16)
        return mask, decode_mask(mask, object_type), []
    if re.fullmatch(r"\d+", text):
        mask = int(text)
        return mask, decode_mask(mask, object_type), []

    table = RIGHTS_LABEL if ace_type == "ML" else _rights_table(object_type)
    mask = 0
    names: List[str] = []
    unresolved: List[str] = []
    if len(text) % 2 != 0:
        raise SddlError("rights field %r has an odd length; aliases are two letters" % text)
    for i in range(0, len(text), 2):
        tok = text[i:i + 2].upper()
        if tok in table:
            bit, name = table[tok]
            mask |= bit
            names.append(name)
        else:
            unresolved.append(tok)
    return mask, names, unresolved


def decode_mask(mask: int, object_type: str) -> List[str]:
    """Name the bits in a numeric mask for the given object type."""
    names: List[str] = []
    specific: List[Tuple[int, str]]
    if object_type in ("file", "directory", "generic"):
        specific = BITS_FILE
    elif object_type == "registry":
        specific = BITS_REGISTRY
    elif object_type == "service":
        specific = [(bit, name) for _, (bit, name) in RIGHTS_SERVICE.items()]
    elif object_type == "ds":
        specific = [(bit, name) for _, (bit, name) in RIGHTS_DS.items()]
    else:
        specific = BITS_FILE
    for bit, name in sorted(specific):
        if mask & bit:
            names.append(name)
    for bit, name in BITS_STANDARD:
        if mask & bit:
            names.append(name)
    return names


def parse_ace(body: str, position: int, object_type: str) -> Ace:
    fields = split_ace_fields(body)
    if len(fields) < 6:
        raise SddlError("ACE %r has %d fields, expected at least 6" % (body, len(fields)))
    ace_type = fields[0].strip().upper()
    flag_text = fields[1].strip().upper()
    rights_text = fields[2].strip()
    obj_guid = fields[3].strip()
    inh_guid = fields[4].strip()
    sid = fields[5].strip().upper()
    condition = fields[6].strip() if len(fields) > 6 else ""

    if ace_type not in ACE_TYPES:
        raise SddlError("unknown ACE type %r in %r" % (ace_type, body))

    flags: List[str] = []
    if len(flag_text) % 2 != 0:
        raise SddlError("flag field %r has an odd length" % flag_text)
    for i in range(0, len(flag_text), 2):
        tok = flag_text[i:i + 2]
        flags.append(tok if tok in ACE_FLAGS else "?" + tok)

    mask, names, unresolved = parse_rights(rights_text, object_type, ace_type)
    return Ace(position=position, raw="(" + body + ")", ace_type=ace_type, flags=flags,
               rights_raw=rights_text, mask=mask, rights=names, object_guid=obj_guid,
               inherit_object_guid=inh_guid, sid=sid, condition=condition,
               unresolved_rights=unresolved)


def parse_sddl(sddl: str, source: str = "", object_type: str = "generic") -> Descriptor:
    """Parse a full descriptor. Sections may appear in any order."""
    sddl = (sddl or "").strip()
    if not sddl:
        raise SddlError("empty descriptor")
    desc = Descriptor(source=source, object_type=object_type, raw=sddl)

    # Find section starts at top level only, so a SID like S-1-5-... inside an
    # ACE never looks like the start of an S: section.
    marks: List[Tuple[int, str]] = []
    depth = 0
    i = 0
    while i < len(sddl):
        ch = sddl[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and ch in "OGDS" and i + 1 < len(sddl) and sddl[i + 1] == ":":
            # A colon only ever appears as a section separator: SIDs, aliases and
            # ACL flag runs contain none, and ACE bodies are inside parentheses
            # so they are never at depth 0. Do not additionally require the
            # previous character to be non-alphanumeric, or the G: in
            # "O:SYG:SYD:..." is missed because the owner alias ends in Y.
            marks.append((i, ch))
        i += 1
    if not marks:
        raise SddlError("no O:/G:/D:/S: section found")

    for idx, (start, letter) in enumerate(marks):
        end = marks[idx + 1][0] if idx + 1 < len(marks) else len(sddl)
        body = sddl[start + 2:end].strip()
        if letter == "O":
            desc.owner = body.upper()
        elif letter == "G":
            desc.group = body.upper()
        else:
            flags_text = body[:body.index("(")] if "(" in body else body
            acl_flags = [f for f in re.findall(r"[A-Z]+", flags_text.upper())]
            aces_text = body[body.index("("):] if "(" in body else ""
            aces = [parse_ace(b, n, object_type)
                    for n, b in enumerate(split_top_level(aces_text))] if aces_text else []
            if letter == "D":
                desc.dacl_present = True
                desc.dacl_flags = acl_flags
                desc.dacl = aces
                desc.dacl_null = "NO_ACCESS_CONTROL" in flags_text.upper() or (
                    not flags_text.strip() and not aces_text)
            else:
                desc.sacl_present = True
                desc.sacl_flags = acl_flags
                desc.sacl = aces
    return desc


def service_sid(name: str) -> str:
    """The NT SERVICE\\<name> SID, which is derived, not allocated.

    S-1-5-80 followed by the SHA1 of the upper-cased service name in UTF-16LE,
    read as five little-endian 32 bit values. Computing it lets the report name
    the S-1-5-80-... SIDs that otherwise fill an audit with unreadable rows, and
    lets a service holding rights over itself be recognised as the Windows
    default rather than reported as a finding.
    """
    digest = hashlib.sha1(name.upper().encode("utf-16-le")).digest()
    parts = [int.from_bytes(digest[i:i + 4], "little") for i in range(0, 20, 4)]
    return "S-1-5-80-" + "-".join(str(p) for p in parts)


# Filled in from whatever collection is loaded, so S-1-5-80-... rows get a name.
KNOWN_SERVICE_SIDS: Dict[str, str] = {}


def register_service_sids(descs: Iterable[Descriptor]) -> None:
    for d in descs:
        if d.object_type == "service" and d.source:
            KNOWN_SERVICE_SIDS[service_sid(d.source)] = d.source


def resolve_sid(sid: str) -> str:
    sid = sid.strip().upper()
    if sid in KNOWN_SERVICE_SIDS:
        return "NT SERVICE\\%s (%s)" % (KNOWN_SERVICE_SIDS[sid], sid)
    if sid in SID_ALIASES:
        known, name = SID_ALIASES[sid]
        return "%s (%s)" % (name, sid)
    if sid in WELL_KNOWN_SIDS:
        return "%s (%s)" % (WELL_KNOWN_SIDS[sid], sid)
    if len(sid) == 2 and sid.isalpha():
        return "unresolved alias (%s)" % sid
    return sid


# --------------------------------------------------------------------------
# Canonical order
# --------------------------------------------------------------------------

def ace_rank(ace: Ace) -> int:
    """Canonical rank: explicit deny, explicit allow, inherited deny, inherited allow."""
    base = 2 if ace.is_inherited else 0
    return base + (1 if not ace.is_deny else 0)


RANK_NAMES = ("explicit deny", "explicit allow", "inherited deny", "inherited allow")


def check_canonical(aces: Sequence[Ace]) -> Optional[str]:
    """Return a description of the first ordering violation, or None."""
    # Audit ACEs live in the SACL and have no canonical ordering requirement.
    ordered = [a for a in aces if not a.is_audit]
    for i in range(1, len(ordered)):
        prev, cur = ordered[i - 1], ordered[i]
        if ace_rank(cur) < ace_rank(prev):
            return ("ACE #%d %s (%s) comes after #%d %s (%s)"
                    % (cur.position, cur.raw, RANK_NAMES[ace_rank(cur)],
                       prev.position, prev.raw, RANK_NAMES[ace_rank(prev)]))
    return None


# --------------------------------------------------------------------------
# Access check simulation
# --------------------------------------------------------------------------

@dataclass
class AccessResult:
    granted: bool
    desired: int
    remaining: int
    decided_by: Optional[Ace]
    reason: str
    evaluated: List[int] = field(default_factory=list)
    skipped: List[Tuple[int, str]] = field(default_factory=list)


def simulate_access(desc: Descriptor, token_sids: Sequence[str], desired: int) -> AccessResult:
    """Walk the DACL in real order, the way the kernel does.

    Deliberately models the three things that make ordering matter: inherit-only
    entries never apply to the object itself, a NULL DACL grants everything, and
    an empty DACL grants nothing.
    """
    tokens = {s.strip().upper() for s in token_sids if s.strip()}

    if not desc.dacl_present or desc.dacl_null:
        return AccessResult(True, desired, 0, None,
                            "NULL DACL: no discretionary control, everyone is granted everything")
    if desc.dacl_empty:
        return AccessResult(False, desired, desired, None,
                            "empty DACL: present but with no entries, nothing is granted")

    remaining = desired
    evaluated: List[int] = []
    skipped: List[Tuple[int, str]] = []

    for ace in desc.dacl:
        if ace.is_audit:
            skipped.append((ace.position, "audit entry, not part of the access check"))
            continue
        if ace.is_inherit_only:
            skipped.append((ace.position, "INHERIT_ONLY, does not apply to this object"))
            continue
        if ace.sid not in tokens:
            skipped.append((ace.position, "SID not in the token"))
            continue
        if ace.condition:
            skipped.append((ace.position, "conditional ACE, condition not evaluated"))
            continue

        evaluated.append(ace.position)
        if ace.is_deny:
            if ace.mask & remaining:
                return AccessResult(False, desired, remaining & ace.mask, ace,
                                    "denied by ACE #%d" % ace.position, evaluated, skipped)
        elif ace.is_allow:
            remaining &= ~ace.mask
            if remaining == 0:
                return AccessResult(True, desired, 0, ace,
                                    "granted by ACE #%d" % ace.position, evaluated, skipped)

    return AccessResult(False, desired, remaining, None,
                        "no entry granted the remaining access", evaluated, skipped)


# --------------------------------------------------------------------------
# Risk rules
# --------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str
    source: str
    object_type: str
    rule: str
    detail: str
    ace: str = ""


def _is_broad(sid: str) -> bool:
    return sid.strip().upper() in BROAD_PRINCIPALS


# Service access bits, named here because the two-letter tokens are shared with
# directory objects and mean something completely different there.
SVC_QUERY_CONFIG  = 0x0001   # CC
SVC_CHANGE_CONFIG = 0x0002   # DC
SVC_QUERY_STATUS  = 0x0004   # LC
SVC_ENUM_DEPEND   = 0x0008   # SW
SVC_START         = 0x0010   # RP
SVC_STOP          = 0x0020   # WP
SVC_PAUSE         = 0x0040   # DT
SVC_INTERROGATE   = 0x0080   # LO
SVC_UDC           = 0x0100   # CR
RIGHT_DELETE      = 0x00010000
RIGHT_WRITE_DAC   = 0x00040000

# Losing SERVICE_QUERY_STATUS as one of these principals is what removes a
# service from the list an operator or a tool actually sees.
HIDE_TARGETS = {"IU", "SU", "BA", "WD", "AU", "BU", "SY", "NU", "AN",
                "S-1-5-4", "S-1-5-6", "S-1-5-32-544", "S-1-1-0", "S-1-5-11",
                "S-1-5-32-545", "S-1-5-18", "S-1-5-2", "S-1-5-7"}


def service_deny_effects(ace: Ace) -> List[str]:
    """Plain-language consequences of one Deny ACE on a service."""
    effects: List[str] = []
    if ace.mask & SVC_QUERY_STATUS:
        effects.append("removed from enumeration (LC)")
    if ace.mask & SVC_QUERY_CONFIG:
        effects.append("configuration unreadable (CC)")
    if ace.mask & SVC_CHANGE_CONFIG:
        effects.append("cannot be reconfigured (DC)")
    if ace.mask & SVC_STOP:
        effects.append("cannot be stopped (WP)")
    if ace.mask & SVC_PAUSE:
        effects.append("cannot be paused (DT)")
    if ace.mask & RIGHT_DELETE:
        effects.append("cannot be deleted (SD)")
    if ace.mask & RIGHT_WRITE_DAC:
        effects.append("permissions cannot be repaired (WD)")
    if ace.mask & 0x10000000:
        effects.append("all access denied (GA)")
    return effects


@dataclass
class ServiceVerdict:
    hidden: bool = False                 # denies enumeration to someone who should see it
    not_enumerated: bool = False         # the collector could not see it through the SCM
    anti_tamper: bool = False            # denies stop, delete, reconfigure or repair
    weak: bool = False                   # grants control to a broad principal
    null_dacl: bool = False
    reasons: List[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.hidden or self.not_enumerated:
            return "HIDDEN"
        if self.null_dacl or self.weak:
            return "WEAK"
        if self.anti_tamper:
            return "ANTI-TAMPER"
        return "ok"


def analyse_service(desc: Descriptor) -> ServiceVerdict:
    """Classify one service descriptor. Services only, the bits differ elsewhere."""
    v = ServiceVerdict()

    enum_visible = (desc.extra.get("EnumVisible", "") or "").strip().lower()
    if enum_visible in ("false", "0", "no"):
        v.not_enumerated = True
        v.reasons.append("present in the registry but not returned by SCM enumeration")

    if desc.dacl_present and desc.dacl_null:
        v.null_dacl = True
        v.reasons.append("NULL DACL, every principal holds every service right "
                         "including SERVICE_CHANGE_CONFIG")

    for ace in desc.dacl:
        if ace.is_deny:
            effects = service_deny_effects(ace)
            if not effects:
                continue
            target = ace.sid.upper()
            hits_admin = target in HIDE_TARGETS
            if (ace.mask & SVC_QUERY_STATUS or ace.mask & 0x10000000) and hits_admin:
                v.hidden = True
                v.reasons.append("Deny to %s: %s" % (resolve_sid(ace.sid), ", ".join(effects)))
            elif (ace.mask & (SVC_CHANGE_CONFIG | SVC_STOP | RIGHT_DELETE | RIGHT_WRITE_DAC)
                  and target in ADMIN_DENY_TARGETS):
                v.anti_tamper = True
                v.reasons.append("Deny to %s: %s" % (resolve_sid(ace.sid), ", ".join(effects)))

        elif ace.is_allow and _is_broad(ace.sid):
            if ace.mask & SVC_CHANGE_CONFIG or ace.mask & 0x10000000:
                v.weak = True
                v.reasons.append("Allow to %s includes SERVICE_CHANGE_CONFIG, the binary path "
                                 "can be replaced" % resolve_sid(ace.sid))
            elif ace.mask & (RIGHT_WRITE_DAC | 0x00080000):
                v.weak = True
                v.reasons.append("Allow to %s includes WRITE_DAC or WRITE_OWNER, so the "
                                 "descriptor can be rewritten" % resolve_sid(ace.sid))
            elif ace.mask & (SVC_START | SVC_STOP) and ace.sid.upper() in UNRESTRICTED_PRINCIPALS:
                # Interactive and Authenticated Users holding start or stop is
                # ordinary Windows configuration on a large number of services.
                # Everyone and Anonymous holding it is not.
                v.weak = True
                v.reasons.append("Allow to %s includes start or stop" % resolve_sid(ace.sid))

    return v


def find_risks(desc: Descriptor) -> List[Finding]:
    out: List[Finding] = []
    src, ot = desc.source, desc.object_type

    def add(sev: str, rule: str, detail: str, ace: Optional[Ace] = None) -> None:
        out.append(Finding(sev, src, ot, rule, detail, ace.raw if ace else ""))

    if desc.dacl_present and desc.dacl_null:
        add("critical", "null-dacl",
            "NULL DACL: every principal is granted every right, and no audit trail explains it")
    if desc.dacl_empty:
        add("info", "empty-dacl",
            "empty DACL: present but with no entries, so nothing is granted to anyone")

    violation = check_canonical(desc.dacl)
    if violation:
        add("high", "non-canonical-order",
            "ordering violation, access is decided by position and the GUI will misrepresent it: "
            + violation)

    for ace in desc.dacl:
        broad = _is_broad(ace.sid)
        label = resolve_sid(ace.sid)

        if ace.is_allow and broad and (ace.mask & 0x10000000 or ace.mask in
                                       (0x001F01FF, 0x000F003F, 0x000F01FF)):
            add("critical", "full-control-broad",
                "full control granted to %s" % label, ace)

        # Administrators and SYSTEM hold WRITE_DAC and WRITE_OWNER on virtually
        # every object Windows ships, and a service commonly holds them over its
        # own descriptor. Reporting either is noise that buries the real
        # findings, so only an unexpected holder is worth a row.
        expected = ace.sid.strip().upper() in DEFAULT_CONTROL_PRINCIPALS
        if ot == "service" and desc.source and ace.sid.strip().upper() == service_sid(desc.source):
            expected = True

        if ace.is_allow and ace.mask & 0x00040000 and not expected:
            add("critical" if broad else "medium", "write-dac",
                "WRITE_DAC granted to %s: the DACL itself can be rewritten, "
                "including into non-canonical order" % label, ace)

        if ace.is_allow and ace.mask & 0x00080000 and not expected:
            add("critical" if broad else "medium", "write-owner",
                "WRITE_OWNER granted to %s: ownership can be taken, and an owner "
                "implicitly holds WRITE_DAC" % label, ace)

        if ace.is_allow and ace.has_generic:
            if ot == "service" and ace.is_inherit_only:
                # A service has no child objects, so OI/CI/IO carry no effect.
                # Windows ships this on its own protected services, and it is
                # the second TrustedInstaller entry the Security tab cannot draw.
                sev = "info"
                note = ("INHERIT_ONLY on a service has no effect, a service has no child "
                        "objects; Windows ships this pattern, but note the GUI shows one "
                        "entry here where the descriptor has two")
            elif ace.is_inherit_only:
                sev = "medium" if expected else "high"
                note = ("INHERIT_ONLY plus generic rights is a deferred grant: it affects "
                        "nothing today and everything created here tomorrow")
            else:
                sev = "info" if expected else "medium"
                note = "generic rights are not rendered by the Security tab"
            add(sev, "generic-rights",
                "%s for %s, %s" % (",".join(n for n in ace.rights if n.startswith("GENERIC")),
                                   label, note), ace)

        if ot == "service" and ace.is_allow and broad:
            if ace.mask & SVC_CHANGE_CONFIG:
                add("critical", "service-change-config",
                    "SERVICE_CHANGE_CONFIG granted to %s: the binary path can be replaced, "
                    "which is arbitrary code as the service account" % label, ace)
            elif ace.mask & (SVC_START | SVC_STOP):
                sev = "medium" if ace.sid.upper() in UNRESTRICTED_PRINCIPALS else "low"
                add(sev, "service-start-stop",
                    "service start or stop granted to %s" % label, ace)

        if ot == "service" and ace.is_deny:
            effects = service_deny_effects(ace)
            if effects and ace.sid.upper() in HIDE_TARGETS:
                if ace.mask & SVC_QUERY_STATUS or ace.mask & 0x10000000:
                    add("critical", "service-hidden",
                        "Deny to %s removes this service from enumeration: %s"
                        % (label, ", ".join(effects)), ace)
                elif ace.mask & (SVC_CHANGE_CONFIG | SVC_STOP | RIGHT_DELETE | RIGHT_WRITE_DAC):
                    add("high", "service-anti-tamper",
                        "Deny to %s blocks administration of this service: %s"
                        % (label, ", ".join(effects)), ace)

    if ot == "service":
        enum_visible = (desc.extra.get("EnumVisible", "") or "").strip().lower()
        if enum_visible in ("false", "0", "no"):
            add("critical", "service-not-enumerated",
                "registered under HKLM\\SYSTEM\\CurrentControlSet\\Services but not returned "
                "by SCM enumeration, which is what hiding looks like from the outside")

    if desc.object_type == "service" and not desc.dacl_present:
        add("high", "no-dacl-section",
            "no D: section in a service descriptor, permissions cannot be established from this text")

    return out


# --------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------

def load_csv(path: str, default_type: str = "generic") -> List[Descriptor]:
    """Read the CSV written by Collect-Sddl.ps1.

    Columns, case insensitive: Source, ObjectType, Sddl. Rows that fail to parse
    are reported on stderr and skipped, so one malformed descriptor in ten
    thousand does not abort a sweep.
    """
    out: List[Descriptor] = []
    bad = 0
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise SystemExit("%s has no header row" % path)
        lookup = {name.lower().strip(): name for name in reader.fieldnames}
        if "sddl" not in lookup:
            raise SystemExit("%s has no Sddl column (found: %s)"
                             % (path, ", ".join(reader.fieldnames)))
        for row in reader:
            sddl = (row.get(lookup["sddl"]) or "").strip()
            if not sddl:
                continue
            source = (row.get(lookup.get("source", ""), "") or "").strip()
            otype = (row.get(lookup.get("objecttype", ""), "") or "").strip().lower()
            if otype not in OBJECT_TYPES:
                otype = default_type
            try:
                desc = parse_sddl(sddl, source=source or "(unnamed)", object_type=otype)
                consumed = {lookup.get("sddl"), lookup.get("source"), lookup.get("objecttype")}
                desc.extra = {k: (v or "") for k, v in row.items() if k not in consumed}
                out.append(desc)
            except SddlError as exc:
                bad += 1
                sys.stderr.write("skipped %s: %s\n" % (source or "(unnamed)", exc))
    if bad:
        sys.stderr.write("%d descriptor(s) could not be parsed\n" % bad)
    return out


def load_input(args: argparse.Namespace) -> List[Descriptor]:
    if getattr(args, "sddl", None):
        return [parse_sddl(args.sddl, source=args.source or "(command line)",
                           object_type=args.object_type)]
    if getattr(args, "input", None):
        descs = load_csv(args.input, default_type=args.object_type)
        register_service_sids(descs)
        return descs
    raise SystemExit("give either --sddl or --input")


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def print_table(rows: List[Dict[str, object]], columns: Sequence[str], limit: int = 0,
                max_width: int = 58) -> None:
    """Console table. Long cells are clipped, the CSV and JSON keep every character."""
    if not rows:
        print("no rows")
        return
    shown = rows[:limit] if limit else rows

    def cell(r: Dict[str, object], c: str) -> str:
        text = str(r.get(c, ""))
        if max_width and len(text) > max_width:
            return text[:max_width - 1] + "…"
        return text

    widths = {c: len(c) for c in columns}
    for r in shown:
        for c in columns:
            widths[c] = max(widths[c], len(cell(r, c)))
    print("  ".join(c.ljust(widths[c]) for c in columns))
    print("  ".join("-" * widths[c] for c in columns))
    for r in shown:
        print("  ".join(cell(r, c).ljust(widths[c]) for c in columns))
    if limit and len(rows) > limit:
        print("... %d more row(s), use --limit 0 or write --csv for all of them"
              % (len(rows) - limit))


def write_outputs(rows: List[Dict[str, object]], args: argparse.Namespace) -> None:
    if getattr(args, "csv", None):
        columns: List[str] = []
        for r in rows:
            for k in r:
                if k not in columns:
                    columns.append(k)
        with open(args.csv, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        print("wrote %s (%d rows)" % (args.csv, len(rows)))
    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2, ensure_ascii=False)
        print("wrote %s (%d rows)" % (args.json, len(rows)))


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------

VERDICT_ORDER = {"HIDDEN": 0, "WEAK": 1, "ANTI-TAMPER": 2, "ok": 3}


def print_hidden_warnings(pairs: List[Tuple[Descriptor, "ServiceVerdict"]],
                          color: bool = True) -> None:
    """Call out every hidden service explicitly, and say why it is hidden.

    A row in a table is easy to scroll past. A service that has removed itself
    from enumeration is the finding the whole tool exists for, so it gets its
    own block: the ACE responsible, the principal it targets, what that
    principal can no longer do, and what to run next.
    """
    hidden = [(d, v) for d, v in pairs if v.hidden or v.not_enumerated]
    if not hidden:
        return

    use = color and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    RED = "\033[1;31m" if use else ""
    YEL = "\033[0;33m" if use else ""
    DIM = "\033[2m" if use else ""
    OFF = "\033[0m" if use else ""

    print("")
    print(RED + "=" * 78 + OFF)
    print(RED + "WARNING  %d service(s) are hidden from enumeration" % len(hidden) + OFF)
    print(RED + "=" * 78 + OFF)

    for desc, v in hidden:
        print("")
        print(RED + "WARNING: %s" % desc.source + OFF
              + ("  (%s)" % desc.extra["DisplayName"] if desc.extra.get("DisplayName") else ""))

        if v.not_enumerated:
            print("  " + YEL + "not enumerated" + OFF
                  + "  registered under HKLM\\SYSTEM\\CurrentControlSet\\Services,")
            print("                  but SCM enumeration did not return it. Anything that asks")
            print("                  the SCM for a service list, sc query, services.msc,")
            print("                  Get-Service, will report a machine that does not have it.")

        for ace in desc.dacl:
            if not ace.is_deny:
                continue
            effects = service_deny_effects(ace)
            if not effects or ace.sid.upper() not in HIDE_TARGETS:
                continue
            if not (ace.mask & SVC_QUERY_STATUS or ace.mask & 0x10000000):
                continue
            print("  " + YEL + "why" + OFF + "             %s" % ace.raw)
            print("                  denies %s" % resolve_sid(ace.sid))
            for eff in effects:
                print("                    - %s" % eff)

        if desc.extra.get("ImagePath"):
            print("  " + YEL + "image path" + OFF + "      %s" % desc.extra["ImagePath"])
        if desc.extra.get("Account"):
            print("  " + YEL + "runs as" + OFF + "         %s" % desc.extra["Account"])
        if desc.extra.get("StartMode"):
            print("  " + YEL + "start" + OFF + "           %s" % desc.extra["StartMode"])
        print("  " + DIM + "descriptor      %s" % desc.raw + OFF)
        print("  " + DIM + "next            sc.exe qc %s   /   reg query "
              "\"HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s\"" % (desc.source, desc.source) + OFF)

    print("")
    print(RED + "-" * 78 + OFF)
    print("Hiding a service is a Deny ACE, not a rootkit. Denying SERVICE_QUERY_STATUS (LC)")
    print("to Interactive, Service and Administrators removes it from every list those")
    print("principals can ask for, while the service keeps running as it always did.")
    print("The usual form is a Deny of DCLC, often DCLCWPDTSD, which also blocks stopping,")
    print("reconfiguring and deleting it. Treat an unexplained one as persistence until")
    print("you have accounted for it.")
    print(RED + "-" * 78 + OFF)


def cmd_services(args: argparse.Namespace) -> int:
    """The service report: every service, interpreted, hidden ones first."""
    descs = [d for d in load_input(args)]
    for d in descs:
        # A collection may carry other surfaces; the service bits only make
        # sense for services, so read everything here as one.
        d.object_type = "service"

    report: List[Tuple[Descriptor, ServiceVerdict]] = []
    for desc in descs:
        report.append((desc, analyse_service(desc)))

    if args.only_hidden:
        report = [(d, v) for d, v in report if v.hidden or v.not_enumerated]
    elif not args.all:
        report = [(d, v) for d, v in report if v.verdict != "ok"]

    report.sort(key=lambda p: (VERDICT_ORDER.get(p[1].verdict, 9), p[0].source.lower()))

    rows: List[Dict[str, object]] = []
    for desc, v in report:
        rows.append({
            "Verdict": v.verdict,
            "Service": desc.source,
            "Account": desc.extra.get("Account", ""),
            "StartMode": desc.extra.get("StartMode", ""),
            "Enumerated": desc.extra.get("EnumVisible", ""),
            "SdSource": desc.extra.get("SdSource", ""),
            "ImagePath": desc.extra.get("ImagePath", ""),
            "Aces": len(desc.dacl),
            "Reasons": " | ".join(v.reasons),
            "Sddl": desc.raw,
        })

    print_table(rows, ["Verdict", "Service", "Account", "Enumerated", "Reasons"], args.limit)

    all_pairs = [(d, analyse_service(d)) for d in descs]
    print_hidden_warnings(all_pairs, color=not args.no_color)

    total = len(descs)
    counts: Dict[str, int] = {}
    for _, v in all_pairs:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    print("\n%d service(s) examined. %s" % (
        total, ", ".join("%s: %d" % (k, counts[k])
                         for k in sorted(counts, key=lambda k: VERDICT_ORDER.get(k, 9)))))

    if args.html:
        write_html_report(descs, args.html, host=args.host)
    write_outputs(rows, args)
    return 0


def write_html_report(descs: List[Descriptor], path: str, host: str = "") -> None:
    """A self-contained report, CQURE corporate surface, meant to be attached to a case."""
    pairs = [(d, analyse_service(d)) for d in descs]
    pairs.sort(key=lambda p: (VERDICT_ORDER.get(p[1].verdict, 9), p[0].source.lower()))
    counts: Dict[str, int] = {}
    for _, v in pairs:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1

    e = html.escape
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parts: List[str] = []
    parts.append("""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CQSDDLAudit &middot; service report</title>
<style>
:root{--accent:#EB5B27;--pink:#FF005C;--fg:#111;--fg2:#4A4744;--fg3:#7A7570;
      --line:#E7E3DF;--line2:#D2CCC5;--bg:#FFF;--soft:#F7F5F3;--inset:#F0EDEA;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:40px}
h1{font-size:34px;line-height:1.1;letter-spacing:-.02em;margin:0 0 6px}
h2{font-size:21px;letter-spacing:-.01em;margin:38px 0 12px}
.eyebrow{font:500 11px/1 ui-monospace,Consolas,monospace;letter-spacing:.12em;
         text-transform:uppercase;color:var(--fg3);margin-bottom:10px}
.meta{color:var(--fg2);font-size:13px;margin-bottom:28px}
.rule{height:4px;width:120px;background:linear-gradient(90deg,var(--accent),var(--pink));margin:14px 0 24px}
.tiles{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:8px}
.tile{border:1px solid var(--line);border-radius:6px;padding:14px 18px;min-width:150px;background:var(--soft)}
.tile .n{font-size:30px;font-weight:600;line-height:1.1}
.tile .l{font:500 11px/1 ui-monospace,Consolas,monospace;letter-spacing:.12em;
         text-transform:uppercase;color:var(--fg3);margin-top:6px}
.tile.hidden{border-color:var(--pink)} .tile.hidden .n{color:var(--pink)}
.tile.weak{border-color:var(--accent)} .tile.weak .n{color:var(--accent)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;font:500 11px/1.4 ui-monospace,Consolas,monospace;letter-spacing:.1em;
   text-transform:uppercase;color:var(--fg3);border-bottom:1px solid var(--line2);padding:8px 10px}
td{border-bottom:1px solid var(--line);padding:8px 10px;vertical-align:top}
tr:hover td{background:var(--soft)}
.v{font:600 11px/1 ui-monospace,Consolas,monospace;letter-spacing:.08em;padding:4px 7px;
   border-radius:3px;display:inline-block;white-space:nowrap}
.v.HIDDEN{background:var(--pink);color:#fff}
.v.WEAK{background:var(--accent);color:#fff}
.v[class*="ANTI"]{background:#B45309;color:#fff}
.v.ok{background:var(--inset);color:var(--fg3)}
code,.sddl{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;word-break:break-all}
.sddl{display:block;background:var(--inset);border-left:3px solid var(--accent);
      padding:8px 10px;margin-top:6px;border-radius:0 3px 3px 0}
.reason{color:var(--fg2);font-size:13px;margin:3px 0}
.ace{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--fg2)}
.deny{color:var(--pink);font-weight:600}
.allow{color:var(--fg)}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);
       color:var(--fg3);font-size:12.5px}
@media print{.wrap{padding:0}tr:hover td{background:none}}
</style></head><body><div class="wrap">""")

    parts.append('<div class="eyebrow">CQURE &middot; CQSDDLAudit</div>')
    parts.append("<h1>Service security descriptor report</h1>")
    parts.append('<div class="rule"></div>')
    parts.append('<div class="meta">%s services examined%s &middot; generated %s</div>'
                 % (len(descs), (" &middot; host " + e(host)) if host else "", e(generated)))

    parts.append('<div class="tiles">')
    for key, cls in (("HIDDEN", "hidden"), ("WEAK", "weak"),
                     ("ANTI-TAMPER", "weak"), ("ok", "")):
        parts.append('<div class="tile %s"><div class="n">%d</div><div class="l">%s</div></div>'
                     % (cls, counts.get(key, 0), e(key)))
    parts.append("</div>")

    flagged = [(d, v) for d, v in pairs if v.verdict != "ok"]
    parts.append("<h2>Findings</h2>")
    if not flagged:
        parts.append("<p>No service descriptor matched a finding rule.</p>")
    else:
        parts.append("<table><thead><tr><th>Verdict</th><th>Service</th><th>Account</th>"
                     "<th>Start</th><th>Enumerated</th><th>Why</th></tr></thead><tbody>")
        for d, v in flagged:
            parts.append("<tr>")
            parts.append('<td><span class="v %s">%s</span></td>' % (e(v.verdict), e(v.verdict)))
            parts.append("<td><strong>%s</strong><br><span class='ace'>%s</span>"
                         % (e(d.source), e(d.extra.get("ImagePath", ""))))
            parts.append('<span class="sddl">%s</span></td>' % e(d.raw))
            parts.append("<td>%s</td>" % e(d.extra.get("Account", "")))
            parts.append("<td>%s</td>" % e(d.extra.get("StartMode", "")))
            parts.append("<td>%s</td>" % e(d.extra.get("EnumVisible", "")))
            parts.append("<td>")
            for r in v.reasons:
                parts.append('<div class="reason">%s</div>' % e(r))
            for ace in d.dacl:
                cls = "deny" if ace.is_deny else "allow"
                parts.append('<div class="ace"><span class="%s">%s</span> %s &rarr; %s</div>'
                             % (cls, e(ace.raw), e(ace.rights_label()), e(ace.sid_label())))
            parts.append("</td></tr>")
        parts.append("</tbody></table>")

    parts.append("<h2>All services</h2>")
    parts.append("<table><thead><tr><th>Verdict</th><th>Service</th><th>Account</th>"
                 "<th>Start</th><th>ACEs</th><th>Descriptor</th></tr></thead><tbody>")
    for d, v in pairs:
        parts.append("<tr>")
        parts.append('<td><span class="v %s">%s</span></td>' % (e(v.verdict), e(v.verdict)))
        parts.append("<td>%s</td>" % e(d.source))
        parts.append("<td>%s</td>" % e(d.extra.get("Account", "")))
        parts.append("<td>%s</td>" % e(d.extra.get("StartMode", "")))
        parts.append("<td>%d</td>" % len(d.dacl))
        parts.append('<td><code>%s</code></td>' % e(d.raw))
        parts.append("</tr>")
    parts.append("</tbody></table>")

    parts.append("<footer>CQSDDLAudit &middot; Paula Januszkiewicz | CQURE &middot; "
                 "Apache License 2.0.<br>"
                 "HIDDEN means the descriptor denies SERVICE_QUERY_STATUS to a principal that "
                 "should be able to list the service, or the service exists in the registry "
                 "while SCM enumeration did not return it.</footer>")
    parts.append("</div></body></html>")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
    print("wrote %s" % path)


def cmd_decode(args: argparse.Namespace) -> int:
    descs = load_input(args)
    rows: List[Dict[str, object]] = []
    for desc in descs:
        print("=" * 78)
        print("source      : %s" % desc.source)
        print("object type : %s%s" % (desc.object_type,
              "  (unqualified, rights read with the file table)"
              if desc.object_type == "generic" else ""))
        print("owner       : %s" % (resolve_sid(desc.owner) if desc.owner else "(absent)"))
        print("group       : %s" % (resolve_sid(desc.group) if desc.group else "(absent)"))
        if desc.dacl_present:
            flags = ",".join(desc.dacl_flags) or "(none)"
            note = ""
            if desc.dacl_null:
                note = "   NULL DACL: everyone is granted everything"
            elif desc.dacl_empty:
                note = "   empty DACL: nothing is granted"
            print("DACL flags  : %s%s" % (flags, note))
        else:
            print("DACL        : absent")
        if desc.sacl_present:
            print("SACL flags  : %s" % (",".join(desc.sacl_flags) or "(none)"))

        violation = check_canonical(desc.dacl)
        print("canonical   : %s" % ("yes" if not violation else "NO, " + violation))
        print("")

        for name, aces in (("DACL", desc.dacl), ("SACL", desc.sacl)):
            if not aces:
                continue
            print("%s, in real order:" % name)
            body = []
            for ace in aces:
                body.append({
                    "#": ace.position,
                    "type": ACE_TYPES.get(ace.ace_type, ace.ace_type),
                    "flags": ",".join(ace.flags) or "-",
                    "rights": ace.rights_label(),
                    "principal": ace.sid_label(),
                })
                rows.append({
                    "Source": desc.source, "ObjectType": desc.object_type, "Acl": name,
                    "Position": ace.position, "Type": ace.ace_type,
                    "Flags": ",".join(ace.flags), "RightsRaw": ace.rights_raw,
                    "Mask": "0x%08X" % ace.mask, "Rights": ace.rights_label(),
                    "Sid": ace.sid, "Principal": ace.sid_label(),
                    "Condition": ace.condition, "Ace": ace.raw,
                })
            print_table(body, ["#", "type", "flags", "rights", "principal"])
            print("")
            for ace in aces:
                if ace.condition:
                    print("  ACE #%d condition: %s" % (ace.position, ace.condition))
                if ace.unresolved_rights:
                    print("  ACE #%d unresolved rights tokens: %s"
                          % (ace.position, ", ".join(ace.unresolved_rights)))
    write_outputs(rows, args)
    return 0


def cmd_order(args: argparse.Namespace) -> int:
    descs = load_input(args)
    rows: List[Dict[str, object]] = []
    for desc in descs:
        violation = check_canonical(desc.dacl)
        if violation is None and not args.all:
            continue
        rows.append({
            "Source": desc.source,
            "ObjectType": desc.object_type,
            "Canonical": "yes" if violation is None else "NO",
            "Violation": violation or "",
            "Aces": len(desc.dacl),
        })
    print_table(rows, ["Source", "ObjectType", "Canonical", "Aces", "Violation"], args.limit)
    write_outputs(rows, args)
    return 0


def cmd_generic(args: argparse.Namespace) -> int:
    descs = load_input(args)
    rows: List[Dict[str, object]] = []
    for desc in descs:
        for ace in desc.dacl:
            if not ace.has_generic:
                continue
            if args.inherit_only and not ace.is_inherit_only:
                continue
            rows.append({
                "Source": desc.source,
                "ObjectType": desc.object_type,
                "#": ace.position,
                "Type": ACE_TYPES.get(ace.ace_type, ace.ace_type),
                "InheritOnly": "yes" if ace.is_inherit_only else "no",
                "Rights": ace.rights_label(),
                "Principal": ace.sid_label(),
                "Ace": ace.raw,
            })
    print_table(rows, ["Source", "#", "Type", "InheritOnly", "Rights", "Principal"], args.limit)
    if rows:
        print("\nThese entries have no row in the Security tab. An inherit-only generic grant\n"
              "affects nothing today and everything created here tomorrow.")
    write_outputs(rows, args)
    return 0


def cmd_risk(args: argparse.Namespace) -> int:
    descs = load_input(args)
    threshold = SEVERITIES.index(args.min_severity)
    findings: List[Finding] = []
    for desc in descs:
        findings.extend(find_risks(desc))
    findings = [f for f in findings if SEVERITIES.index(f.severity) <= threshold]
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.source, f.rule))
    rows = [{"Severity": f.severity, "Source": f.source, "ObjectType": f.object_type,
             "Rule": f.rule, "Detail": f.detail, "Ace": f.ace} for f in findings]
    print_table(rows, ["Severity", "Source", "Rule", "Detail"], args.limit)
    if rows:
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print("\n" + ", ".join("%s: %d" % (s, counts[s]) for s in SEVERITIES if s in counts))
    write_outputs(rows, args)
    return 0


def cmd_access(args: argparse.Namespace) -> int:
    descs = load_input(args)
    tokens = [t for chunk in args.token for t in chunk.split(",") if t.strip()]
    if not tokens:
        raise SystemExit("give at least one --token")

    rows: List[Dict[str, object]] = []
    for desc in descs:
        desired, names, unresolved = parse_rights(args.want, desc.object_type, "A")
        if unresolved:
            raise SystemExit("unrecognised tokens in --want: %s" % ", ".join(unresolved))
        result = simulate_access(desc, tokens, desired)

        print("=" * 78)
        print("source    : %s  (%s)" % (desc.source, desc.object_type))
        print("token     : %s" % ", ".join(resolve_sid(t) for t in tokens))
        print("wanted    : %s  (0x%08X)" % (",".join(names) or args.want, desired))
        print("result    : %s" % ("GRANTED" if result.granted else "DENIED"))
        print("because   : %s" % result.reason)
        if result.decided_by is not None:
            print("decided by: %s" % result.decided_by.raw)
        if not result.granted and result.remaining:
            print("missing   : %s" % (",".join(decode_mask(result.remaining, desc.object_type))
                                      or "0x%08X" % result.remaining))
        if args.explain:
            print("")
            print("walk, in real order:")
            for ace in desc.dacl:
                mark = "  "
                why = ""
                if ace.position in result.evaluated:
                    mark = "->"
                else:
                    why = next((r for p, r in result.skipped if p == ace.position), "")
                print("  %s #%d %-28s %s" % (mark, ace.position, ace.raw, why))
                if result.decided_by is not None and ace.position == result.decided_by.position:
                    print("       ^ this one decided it, entries after it were never reached")
        rows.append({
            "Source": desc.source, "ObjectType": desc.object_type,
            "Token": ",".join(tokens), "Wanted": args.want,
            "Granted": "yes" if result.granted else "no",
            "Reason": result.reason,
            "DecidedBy": result.decided_by.raw if result.decided_by else "",
        })
    write_outputs(rows, args)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    current = {d.source: d for d in load_csv(args.input, args.object_type)}
    baseline = {d.source: d for d in load_csv(args.baseline, args.object_type)}
    rows: List[Dict[str, object]] = []

    for source in sorted(set(current) | set(baseline)):
        cur, base = current.get(source), baseline.get(source)
        if base is None:
            rows.append({"Source": source, "Change": "added", "Detail": cur.raw})
            continue
        if cur is None:
            rows.append({"Source": source, "Change": "removed", "Detail": base.raw})
            continue
        if cur.raw == base.raw:
            continue
        cur_aces = [a.raw for a in cur.dacl]
        base_aces = [a.raw for a in base.dacl]
        if sorted(cur_aces) == sorted(base_aces):
            rows.append({"Source": source, "Change": "reordered",
                         "Detail": "same entries, different order, which can change access"})
        else:
            added = [a for a in cur_aces if a not in base_aces]
            removed = [a for a in base_aces if a not in cur_aces]
            detail = []
            if added:
                detail.append("added " + " ".join(added))
            if removed:
                detail.append("removed " + " ".join(removed))
            if cur.owner != base.owner:
                detail.append("owner %s -> %s" % (base.owner or "(absent)", cur.owner or "(absent)"))
            rows.append({"Source": source, "Change": "changed", "Detail": "; ".join(detail)})

    print_table(rows, ["Source", "Change", "Detail"], args.limit)
    write_outputs(rows, args)
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _add_common(p: argparse.ArgumentParser, *, needs_input: bool = True) -> None:
    if needs_input:
        p.add_argument("--input", help="CSV from Collect-Sddl.ps1")
        p.add_argument("--sddl", help="a single descriptor, instead of --input")
        p.add_argument("--source", default="", help="label for a --sddl descriptor")
    p.add_argument("--object-type", default="generic", choices=OBJECT_TYPES,
                   help="how to read the rights field; two-letter tokens differ per type")
    p.add_argument("--csv", help="write every field to this CSV")
    p.add_argument("--json", help="write every field to this JSON")
    p.add_argument("--limit", type=int, default=40,
                   help="console rows, 0 for all (files always get everything)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="CQSDDLAudit.py",
        description="Offline auditing of Windows security descriptors in SDDL form.",
        epilog="Author: Paula Januszkiewicz | CQURE.  Collect with Collect-Sddl.ps1.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("services", help="the service report, hidden services first")
    _add_common(p)
    p.add_argument("--only-hidden", action="store_true",
                   help="just the services that deny their own enumeration")
    p.add_argument("--all", action="store_true", help="include services with no finding")
    p.add_argument("--html", help="write a self-contained HTML report")
    p.add_argument("--host", default="", help="host label for the report header")
    p.add_argument("--no-color", action="store_true", help="plain text warnings, no ANSI")
    p.set_defaults(func=cmd_services, object_type="service")

    p = sub.add_parser("decode", help="one descriptor, every ACE in real order")
    _add_common(p)
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("order", help="canonical-order violations")
    _add_common(p)
    p.add_argument("--all", action="store_true", help="list clean descriptors too")
    p.set_defaults(func=cmd_order)

    p = sub.add_parser("generic", help="ACEs the Security tab cannot render")
    _add_common(p)
    p.add_argument("--inherit-only", action="store_true",
                   help="only deferred grants, the ones effective-access tooling walks past")
    p.set_defaults(func=cmd_generic)

    p = sub.add_parser("risk", help="pattern findings with severity")
    _add_common(p)
    p.add_argument("--min-severity", default="low", choices=SEVERITIES,
                   help="report this severity and anything worse")
    p.set_defaults(func=cmd_risk)

    p = sub.add_parser("access", help="access-check simulator")
    _add_common(p)
    p.add_argument("--token", action="append", default=[], required=True,
                   help="SID or alias held by the caller; repeat or comma separate")
    p.add_argument("--want", required=True, help="desired access, e.g. FA, WP, 0x120089")
    p.add_argument("--explain", action="store_true", help="show the walk, entry by entry")
    p.set_defaults(func=cmd_access)

    p = sub.add_parser("diff", help="order-aware comparison against a baseline")
    p.add_argument("--input", required=True, help="current CSV")
    p.add_argument("--baseline", required=True, help="baseline CSV")
    p.add_argument("--object-type", default="generic", choices=OBJECT_TYPES)
    p.add_argument("--csv")
    p.add_argument("--json")
    p.add_argument("--limit", type=int, default=40)
    p.set_defaults(func=cmd_diff)

    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SddlError as exc:
        sys.stderr.write("SDDL error: %s\n" % exc)
        return 2
    except FileNotFoundError as exc:
        sys.stderr.write("%s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
