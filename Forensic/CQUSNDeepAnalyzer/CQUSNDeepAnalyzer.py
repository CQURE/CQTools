#!/usr/bin/env python3
r"""
CQUSNDeepAnalyzer
=================

A forensic command-line tool for parsing NTFS USN Journal records from an exported
$UsnJrnl:$J stream and generating a timeline with basic behavioral analysis.

AAuthor: CQURE / Paula Januszkiewicz
License: Apache License 2.0

Supported records:
- USN_RECORD_V2
- USN_RECORD_V3, basic parsing

Typical acquisition examples on Windows:
  fsutil usn readjournal C: csv > usn_fsutil.csv   # not binary, not for this parser

For raw $J extraction, use a forensic acquisition method that can extract the
alternate data stream:
  C:\$Extend\$UsnJrnl:$J

Example usage:
  python CQUSNDeepAnalyzer.py --input J.bin --csv timeline.csv --json timeline.json --html report.html
  python CQUSNDeepAnalyzer.py --input J.bin --csv timeline.csv --include-path C:\Users --min-severity medium

Notes:
- Parent path reconstruction is best-effort. The USN journal stores parent FRN,
  not the full path. This tool builds observed FRN-to-name mappings from records.
- For stronger path reconstruction, correlate with $MFT in a future module.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import datetime as dt
import html
import json
import os
import statistics
import struct
import sys
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import BinaryIO, Deque, Dict, Iterable, List, Optional, Tuple

WINDOWS_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)

REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}

FILE_ATTR_FLAGS = {
    0x00000001: "READONLY",
    0x00000002: "HIDDEN",
    0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY",
    0x00000020: "ARCHIVE",
    0x00000040: "DEVICE",
    0x00000080: "NORMAL",
    0x00000100: "TEMPORARY",
    0x00000200: "SPARSE_FILE",
    0x00000400: "REPARSE_POINT",
    0x00000800: "COMPRESSED",
    0x00001000: "OFFLINE",
    0x00002000: "NOT_CONTENT_INDEXED",
    0x00004000: "ENCRYPTED",
    0x00008000: "INTEGRITY_STREAM",
    0x00020000: "NO_SCRUB_DATA",
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".scr", ".com", ".msi",
}

COMMON_RANSOM_EXTENSIONS = {
    ".locked", ".lockbit", ".encrypted", ".crypt", ".crypted", ".enc", ".ryuk", ".conti", ".blackcat",
    ".akira", ".clop", ".mallox", ".medusa", ".8base", ".blackbasta",
}

# CQURE brand palette (hex approximations of the oklch tokens used in the HTML report).
CQURE_COLORS = {
    "bg":        "#25201D",
    "bg_2":      "#2D2825",
    "bg_3":      "#36312D",
    "line":      "#423E3A",
    "line_2":    "#534F4A",
    "text":      "#F4F2EC",
    "text_dim":  "#B5AEA4",
    "text_mute": "#837C72",
    "accent":    "#DC7B3E",
    "accent_2":  "#C25627",
    "sev_critical": "#B53521",
    "sev_high":     "#DC7B3E",
    "sev_medium":   "#D9A04A",
    "sev_low":      "#837C72",
    "sev_info":     "#5089B8",
    "risk_neutral":   "#5089B8",
    "risk_high_risk": "#D9A04A",
    "risk_ransom":    "#B53521",
}

# Light-theme equivalents for the layout-level Plotly colors (axes, text, hover,
# modebar). Trace colors (REASON_COLOR, severity) stay as-is - they are mid-tone
# and read on both themes. Charts use a transparent paper/plot bg so they inherit
# the page background; only these line/text colors need re-styling on theme switch.
# Hex values approximate the oklch light tokens used in :root[data-theme="light"].
CQURE_COLORS_LIGHT = {
    "bg":        "#F7F4EF",
    "bg_2":      "#FCFAF7",
    "bg_3":      "#E8E3DB",
    "line":      "#DBD5CC",
    "line_2":    "#C3BBAF",
    "text":      "#312B25",
    "text_dim":  "#6A6256",
    "text_mute": "#8F8678",
    "accent":    "#DC7B3E",
}

REASON_COLOR = {
    "FILE_CREATE":         "#6FB874",
    "FILE_DELETE":         "#B53521",
    "RENAME_NEW_NAME":     "#D9A04A",
    "RENAME_OLD_NAME":     "#C29B30",
    "DATA_OVERWRITE":      "#DC7B3E",
    "DATA_EXTEND":         "#C25627",
    "DATA_TRUNCATION":     "#A04022",
    "CLOSE":               "#837C72",
    "BASIC_INFO_CHANGE":   "#5089B8",
    "SECURITY_CHANGE":     "#B470C8",
    "NAMED_DATA_OVERWRITE":"#5E8DA9",
    "NAMED_DATA_EXTEND":   "#4D7B95",
    "EA_CHANGE":           "#A67BBC",
    "STREAM_CHANGE":       "#6FA8B8",
    "ENCRYPTION_CHANGE":   "#9B6FB8",
    "INDEXABLE_CHANGE":    "#6F9BB8",
    "OBJECT_ID_CHANGE":    "#A89280",
    "REPARSE_POINT_CHANGE":"#8FB05E",
    "COMPRESSION_CHANGE":  "#C8B05E",
    "HARD_LINK_CHANGE":    "#7E94B8",
}

DEFAULT_REASON_COLOR = "#837C72"


@dataclass
class USNRecord:
    offset: int
    record_length: int
    major_version: int
    minor_version: int
    file_reference_number: str
    parent_file_reference_number: str
    usn: int
    timestamp_utc: str
    reason: int
    reason_names: List[str]
    source_info: int
    security_id: int
    file_attributes: int
    file_attribute_names: List[str]
    filename: str
    reconstructed_path: str = ""

@dataclass
class EvtxRecord:
    """One Windows Event Log entry, parsed from a pre-extracted CSV.

    Accepts CSV output from EZ Tools `EvtxECmd` or any equivalent (the loader
    looks at a fixed set of column names but is lenient about missing fields).
    """
    timestamp: dt.datetime
    event_id: int
    provider: str
    channel: str
    username: str
    payload: str
    executable_info: str
    source: str


# Event IDs that are forensically interesting on their own (standalone findings).
_EVTX_NOTABLE_EVENTS: Dict[int, Tuple[str, str]] = {
    # event_id : (short_label, severity)
    1102: ("Audit log cleared",           "critical"),  # Security
    4624: ("Successful logon",            "info"),
    4625: ("Failed logon",                "low"),
    4634: ("Logoff",                      "info"),
    4663: ("Object access",               "info"),
    4688: ("Process create",              "info"),
    4689: ("Process exit",                "info"),
    4698: ("Scheduled task created",      "medium"),
    4700: ("Scheduled task enabled",      "low"),
    4720: ("User account created",        "high"),
    4732: ("User added to local group",   "high"),
    4756: ("User added to global group",  "high"),
    7045: ("Service installed",           "medium"),
    7036: ("Service state changed",       "info"),
    1074: ("Shutdown initiated",          "info"),
    4104: ("PowerShell script block",     "low"),
    1100: ("Eventlog service shutdown",   "medium"),
}

# Standalone events: emit a Finding even without a USN burst nearby.
_EVTX_STANDALONE_EVENTS: Dict[int, Tuple[str, str, str]] = {
    1102: (
        "critical",
        "Security audit log was cleared",
        "Security log was cleared (event ID 1102). Classic anti-forensics signal. Investigate the user account responsible (Payload contains SubjectUserName).",
    ),
    4720: (
        "high",
        "User account created",
        "A new user account was created (event ID 4720). On a server in IR context this is unusual; verify if expected.",
    ),
    4732: (
        "high",
        "User added to local privileged group",
        "User added to a local security-enabled group (event ID 4732). Often used to grant admin rights as part of persistence.",
    ),
    4756: (
        "high",
        "User added to global privileged group",
        "User added to a global security-enabled group (event ID 4756). Often abused for AD privilege escalation.",
    ),
    7045: (
        "medium",
        "Service installed",
        "A new Windows service was installed (event ID 7045). Persistent installer / SCM-based execution. Check service path for non-standard locations.",
    ),
    1100: (
        "medium",
        "Event Log service shutdown",
        "Event Log service shutdown event (event ID 1100). Sometimes precedes log tampering.",
    ),
    4698: (
        "medium",
        "Scheduled task created",
        "Scheduled task was created (event ID 4698). Common persistence mechanism.",
    ),
}


def load_evtx_csv(path: str) -> List[EvtxRecord]:
    """Load pre-parsed EVTX records from a CSV (e.g. EvtxECmd output).

    The loader accepts the standard EvtxECmd column names. Missing columns are
    silently tolerated.
    """
    out: List[EvtxRecord] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_str = (
                row.get("TimeCreated")
                or row.get("Timestamp")
                or row.get("TimeGenerated")
                or ""
            ).strip()
            if not ts_str:
                continue
            ts = parse_iso(ts_str.replace(" ", "T"))
            if not ts:
                continue
            try:
                eid = int(row.get("EventId") or row.get("EventID") or 0)
            except (TypeError, ValueError):
                eid = 0
            out.append(EvtxRecord(
                timestamp=ts,
                event_id=eid,
                provider=(row.get("Provider") or "").strip(),
                channel=(row.get("Channel") or "").strip(),
                username=(row.get("UserName") or row.get("User") or "").strip(),
                payload=(row.get("Payload") or row.get("MapDescription") or "").strip(),
                executable_info=(row.get("ExecutableInfo") or "").strip(),
                source=(row.get("SourceFile") or "").strip(),
            ))
    return out


def detect_evtx_standalone_findings(evtx_records: List[EvtxRecord]) -> List[Finding]:
    """Generate findings for forensically-loud EVTX events independent of USN bursts."""
    by_id: Dict[int, List[EvtxRecord]] = {}
    for e in evtx_records:
        if e.event_id in _EVTX_STANDALONE_EVENTS:
            by_id.setdefault(e.event_id, []).append(e)

    findings: List[Finding] = []
    for eid, hits in by_id.items():
        sev, title, desc = _EVTX_STANDALONE_EVENTS[eid]
        samples = []
        for e in hits[:10]:
            who = e.username or "?"
            what = (e.executable_info or e.payload or "").replace("\n", " ")[:140]
            samples.append(
                f"{e.timestamp.isoformat()} [{eid}] user={who} :: {what}"
            )
        first_ts = min(h.timestamp for h in hits).isoformat()
        findings.append(Finding(
            severity=sev,
            category=f"evtx:{eid}",
            title=f"{title} (EVTX {eid})",
            description=f"{desc} {len(hits)} matching event(s).",
            timestamp_utc=first_ts,
            count=len(hits),
            sample_paths=samples,
        ))
    return findings


def enrich_findings_with_evtx_context(
    findings: List[Finding],
    evtx_records: List[EvtxRecord],
    window_seconds: int = 120,
) -> None:
    """Mutate `findings` in place, appending EVTX context lines to high/critical ones."""
    if not evtx_records:
        return
    sorted_evtx = sorted(evtx_records, key=lambda r: r.timestamp)
    ts_list = [r.timestamp for r in sorted_evtx]
    for f in findings:
        if not f.timestamp_utc:
            continue
        if f.severity not in ("critical", "high"):
            continue
        # Skip EVTX-derived findings themselves to avoid double-context.
        if f.category.startswith("evtx"):
            continue
        center = parse_iso(f.timestamp_utc)
        if not center:
            continue
        start = center - dt.timedelta(seconds=window_seconds)
        end = center + dt.timedelta(seconds=window_seconds)
        i_start = bisect.bisect_left(ts_list, start)
        i_end = bisect.bisect_right(ts_list, end)
        window = sorted_evtx[i_start:i_end]
        notable = [e for e in window if e.event_id in _EVTX_NOTABLE_EVENTS]
        if not notable:
            continue
        lines = []
        for e in notable[:8]:
            label, _ = _EVTX_NOTABLE_EVENTS[e.event_id]
            who = e.username or "?"
            what = (e.executable_info or e.payload or "").replace("\n", " ")[:120]
            lines.append(
                f"{e.timestamp.isoformat()} [{e.event_id} {label}] user={who} :: {what}"
            )
        if len(notable) > 8:
            lines.append(f"... and {len(notable) - 8} more events within ±{window_seconds}s")
        f.context_lines = lines


@dataclass
class FilenameRule:
    """A lightweight YARA-style rule matched against USN record filenames/paths.

    All patterns are lower-cased substring matches against `reconstructed_path`
    (falling back to `filename`). The first matching pattern in a record
    contributes one hit for that rule.
    """
    name: str
    patterns: List[str]
    severity: str
    category: str
    description: str
    references: List[str] = field(default_factory=list)


_BUILTIN_FILENAME_RULES: List[FilenameRule] = [
    FilenameRule(
        name="Mimikatz / Kiwi",
        patterns=["mimikatz", "mimilove.exe", "kiwi.exe", "mimispool.dll"],
        severity="critical",
        category="credential_dumping",
        description="Mimikatz / Kiwi credential extractor binary names.",
        references=["https://github.com/gentilkiwi/mimikatz"],
    ),
    FilenameRule(
        name="LSASS memory dump",
        patterns=["lsass.dmp", "lsass_", "lsa.dmp", "lsass.zip", "lsass.bin"],
        severity="critical",
        category="credential_dumping",
        description="Memory dump of LSASS process. Direct evidence of credential theft attempt.",
        references=["https://attack.mitre.org/techniques/T1003/001/"],
    ),
    FilenameRule(
        name="Credential dumping tools",
        patterns=["procdump.exe", "procdump64.exe", "pwdump", "fgdump", "hashdump", "wce.exe", "creddump"],
        severity="high",
        category="credential_dumping",
        description="Known credential-dumping utility binary names (ProcDump, pwdump, fgdump, WCE, creddump).",
    ),
    FilenameRule(
        name="Shadow copy deletion",
        patterns=["vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "vssadmin_", "delete shadows"],
        severity="high",
        category="anti_recovery",
        description=(
            "Volume Shadow Service / backup utility usage. Often abused by ransomware to delete "
            "shadow copies before encryption ('vssadmin delete shadows', 'wbadmin delete catalog'). "
            "Cross-check with mass file rename / write activity nearby."
        ),
        references=["https://attack.mitre.org/techniques/T1490/"],
    ),
    FilenameRule(
        name="Remote access tools (red-team)",
        patterns=["psexec.exe", "psexec64.exe", "paexec.exe", "psexesvc.exe", "ammyy_admin", "atera_setup", "screenconnect"],
        severity="high",
        category="lateral_movement",
        description=(
            "PsExec / PAExec / Ammyy / Atera / ScreenConnect binaries. Legit admin tools "
            "but heavily abused for lateral movement and persistent remote access."
        ),
        references=["https://attack.mitre.org/techniques/T1021/002/"],
    ),
    FilenameRule(
        name="Cobalt Strike artifacts",
        patterns=["beacon.exe", "cobaltstrike", "/beacon/", "\\beacon\\", ".cobaltstrike"],
        severity="critical",
        category="c2_framework",
        description="Cobalt Strike beacon / framework artifact names. High-confidence post-exploitation signal.",
        references=["https://attack.mitre.org/software/S0154/"],
    ),
    FilenameRule(
        name="Cryptominer binaries",
        patterns=["xmrig", "minergate", "nicehash", "phoenixminer", "ethminer", "t-rex.exe", "claymore", "nbminer"],
        severity="high",
        category="cryptomining",
        description="Known cryptominer binaries / installers. Indicates resource abuse, possibly via initial-access malware.",
        references=["https://attack.mitre.org/techniques/T1496/"],
    ),
    FilenameRule(
        name="Ransomware family names",
        patterns=[
            "lockbit", "conti", "ryuk", "akira", "clop", "medusa", "blackcat",
            "blackbasta", "8base", "phobos", "babuk", "darkside", "revil",
            "royal_decryptor", "play_decryptor", "rorschach",
        ],
        severity="critical",
        category="ransomware",
        description="Filename contains a known ransomware family marker. Confirm with ransom-note files and bulk renames.",
    ),
    FilenameRule(
        name="Ransom notes",
        patterns=[
            "readme.txt", "_readme.txt", "how_to_decrypt", "how-to-decrypt",
            "decrypt-instructions", "restore_files", "your_files", "recovery_instructions",
            "_help_", "!!!_help_", "decryptor_",
        ],
        severity="high",
        category="ransomware",
        description="Common ransom note filename patterns. False-positive rate is non-trivial (e.g. README.txt in source repos), correlate with mass-rename burst.",
    ),
    FilenameRule(
        name="Recon / discovery tools",
        patterns=["nmap.exe", "ncat.exe", "nbtscan.exe", "bloodhound", "sharphound", "advanced_ip_scanner", "softperfect_netscan"],
        severity="medium",
        category="recon",
        description="Network discovery / AD recon utility names. Legit admin use possible, but in IR context often paired with lateral movement.",
        references=["https://attack.mitre.org/techniques/T1018/"],
    ),
    FilenameRule(
        name="PowerShell offensive scripts",
        patterns=["invoke-mimikatz", "invoke-mass", "powerview", "nishang", "powerupsql", "empire.ps1", "powersploit"],
        severity="high",
        category="post_exploitation",
        description="Known offensive PowerShell module names. Encrypted/obfuscated variants often slip through; correlate with PowerShell EVTX (4104).",
    ),
    FilenameRule(
        name="Webshells (common names)",
        patterns=[".aspx;", "cmd.aspx", "shell.aspx", "1.aspx", "test.aspx", "asp.jsp", "cmd.jsp", "spy.aspx", "c99.php", "r57.php"],
        severity="critical",
        category="webshell",
        description="Common webshell filenames (.aspx/.jsp/.php). Especially suspicious under \\inetpub\\wwwroot\\.",
        references=["https://attack.mitre.org/techniques/T1505/003/"],
    ),
]


def detect_filename_rule_findings(
    records: List[USNRecord],
    rules: List[FilenameRule],
    baseline_patterns: Optional[List[str]] = None,
) -> List[Finding]:
    """Match records against filename rules; one Finding per matching rule.

    Records whose path matches any baseline pattern are skipped (so Windows Update
    extracts of e.g. legit `procdump.exe` from SysInternals zip don't trigger).
    """
    baseline = baseline_patterns or []
    by_rule: Dict[str, List[USNRecord]] = {}
    for r in records:
        path_l = (r.reconstructed_path or r.filename or "").lower()
        if not path_l:
            continue
        if baseline and any(b in path_l for b in baseline):
            continue
        for rule in rules:
            for pat in rule.patterns:
                if pat in path_l:
                    by_rule.setdefault(rule.name, []).append(r)
                    break  # one rule, one hit per record

    findings: List[Finding] = []
    rules_by_name = {r.name: r for r in rules}
    for rule_name, hits in by_rule.items():
        rule = rules_by_name[rule_name]
        unique_frns = {h.file_reference_number for h in hits}
        unique_paths = list(dict.fromkeys(
            (h.reconstructed_path or h.filename) for h in hits
        ))[:10]
        first_ts = min((h.timestamp_utc for h in hits if h.timestamp_utc), default=None)
        ref_tail = (" Refs: " + ", ".join(rule.references)) if rule.references else ""
        findings.append(Finding(
            severity=rule.severity,
            category=f"yara_lite:{rule.category}",
            title=f"YARA-lite hit: {rule.name}",
            description=(
                f"{rule.description} {len(hits)} USN events across "
                f"{len(unique_frns)} unique files matched.{ref_tail}"
            ),
            timestamp_utc=first_ts,
            count=len(hits),
            sample_paths=unique_paths,
        ))
    return findings


def load_filename_rules_from_json(path: str) -> List[FilenameRule]:
    """Load a list of FilenameRule from a JSON file.

    Format: array of objects with keys matching FilenameRule fields. Unknown
    keys ignored. Patterns are lower-cased on load.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("--rules file must contain a JSON array")
    out: List[FilenameRule] = []
    for i, entry in enumerate(data):
        try:
            out.append(FilenameRule(
                name=str(entry["name"]),
                patterns=[str(p).lower() for p in entry["patterns"]],
                severity=str(entry.get("severity", "medium")),
                category=str(entry.get("category", "custom")),
                description=str(entry.get("description", "")),
                references=[str(r) for r in entry.get("references", [])],
            ))
        except (KeyError, TypeError) as exc:
            raise ValueError(f"--rules entry #{i}: {exc}")
    return out


@dataclass
class MFTRecord:
    frn: str
    parent_frn: str
    filename: str
    is_directory: bool
    in_use: bool
    # $STANDARD_INFORMATION timestamps (Windows FILETIME, 100 ns ticks)
    si_created: int = 0
    si_modified: int = 0
    si_mft_modified: int = 0
    si_accessed: int = 0
    # $FILE_NAME timestamps from the preferred name attribute
    fn_created: int = 0
    fn_modified: int = 0
    fn_mft_modified: int = 0
    fn_accessed: int = 0
    # Alternate Data Stream names (named $DATA attributes only; the default unnamed
    # stream is not included). Empty list means no ADS.
    ads_names: List[str] = field(default_factory=list)
    # Mark-of-the-Web (parsed from resident Zone.Identifier $DATA, if present).
    # ZoneId values: 0=Local, 1=Intranet, 2=Trusted, 3=Internet, 4=Restricted.
    motw_zone_id: int = 0
    motw_host_url: str = ""
    motw_referrer_url: str = ""
    # Derived signals (computed during parsing)
    si_lt_fn: bool = False
    usec_zeros: bool = False
    has_ads: bool = False


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    timestamp_utc: Optional[str] = None
    count: int = 0
    sample_paths: List[str] = field(default_factory=list)
    # Auxiliary context (e.g. EVTX events around finding timestamp). Renderer
    # shows this as a separate block in the finding card.
    context_lines: List[str] = field(default_factory=list)


def filetime_to_iso(filetime: int) -> str:
    try:
        return (WINDOWS_EPOCH + dt.timedelta(microseconds=filetime / 10)).isoformat()
    except Exception:
        return ""


def flags_to_names(value: int, mapping: Dict[int, str]) -> List[str]:
    return [name for bit, name in mapping.items() if value & bit]


def frn_to_string(value: int) -> str:
    # Lower 48 bits: MFT entry number. Upper 16 bits: sequence number.
    entry = value & 0x0000FFFFFFFFFFFF
    seq = (value >> 48) & 0xFFFF
    return f"{entry}-{seq}"


def decode_filename(raw: bytes) -> str:
    try:
        return raw.decode("utf-16le", errors="replace").rstrip("\x00")
    except Exception:
        return "<decode_error>"


def parse_usn_records(handle: BinaryIO, max_records: Optional[int] = None) -> Iterable[USNRecord]:
    offset = 0
    parsed = 0
    data = handle.read()
    size = len(data)

    while offset + 8 <= size:
        record_length = struct.unpack_from("<I", data, offset)[0]
        if record_length == 0:
            offset += 8
            continue
        if record_length < 60 or offset + record_length > size:
            # Move by 8 to resync. USN records are 8-byte aligned.
            offset += 8
            continue

        major, minor = struct.unpack_from("<HH", data, offset + 4)
        try:
            if major == 2:
                # USN_RECORD_V2 fixed header, 60 bytes before filename
                fields = struct.unpack_from("<IHHQQqQIIIIHH", data, offset)
                (
                    rec_len, maj, minv, frn, parent_frn, usn, timestamp, reason,
                    source_info, security_id, file_attrs, filename_length, filename_offset,
                ) = fields
            elif major == 3:
                # USN_RECORD_V3 uses 128-bit file reference identifiers.
                # We keep FRN compact by hashing/hexing the 16-byte values.
                rec_len, maj, minv = struct.unpack_from("<IHH", data, offset)
                frn_raw = data[offset + 8: offset + 24]
                parent_raw = data[offset + 24: offset + 40]
                usn, timestamp, reason, source_info, security_id, file_attrs, filename_length, filename_offset = struct.unpack_from(
                    "<qQIIIIHH", data, offset + 40
                )
                frn = int.from_bytes(frn_raw[:8], "little")
                parent_frn = int.from_bytes(parent_raw[:8], "little")
            else:
                offset += 8
                continue

            filename_start = offset + filename_offset
            filename_end = filename_start + filename_length
            if filename_end > offset + record_length:
                offset += 8
                continue

            filename = decode_filename(data[filename_start:filename_end])
            yield USNRecord(
                offset=offset,
                record_length=record_length,
                major_version=major,
                minor_version=minor,
                file_reference_number=frn_to_string(frn),
                parent_file_reference_number=frn_to_string(parent_frn),
                usn=usn,
                timestamp_utc=filetime_to_iso(timestamp),
                reason=reason,
                reason_names=flags_to_names(reason, REASON_FLAGS),
                source_info=source_info,
                security_id=security_id,
                file_attributes=file_attrs,
                file_attribute_names=flags_to_names(file_attrs, FILE_ATTR_FLAGS),
                filename=filename,
            )
            parsed += 1
            if max_records and parsed >= max_records:
                break
            offset += ((record_length + 7) // 8) * 8
        except Exception:
            offset += 8


_MFT_RECORD_SIZE = 1024
_MFT_SECTOR_SIZE = 512
# $FILE_NAME name_type: 1=Win32, 3=Win32+DOS, 0=POSIX, 2=DOS 8.3
_NAME_TYPE_RANK = {1: 4, 3: 3, 0: 2, 2: 1}
# Windows FILETIME has 100-ns resolution. 10_000_000 ticks == 1 second.
_FILETIME_PER_SECOND = 10_000_000
# Timestomping heuristic: $SI.Created earlier than $FN.Created by at least 1 s.
# Small natural drift exists between $SI and $FN at file creation, so a
# 1-second threshold filters benign noise.
_TIMESTOMP_SI_LT_FN_MIN_DELTA = _FILETIME_PER_SECOND

# ADS names that occur during normal OS / app behavior. Used to triage the
# "interesting" subset of files with alternate data streams from the noisy total.
# Zone.Identifier is the Mark-of-the-Web (MOTW) marker placed by browsers/zip on
# downloaded files; it gets its own analysis in a later stage with content parsing.
# Built-in baseline of NTFS path patterns that routinely trip the timestomping
# detector for benign reasons. CAB extraction (Windows Update), .NET assembly
# install, Defender signature updates and similar mechanisms all bake the
# original archive timestamps into $SI while $FN is set to the on-disk creation
# time. Case-insensitive substring match on the reconstructed path.
_DEFAULT_TIMESTOMP_BASELINE: Tuple[str, ...] = (
    "windows\\softwaredistribution\\",
    "windows\\winsxs\\",
    "windows\\microsoft.net\\",
    "windows\\assembly\\",
    "windows\\servicing\\",
    "windows\\system32\\driverstore\\",
    "windows\\system32\\catroot\\",
    "windows\\system32\\catroot2\\",
    "windows\\system32\\drivers\\fileinfo\\",
    "windows\\appcompat\\",
    "programdata\\microsoft\\windows defender\\",
    "program files\\windowsapps\\",
    "program files (x86)\\microsoft\\",
)

# Executable-like extensions used to upgrade MOTW findings to high/critical when
# the file came from the Internet zone.
_MOTW_EXEC_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".scr", ".ps1", ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".com", ".jar",
}

_BENIGN_ADS_NAMES = {
    "Zone.Identifier",
    "$TXF_DATA",
    "encryptable",
    "SmartScreen",
    "AFP_AfpInfo",
    "AFP_Resource",
    "OECustomProperty",
    "favicon",
    "com.dropbox.attributes",
    "com.apple.metadata",
    "Win32App_1",
    "Win32App_2",
}


def _apply_mft_fixup(buf: bytearray, usa_offset: int, usa_count: int) -> bool:
    """Apply NTFS Update Sequence Array fixup in place. Returns True on success."""
    if usa_count < 2:
        return False
    end = usa_offset + 2 * usa_count
    if end > len(buf):
        return False
    sig = bytes(buf[usa_offset:usa_offset + 2])
    for i in range(1, usa_count):
        sector_tail = i * _MFT_SECTOR_SIZE - 2
        if sector_tail + 2 > len(buf):
            return False
        if bytes(buf[sector_tail:sector_tail + 2]) != sig:
            return False
        orig = bytes(buf[usa_offset + 2 * i:usa_offset + 2 * i + 2])
        buf[sector_tail:sector_tail + 2] = orig
    return True


def parse_mft_records(handle: BinaryIO) -> Iterable[MFTRecord]:
    """Parse a raw $MFT stream and yield MFTRecord objects (best-effort, fault-tolerant).

    Only the minimum needed for path reconstruction is extracted:
    FRN, parent FRN (from $FILE_NAME), preferred filename, in-use/directory flags.
    Skips extension records (base_record_reference != 0).
    """
    data = handle.read()
    n = len(data) // _MFT_RECORD_SIZE
    for ri in range(n):
        off = ri * _MFT_RECORD_SIZE
        rec = bytearray(data[off:off + _MFT_RECORD_SIZE])
        if rec[:4] != b"FILE":
            continue  # BAAD or zeroed
        try:
            usa_offset, usa_count = struct.unpack_from("<HH", rec, 4)
            if not _apply_mft_fixup(rec, usa_offset, usa_count):
                continue
            seq, _hardlinks, attr_off, flags = struct.unpack_from("<HHHH", rec, 16)
            base_ref = struct.unpack_from("<Q", rec, 32)[0]
            if base_ref != 0:
                continue  # extension record (its attrs belong to a base record)
            in_use = bool(flags & 0x1)
            is_dir = bool(flags & 0x2)

            # Iterate attributes.
            best_rank = -1
            filename = ""
            parent_frn = ""
            si_c = si_m = si_mr = si_a = 0
            fn_c = fn_m = fn_mr = fn_a = 0
            ads_names: List[str] = []
            motw_zone_id = 0
            motw_host_url = ""
            motw_referrer_url = ""
            a_off = attr_off
            while a_off + 4 <= _MFT_RECORD_SIZE:
                atype = struct.unpack_from("<I", rec, a_off)[0]
                if atype == 0xFFFFFFFF:
                    break
                if a_off + 16 > _MFT_RECORD_SIZE:
                    break
                arec_len = struct.unpack_from("<I", rec, a_off + 4)[0]
                if arec_len == 0 or a_off + arec_len > _MFT_RECORD_SIZE:
                    break
                if atype == 0x10:  # $STANDARD_INFORMATION
                    non_res = rec[a_off + 8]
                    if non_res == 0:
                        content_off = struct.unpack_from("<H", rec, a_off + 20)[0]
                        si_off = a_off + content_off
                        if si_off + 32 <= _MFT_RECORD_SIZE:
                            si_c, si_m, si_mr, si_a = struct.unpack_from("<QQQQ", rec, si_off)
                elif atype == 0x80:  # $DATA - collect names of *named* streams (ADS).
                    name_len = rec[a_off + 9]
                    if name_len > 0:
                        name_off_local = struct.unpack_from("<H", rec, a_off + 10)[0]
                        name_start = a_off + name_off_local
                        name_end = name_start + 2 * name_len
                        if name_end <= a_off + arec_len <= _MFT_RECORD_SIZE:
                            try:
                                ads = bytes(rec[name_start:name_end]).decode(
                                    "utf-16le", errors="replace"
                                )
                            except Exception:
                                ads = ""
                            if ads:
                                ads_names.append(ads)
                                # Parse Zone.Identifier content if resident.
                                if ads == "Zone.Identifier" and rec[a_off + 8] == 0:
                                    content_len = struct.unpack_from("<I", rec, a_off + 16)[0]
                                    content_off = struct.unpack_from("<H", rec, a_off + 20)[0]
                                    cstart = a_off + content_off
                                    cend = cstart + content_len
                                    if 0 < content_len <= arec_len and cend <= a_off + arec_len <= _MFT_RECORD_SIZE:
                                        motw_text = _decode_motw_bytes(bytes(rec[cstart:cend]))
                                        z, h, r_url = _parse_motw_ini(motw_text)
                                        if z or h or r_url:
                                            motw_zone_id = z
                                            motw_host_url = h
                                            motw_referrer_url = r_url
                elif atype == 0x30:  # $FILE_NAME
                    non_res = rec[a_off + 8]
                    if non_res == 0:
                        content_off = struct.unpack_from("<H", rec, a_off + 20)[0]
                        fn_off = a_off + content_off
                        if fn_off + 66 <= _MFT_RECORD_SIZE:
                            parent_ref = struct.unpack_from("<Q", rec, fn_off)[0]
                            name_len = rec[fn_off + 64]
                            name_type = rec[fn_off + 65]
                            rank = _NAME_TYPE_RANK.get(name_type, 0)
                            name_bytes_end = fn_off + 66 + 2 * name_len
                            if rank > best_rank and name_bytes_end <= _MFT_RECORD_SIZE:
                                try:
                                    fname = bytes(rec[fn_off + 66:name_bytes_end]).decode(
                                        "utf-16le", errors="replace"
                                    )
                                except Exception:
                                    fname = ""
                                if fname:
                                    filename = fname
                                    parent_frn = frn_to_string(parent_ref)
                                    best_rank = rank
                                    # FN timestamps live at offsets 8..40 of the FN content.
                                    if fn_off + 40 <= _MFT_RECORD_SIZE:
                                        fn_c, fn_m, fn_mr, fn_a = struct.unpack_from(
                                            "<QQQQ", rec, fn_off + 8
                                        )
                a_off += arec_len

            if not filename:
                continue

            # Timestomping signals
            si_lt_fn = bool(
                fn_c and si_c and si_c + _TIMESTOMP_SI_LT_FN_MIN_DELTA < fn_c
            )
            usec_zeros = any(
                t > 0 and (t % _FILETIME_PER_SECOND) == 0
                for t in (si_c, si_m, si_mr, si_a)
            )

            # Record number is stored at offset 44 (low 32 bits); combine with sequence.
            ent_num = struct.unpack_from("<I", rec, 44)[0]
            full_frn = (seq << 48) | ent_num
            yield MFTRecord(
                frn=frn_to_string(full_frn),
                parent_frn=parent_frn,
                filename=filename,
                is_directory=is_dir,
                in_use=in_use,
                si_created=si_c, si_modified=si_m,
                si_mft_modified=si_mr, si_accessed=si_a,
                fn_created=fn_c, fn_modified=fn_m,
                fn_mft_modified=fn_mr, fn_accessed=fn_a,
                ads_names=ads_names,
                motw_zone_id=motw_zone_id,
                motw_host_url=motw_host_url,
                motw_referrer_url=motw_referrer_url,
                si_lt_fn=si_lt_fn,
                usec_zeros=usec_zeros,
                has_ads=bool(ads_names),
            )
        except Exception:
            continue


def build_mft_path_map(mft_records: List[MFTRecord]) -> Dict[str, str]:
    """Build FRN -> full reconstructed path (without leading separator)."""
    by_frn: Dict[str, MFTRecord] = {r.frn: r for r in mft_records}
    cache: Dict[str, str] = {}

    def resolve(frn: str, visiting: set) -> str:
        if frn in cache:
            return cache[frn]
        if frn in visiting or len(visiting) > 128:
            return ""
        rec = by_frn.get(frn)
        if not rec:
            return ""
        # NTFS root directory has entry 5 and points to itself as parent.
        if rec.frn == rec.parent_frn or rec.frn.startswith("5-"):
            cache[frn] = ""
            return ""
        visiting.add(frn)
        parent_path = resolve(rec.parent_frn, visiting) if rec.parent_frn else ""
        visiting.discard(frn)
        full = (parent_path + "\\" + rec.filename) if parent_path else rec.filename
        cache[frn] = full
        return full

    out: Dict[str, str] = {}
    for r in mft_records:
        out[r.frn] = resolve(r.frn, set())
    return out


def _decode_motw_bytes(buf: bytes) -> str:
    """Decode the raw Zone.Identifier $DATA bytes to text, respecting BOM if present."""
    if buf.startswith(b"\xff\xfe"):
        return buf[2:].decode("utf-16-le", errors="replace")
    if buf.startswith(b"\xfe\xff"):
        return buf[2:].decode("utf-16-be", errors="replace")
    if buf.startswith(b"\xef\xbb\xbf"):
        return buf[3:].decode("utf-8", errors="replace")
    return buf.decode("utf-8", errors="replace")


def _parse_motw_ini(text: str) -> Tuple[int, str, str]:
    """Parse Zone.Identifier INI body. Returns (zone_id, host_url, referrer_url)."""
    zone_id = 0
    host_url = ""
    referrer_url = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith(";") or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "zoneid":
            try:
                zone_id = int(v)
            except ValueError:
                pass
        elif k == "hosturl":
            host_url = v
        elif k == "referrerurl":
            referrer_url = v
    return zone_id, host_url, referrer_url


def _load_baseline_patterns(
    path: Optional[str], include_defaults: bool
) -> List[str]:
    """Build the timestomping baseline pattern list.

    Combines built-in defaults (Windows Update / WinSxS / .NET / Defender / etc.)
    with optional user-provided patterns from a text file. The file format is
    one substring per line, '#' for comments, blank lines ignored. All patterns
    are lower-cased for case-insensitive substring matching.
    """
    patterns: List[str] = []
    if include_defaults:
        patterns.extend(p.lower() for p in _DEFAULT_TIMESTOMP_BASELINE)
    if path:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                s = raw.strip()
                if not s or s.startswith("#"):
                    continue
                patterns.append(s.lower())
    return patterns


def _baseline_matches(rec: MFTRecord, mft_path_map: Dict[str, str], patterns: List[str]) -> bool:
    """True if the record's reconstructed path matches any baseline pattern."""
    if not patterns:
        return False
    p = mft_path_map.get(rec.frn) or rec.filename
    if not p:
        return False
    pl = p.lower()
    for pat in patterns:
        if pat in pl:
            return True
    return False


def _is_ntfs_system_entry(rec: MFTRecord) -> bool:
    """True for the first 16 MFT entries reserved by NTFS ($MFT, $LogFile, root, etc.).

    These records routinely have peculiar timestamps (e.g. all-zero seconds boundaries
    set by the filesystem itself) and would dominate timestomping findings as false
    positives if not filtered.
    """
    try:
        return int(rec.frn.split("-", 1)[0]) < 16
    except (ValueError, IndexError):
        return False


def _is_ntfs_internal(rec: MFTRecord) -> bool:
    """Broader filter that also excludes children of NTFS metadata directories.

    Covers reserved entries (0..15) AND NTFS-internal files like everything inside
    $Extend\\ ($RmMetadata\\$Repair, $UsnJrnl with $J/$Max streams, $ObjId, $Quota,
    $Reparse, etc.). Convention: NTFS internal file names always start with '$'.
    """
    if _is_ntfs_system_entry(rec):
        return True
    return rec.filename.startswith("$")


def _mft_full_path(rec: MFTRecord, mft_path_map: Dict[str, str]) -> str:
    """Resolve an MFTRecord to a printable full path using the path map."""
    parent_path = mft_path_map.get(rec.parent_frn, "")
    if parent_path:
        return parent_path + "\\" + rec.filename
    return rec.filename


def detect_timestomping_findings(
    mft_records: List[MFTRecord],
    mft_path_map: Dict[str, str],
    baseline_patterns: Optional[List[str]] = None,
) -> List[Finding]:
    """Generate Findings for timestamp manipulation signals (Etap 2).

    Two independent detections:
    1. $SI.Created earlier than $FN.Created by >=1 s (classic SetFileTime / Mimikatz timestomp).
    2. At least one $SI timestamp exactly on a 1-second boundary (sub-second zeros).

    Optional `baseline_patterns` is a list of lowercased substrings that, when
    matched against the reconstructed path, exclude the record from findings.
    Built-in defaults cover Windows Update / WinSxS / .NET / Defender artifacts
    where benign timestamp anomalies are routine.
    """
    patterns = baseline_patterns or []

    si_pre_baseline = [
        r for r in mft_records if r.si_lt_fn and not _is_ntfs_system_entry(r)
    ]
    usec_pre_baseline = [
        r for r in mft_records if r.usec_zeros and not _is_ntfs_system_entry(r)
    ]
    si_lt_fn_records = [
        r for r in si_pre_baseline if not _baseline_matches(r, mft_path_map, patterns)
    ]
    usec_records = [
        r for r in usec_pre_baseline if not _baseline_matches(r, mft_path_map, patterns)
    ]
    si_excluded = len(si_pre_baseline) - len(si_lt_fn_records)
    usec_excluded = len(usec_pre_baseline) - len(usec_records)
    baseline_tag = (
        f" Baseline filter excluded {si_excluded}/{usec_excluded} (si/usec) routine entries."
        if patterns and (si_excluded or usec_excluded)
        else ""
    )

    findings: List[Finding] = []

    if si_lt_fn_records:
        n = len(si_lt_fn_records)
        sev = "critical" if n > 100 else ("high" if n > 10 else "medium")
        sample = [_mft_full_path(r, mft_path_map) for r in si_lt_fn_records[:10]]
        earliest = min(
            (r.si_created for r in si_lt_fn_records if r.si_created > 0),
            default=0,
        )
        findings.append(Finding(
            severity=sev,
            category="timestomping_si_lt_fn",
            title="Timestomping signal: $SI.Created earlier than $FN.Created",
            description=(
                f"{n} files where $STANDARD_INFORMATION.Created is at least one second earlier "
                f"than $FILE_NAME.Created. $FN times are normally write-protected by the kernel, "
                f"so a back-dated $SI is a classic forgery signal (Mimikatz timestomp, Cobalt Strike, "
                f"SetFileTime). Investigate the listed files." + baseline_tag
            ),
            timestamp_utc=filetime_to_iso(earliest) if earliest else None,
            count=n,
            sample_paths=sample,
        ))

    if usec_records:
        n = len(usec_records)
        sev = "high" if n > 100 else ("medium" if n > 10 else "low")
        sample = [_mft_full_path(r, mft_path_map) for r in usec_records[:10]]
        findings.append(Finding(
            severity=sev,
            category="timestomping_usec_zeros",
            title="Timestomping signal: zeroed sub-second precision in $SI",
            description=(
                f"{n} files where at least one $STANDARD_INFORMATION timestamp lands exactly "
                f"on a 1-second boundary (microseconds == 0). NTFS preserves 100 ns resolution, "
                f"so round timestamps usually come from explicit SetFileTime / API-driven "
                f"manipulation. Cross-check with $SI<$FN finding for stronger signal." + baseline_tag
            ),
            count=n,
            sample_paths=sample,
        ))

    return findings


def detect_ads_findings(
    mft_records: List[MFTRecord], mft_path_map: Dict[str, str]
) -> List[Finding]:
    """Generate Findings for files carrying Alternate Data Streams (Etap 3).

    Two grades:
    1. Any non-system file with at least one named $DATA stream.
    2. Subset whose ADS name is NOT in _BENIGN_ADS_NAMES (i.e. not the usual
       Zone.Identifier / SmartScreen / TXF noise). These warrant direct review.
    """
    all_ads: List[MFTRecord] = []
    suspicious: List[Tuple[MFTRecord, List[str]]] = []
    for r in mft_records:
        if not r.has_ads or _is_ntfs_internal(r):
            continue
        all_ads.append(r)
        interesting = [n for n in r.ads_names if n not in _BENIGN_ADS_NAMES]
        if interesting:
            suspicious.append((r, interesting))

    findings: List[Finding] = []

    if all_ads:
        n = len(all_ads)
        sev = "low" if n > 100 else ("info" if n > 0 else "info")
        # Sample paths annotated with ADS names like "file.txt:Zone.Identifier".
        sample_lines = []
        for r in all_ads[:10]:
            base = _mft_full_path(r, mft_path_map)
            sample_lines.append(base + ":" + ",".join(r.ads_names))
        findings.append(Finding(
            severity=sev,
            category="ads_present",
            title="Alternate Data Streams observed",
            description=(
                f"{n} files carry at least one named $DATA stream beyond the default. "
                f"Most are benign (Zone.Identifier / SmartScreen / TXF metadata); see the "
                f"separate finding for streams whose names are not on the known-benign list."
            ),
            count=n,
            sample_paths=sample_lines,
        ))

    if suspicious:
        n = len(suspicious)
        sev = "critical" if n > 100 else ("high" if n > 10 else "medium")
        sample_lines = []
        for r, names in suspicious[:10]:
            base = _mft_full_path(r, mft_path_map)
            sample_lines.append(base + ":" + ",".join(names))
        findings.append(Finding(
            severity=sev,
            category="ads_suspicious",
            title="Files with non-standard Alternate Data Streams",
            description=(
                f"{n} files carry $DATA streams whose names are not in the known-benign list "
                f"(Zone.Identifier, $TXF_DATA, SmartScreen, etc.). Custom-named ADS is a classic "
                f"hiding technique for payloads and configuration. Review the listed files."
            ),
            count=n,
            sample_paths=sample_lines,
        ))

    return findings


def detect_motw_findings(
    mft_records: List[MFTRecord], mft_path_map: Dict[str, str]
) -> List[Finding]:
    """Generate Findings for files carrying Mark-of-the-Web (Etap 4).

    Two grades:
    1. Any non-system file with a populated Zone.Identifier (zone_id > 0).
    2. Subset that is an executable file (EXE/DLL/MSI/script/etc.) AND comes from
       the Internet/Restricted zone (zone_id >= 3). Highest priority for triage:
       these are downloaded EXE candidates for execution evidence correlation.
    """
    motw_records = [
        r for r in mft_records
        if r.motw_zone_id and not _is_ntfs_internal(r)
    ]
    if not motw_records:
        return []

    exec_internet: List[MFTRecord] = []
    for r in motw_records:
        if r.motw_zone_id < 3:
            continue
        _, ext = os.path.splitext(r.filename.lower())
        if ext in _MOTW_EXEC_EXTENSIONS:
            exec_internet.append(r)

    findings: List[Finding] = []

    def fmt_motw_sample(r: MFTRecord, with_url: bool = True) -> str:
        base = _mft_full_path(r, mft_path_map)
        parts = [base, f"zone={r.motw_zone_id}"]
        if with_url and r.motw_host_url:
            parts.append(f"host={r.motw_host_url}")
        if with_url and r.motw_referrer_url and r.motw_referrer_url != r.motw_host_url:
            parts.append(f"ref={r.motw_referrer_url}")
        return " | ".join(parts)

    n_all = len(motw_records)
    sev = "low" if n_all > 10 else "info"
    findings.append(Finding(
        severity=sev,
        category="motw_observed",
        title="Mark-of-the-Web (Zone.Identifier) on files",
        description=(
            f"{n_all} files carry a populated Zone.Identifier ADS, marking them as downloaded "
            f"from outside the local computer. ZoneId: 0=Local, 1=Intranet, 2=Trusted, "
            f"3=Internet, 4=Restricted. Inspect HostUrl/ReferrerUrl values for file provenance."
        ),
        count=n_all,
        sample_paths=[fmt_motw_sample(r) for r in motw_records[:10]],
    ))

    if exec_internet:
        n_exec = len(exec_internet)
        sev = "critical" if n_exec > 5 else "high"
        findings.append(Finding(
            severity=sev,
            category="motw_executable_internet",
            title="Executable files downloaded from the Internet (MOTW)",
            description=(
                f"{n_exec} executable files (EXE/DLL/MSI/script/etc.) carry MOTW with ZoneId>=3 "
                f"(Internet/Restricted). Review the provenance URLs; correlate with execution "
                f"evidence (Prefetch, Amcache, Shimcache) to confirm whether they ran."
            ),
            count=n_exec,
            sample_paths=[fmt_motw_sample(r) for r in exec_internet[:10]],
        ))

    return findings


def reconstruct_paths(records: List[USNRecord], mft_path_map: Optional[Dict[str, str]] = None) -> None:
    """Best-effort path reconstruction using observed FRN parent/name mappings."""
    names: Dict[str, str] = {}
    parents: Dict[str, str] = {}

    for r in records:
        if r.filename:
            names[r.file_reference_number] = r.filename
            parents[r.file_reference_number] = r.parent_file_reference_number

    def build_path(frn: str, fallback_name: str) -> str:
        parts = []
        seen = set()
        cur = frn
        while cur and cur not in seen and cur in names:
            seen.add(cur)
            parts.append(names.get(cur, ""))
            cur = parents.get(cur, "")
            if len(parts) > 128:
                break
        if not parts and fallback_name:
            return fallback_name
        return "\\".join(reversed([p for p in parts if p]))

    for r in records:
        # Prefer $MFT-derived parent path when available; otherwise fall back to
        # USN-only best-effort reconstruction. Falling back per-record means a
        # record whose parent FRN isn't represented in $MFT still gets the
        # observed-journal path.
        mft_parent_path = mft_path_map.get(r.parent_file_reference_number) if mft_path_map else None
        if mft_parent_path:
            r.reconstructed_path = mft_parent_path + "\\" + r.filename if r.filename else mft_parent_path
        else:
            r.reconstructed_path = build_path(r.file_reference_number, r.filename)


def filter_records(records: Iterable[USNRecord], include_path: Optional[str], exclude_path: Optional[str]) -> List[USNRecord]:
    output = []
    inc = include_path.lower() if include_path else None
    exc = exclude_path.lower() if exclude_path else None
    for r in records:
        hay = (r.reconstructed_path or r.filename or "").lower()
        if inc and inc not in hay:
            continue
        if exc and exc in hay:
            continue
        output.append(r)
    return output


def parse_iso(ts: str) -> Optional[dt.datetime]:
    try:
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None


def analyze(records: List[USNRecord], window_seconds: int = 60) -> List[Finding]:
    findings: List[Finding] = []
    records_sorted = sorted(records, key=lambda r: r.timestamp_utc)

    # Overall reason statistics
    reason_counter = Counter()
    ext_counter = Counter()
    for r in records_sorted:
        reason_counter.update(r.reason_names)
        _, ext = os.path.splitext(r.filename.lower())
        if ext:
            ext_counter[ext] += 1

    # Burst detection
    window: Deque[USNRecord] = deque()
    max_burst = 0
    max_burst_at = None
    max_burst_sample: List[str] = []
    for r in records_sorted:
        ts = parse_iso(r.timestamp_utc)
        if not ts:
            continue
        window.append(r)
        while window:
            first_ts = parse_iso(window[0].timestamp_utc)
            if first_ts and (ts - first_ts).total_seconds() > window_seconds:
                window.popleft()
            else:
                break
        if len(window) > max_burst:
            max_burst = len(window)
            max_burst_at = r.timestamp_utc
            max_burst_sample = [(x.reconstructed_path or x.filename) for x in list(window)[-10:]]

    if max_burst >= 1000:
        findings.append(Finding(
            severity="high",
            category="burst_activity",
            title="High-volume filesystem activity burst",
            description=f"Observed {max_burst} USN records within {window_seconds} seconds. This may indicate automation, deployment, backup activity, malware activity, or ransomware-like behavior.",
            timestamp_utc=max_burst_at,
            count=max_burst,
            sample_paths=max_burst_sample,
        ))
    elif max_burst >= 250:
        findings.append(Finding(
            severity="medium",
            category="burst_activity",
            title="Medium-volume filesystem activity burst",
            description=f"Observed {max_burst} USN records within {window_seconds} seconds.",
            timestamp_utc=max_burst_at,
            count=max_burst,
            sample_paths=max_burst_sample,
        ))

    # Rename and delete wave detection
    rename_new = [r for r in records_sorted if "RENAME_NEW_NAME" in r.reason_names]
    deletes = [r for r in records_sorted if "FILE_DELETE" in r.reason_names]
    creates = [r for r in records_sorted if "FILE_CREATE" in r.reason_names]
    writes = [r for r in records_sorted if any(x in r.reason_names for x in ["DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION"])]

    if len(rename_new) >= 500:
        sample = [(r.reconstructed_path or r.filename) for r in rename_new[:10]]
        findings.append(Finding(
            severity="high",
            category="rename_wave",
            title="Mass rename activity detected",
            description=f"Observed {len(rename_new)} RENAME_NEW_NAME records. Mass renames can be normal in migrations, but are also a common ransomware signal.",
            timestamp_utc=rename_new[0].timestamp_utc if rename_new else None,
            count=len(rename_new),
            sample_paths=sample,
        ))

    if len(deletes) >= 500:
        sample = [(r.reconstructed_path or r.filename) for r in deletes[:10]]
        findings.append(Finding(
            severity="medium",
            category="delete_wave",
            title="Mass delete activity detected",
            description=f"Observed {len(deletes)} FILE_DELETE records. This can indicate cleanup, user activity, software deployment, or destructive behavior.",
            timestamp_utc=deletes[0].timestamp_utc if deletes else None,
            count=len(deletes),
            sample_paths=sample,
        ))

    # Ransomware-like extension signal
    ransom_ext_hits = []
    for r in rename_new:
        _, ext = os.path.splitext(r.filename.lower())
        if ext in COMMON_RANSOM_EXTENSIONS:
            ransom_ext_hits.append(r)
    if ransom_ext_hits:
        findings.append(Finding(
            severity="critical",
            category="ransomware_extension",
            title="Known ransomware-like extension activity",
            description=f"Observed {len(ransom_ext_hits)} renamed files with extensions commonly seen in ransomware cases.",
            timestamp_utc=ransom_ext_hits[0].timestamp_utc,
            count=len(ransom_ext_hits),
            sample_paths=[(r.reconstructed_path or r.filename) for r in ransom_ext_hits[:10]],
        ))

    # Suspicious executable/script creation
    suspicious_creates = []
    for r in creates:
        _, ext = os.path.splitext(r.filename.lower())
        path = (r.reconstructed_path or r.filename).lower()
        if ext in HIGH_RISK_EXTENSIONS and any(p in path for p in ["temp", "appdata", "programdata", "users\\public", "windows\\tasks"]):
            suspicious_creates.append(r)
    if suspicious_creates:
        findings.append(Finding(
            severity="medium",
            category="suspicious_file_create",
            title="Potential tool or payload staging",
            description="Executable or script files were created in locations often used for staging.",
            timestamp_utc=suspicious_creates[0].timestamp_utc,
            count=len(suspicious_creates),
            sample_paths=[(r.reconstructed_path or r.filename) for r in suspicious_creates[:10]],
        ))

    # Summary scale finding
    if records_sorted:
        findings.append(Finding(
            severity="info",
            category="summary",
            title="USN timeline summary",
            description=(
                f"Parsed {len(records_sorted)} records. Creates: {len(creates)}, writes: {len(writes)}, "
                f"renames: {len(rename_new)}, deletes: {len(deletes)}. Top reasons: {reason_counter.most_common(5)}."
            ),
            timestamp_utc=records_sorted[0].timestamp_utc,
            count=len(records_sorted),
            sample_paths=[],
        ))

    return findings


# ---------- Aggregations for the HTML report ----------

def pick_bin_seconds(records: List[USNRecord]) -> int:
    """Heuristic time-bucket size that targets a sensible number of buckets on the timeline."""
    if not records:
        return 60
    first = parse_iso(records[0].timestamp_utc)
    last = parse_iso(records[-1].timestamp_utc)
    if not first or not last:
        return 60
    duration = max(1.0, (last - first).total_seconds())
    if duration < 3600:
        return 60
    if duration < 86400:
        return 300
    if duration < 86400 * 7:
        return 3600
    if duration < 86400 * 30:
        return 86400
    return 86400 * 7


def _bucket_iso(ts: dt.datetime, bin_seconds: int) -> str:
    bucket = int(ts.timestamp() // bin_seconds) * bin_seconds
    return dt.datetime.fromtimestamp(bucket, dt.timezone.utc).isoformat()


def aggregate_timeline(records: List[USNRecord], bin_seconds: int) -> List[Tuple[str, int]]:
    bins: Dict[str, int] = defaultdict(int)
    for r in records:
        ts = parse_iso(r.timestamp_utc)
        if not ts:
            continue
        bins[_bucket_iso(ts, bin_seconds)] += 1
    return sorted(bins.items())


def aggregate_hour_day_matrix(records: List[USNRecord]) -> List[List[int]]:
    matrix = [[0] * 24 for _ in range(7)]
    for r in records:
        ts = parse_iso(r.timestamp_utc)
        if not ts:
            continue
        matrix[ts.weekday()][ts.hour] += 1
    return matrix


def aggregate_reasons_over_time(records: List[USNRecord], bin_seconds: int, top_n: int = 8) -> Dict[str, List[Tuple[str, int]]]:
    totals: Counter = Counter()
    for r in records:
        totals.update(r.reason_names)
    top_reasons = [name for name, _ in totals.most_common(top_n)]

    series: Dict[str, Dict[str, int]] = {name: defaultdict(int) for name in top_reasons}
    for r in records:
        ts = parse_iso(r.timestamp_utc)
        if not ts:
            continue
        bucket = _bucket_iso(ts, bin_seconds)
        for name in r.reason_names:
            if name in series:
                series[name][bucket] += 1

    return {name: sorted(buckets.items()) for name, buckets in series.items()}


def aggregate_extensions(records: List[USNRecord], top_n: int = 20) -> List[Tuple[str, int, str]]:
    counter: Counter = Counter()
    for r in records:
        _, ext = os.path.splitext(r.filename.lower())
        if ext:
            counter[ext] += 1
    rows: List[Tuple[str, int, str]] = []
    for ext, count in counter.most_common(top_n):
        if ext in COMMON_RANSOM_EXTENSIONS:
            risk = "ransom"
        elif ext in HIGH_RISK_EXTENSIONS:
            risk = "high_risk"
        else:
            risk = "neutral"
        rows.append((ext, count, risk))
    return rows


def aggregate_paths_tree(records: List[USNRecord], top_n: int = 80, max_depth: int = 6) -> Tuple[List[str], List[str], List[str], List[int]]:
    """Returns (ids, labels, parents, values) for a Plotly treemap.

    `ids` and `parents` use the full path string so labels can repeat across branches.
    """
    counter: Counter = Counter()
    for r in records:
        path = r.reconstructed_path or r.filename
        if not path:
            continue
        parts = [p for p in path.split("\\") if p][:max_depth]
        for d in range(1, len(parts) + 1):
            counter["\\".join(parts[:d])] += 1

    top_items = counter.most_common(top_n)
    top_paths = {p for p, _ in top_items}

    ids: List[str] = []
    labels: List[str] = []
    parents: List[str] = []
    values: List[int] = []

    for full_path, count in top_items:
        parts = full_path.split("\\")
        leaf = parts[-1] if parts else full_path
        parent_path = "\\".join(parts[:-1])
        parent_id = parent_path if parent_path in top_paths else ""
        ids.append(full_path)
        labels.append(leaf or full_path)
        parents.append(parent_id)
        values.append(count)

    return ids, labels, parents, values


def _path_bucket(path: str) -> str:
    """Classify a reconstructed path into a small set of forensic-relevant buckets."""
    if not path:
        return "Other"
    p = path.lower()
    # NTFS-internal paths first.
    if p.startswith("$") or "\\$" in p:
        return "NTFS internal"
    # User-specific subtrees - high-value forensic locations.
    if "\\users\\" in p or p.startswith("users\\"):
        if "\\appdata\\local\\temp\\" in p:
            return "Users\\*\\AppData\\Local\\Temp"
        if "\\appdata\\local\\" in p:
            return "Users\\*\\AppData\\Local"
        if "\\appdata\\roaming\\" in p:
            return "Users\\*\\AppData\\Roaming"
        if "\\downloads\\" in p:
            return "Users\\*\\Downloads"
        if "\\documents\\" in p:
            return "Users\\*\\Documents"
        if "\\desktop\\" in p:
            return "Users\\*\\Desktop"
        return "Users\\*\\Other"
    # Windows subtrees.
    if "\\windows\\softwaredistribution\\" in p or p.startswith("windows\\softwaredistribution\\"):
        return "Windows\\SoftwareDistribution"
    if "\\windows\\winsxs\\" in p or p.startswith("windows\\winsxs\\"):
        return "Windows\\WinSxS"
    if "\\windows\\system32\\" in p or p.startswith("windows\\system32\\"):
        return "Windows\\System32"
    if "\\windows\\temp\\" in p or p.startswith("windows\\temp\\"):
        return "Windows\\Temp"
    if "\\windows\\" in p or p.startswith("windows\\"):
        return "Windows\\Other"
    # Program files and shared data.
    if "\\program files (x86)\\" in p or p.startswith("program files (x86)\\"):
        return "Program Files (x86)"
    if "\\program files\\" in p or p.startswith("program files\\"):
        return "Program Files"
    if "\\programdata\\" in p or p.startswith("programdata\\"):
        return "ProgramData"
    return "Other"


def aggregate_sankey(
    records: List[USNRecord],
    top_reasons: int = 10,
    top_exts: int = 15,
    top_buckets: int = 12,
) -> Dict[str, List[Dict[str, object]]]:
    """Build node/link payload for a 3-column Plotly Sankey: reason -> ext -> path bucket."""
    reason_ext: Counter = Counter()
    ext_bucket: Counter = Counter()
    reason_totals: Counter = Counter()
    ext_totals: Counter = Counter()
    bucket_totals: Counter = Counter()

    for r in records:
        path = r.reconstructed_path or r.filename
        _, ext = os.path.splitext(r.filename.lower())
        if not ext:
            ext = "(none)"
        bucket = _path_bucket(path)
        bucket_totals[bucket] += 1
        ext_totals[ext] += 1
        ext_bucket[(ext, bucket)] += 1
        for reason_name in r.reason_names:
            reason_totals[reason_name] += 1
            reason_ext[(reason_name, ext)] += 1

    top_r = {name for name, _ in reason_totals.most_common(top_reasons)}
    top_e = {name for name, _ in ext_totals.most_common(top_exts)}
    top_b = {name for name, _ in bucket_totals.most_common(top_buckets)}

    nodes: List[Dict[str, object]] = []
    node_idx: Dict[str, int] = {}

    def add_node(name: str, color: str) -> int:
        if name not in node_idx:
            node_idx[name] = len(nodes)
            nodes.append({"label": name, "color": color})
        return node_idx[name]

    # Columns in this order (Plotly arranges left-to-right by appearance and link flow).
    for name in sorted(top_r, key=lambda n: -reason_totals[n]):
        add_node(name, REASON_COLOR.get(name, DEFAULT_REASON_COLOR))
    for name in sorted(top_e, key=lambda n: -ext_totals[n]):
        color = (
            CQURE_COLORS["risk_ransom"] if name in COMMON_RANSOM_EXTENSIONS else
            CQURE_COLORS["risk_high_risk"] if name in HIGH_RISK_EXTENSIONS else
            CQURE_COLORS["risk_neutral"]
        )
        add_node(name, color)
    for name in sorted(top_b, key=lambda n: -bucket_totals[n]):
        n_lower = name.lower()
        # Elevate visual emphasis for risk-prone locations.
        if "temp" in n_lower or "appdata" in n_lower or name == "NTFS internal":
            color = CQURE_COLORS["risk_high_risk"]
        elif "downloads" in n_lower or "desktop" in n_lower:
            color = CQURE_COLORS["sev_info"]
        else:
            color = CQURE_COLORS["text_mute"]
        add_node(name, color)

    links: List[Dict[str, object]] = []

    def with_alpha(hex_color: str, alpha_hex: str = "55") -> str:
        # Plotly accepts rgba/hex; appending hex alpha works in modern browsers.
        return hex_color + alpha_hex if hex_color.startswith("#") and len(hex_color) == 7 else hex_color

    for (reason, ext), count in reason_ext.items():
        if reason in top_r and ext in top_e:
            links.append({
                "source": node_idx[reason],
                "target": node_idx[ext],
                "value": count,
                "color": with_alpha(REASON_COLOR.get(reason, DEFAULT_REASON_COLOR), "55"),
            })
    for (ext, bucket), count in ext_bucket.items():
        if ext in top_e and bucket in top_b:
            # Link color follows the extension's risk class for stronger visual cue
            # of "where do risky extensions land".
            ext_color = (
                CQURE_COLORS["risk_ransom"] if ext in COMMON_RANSOM_EXTENSIONS else
                CQURE_COLORS["risk_high_risk"] if ext in HIGH_RISK_EXTENSIONS else
                CQURE_COLORS["risk_neutral"]
            )
            links.append({
                "source": node_idx[ext],
                "target": node_idx[bucket],
                "value": count,
                "color": with_alpha(ext_color, "55"),
            })

    return {"nodes": nodes, "links": links}


def _prefetch_exe_from_filename(pf_name: str) -> str:
    """Extract the underlying executable name from a Prefetch filename.

    Prefetch filename format: `EXECUTABLE.EXE-XXXXXXXX.pf` where XXXXXXXX is a path hash.
    For a few special files (NTOSBOOT-B00DFAAD.pf, AgRobust.db) the format differs;
    we fall back to dropping the .pf extension only.
    """
    name = pf_name
    if name.lower().endswith(".pf"):
        name = name[:-3]
    if "-" in name:
        head, _ = name.rsplit("-", 1)
        if head:
            return head
    return name


def detect_prefetch_executions(
    records: List[USNRecord],
    rules: Optional[List[FilenameRule]] = None,
) -> Tuple[List[Finding], Dict[str, List[USNRecord]]]:
    """Identify executables that ran by looking for their Prefetch entries in USN.

    Returns (findings, by_exe). `by_exe` maps EXE name (uppercase) to the USN
    records that touched its `.pf` file. Used both for direct findings and for
    enriching other findings' context.
    """
    pf_records: List[USNRecord] = []
    for r in records:
        path_l = (r.reconstructed_path or r.filename or "").lower()
        if path_l.endswith(".pf") and "windows\\prefetch\\" in path_l:
            pf_records.append(r)

    if not pf_records:
        return [], {}

    by_exe: Dict[str, List[USNRecord]] = defaultdict(list)
    for r in pf_records:
        exe = _prefetch_exe_from_filename(r.filename).upper()
        by_exe[exe].append(r)

    findings: List[Finding] = []

    # Generic finding: every executable that left a Prefetch artifact.
    top_exes = sorted(by_exe.items(), key=lambda x: -len(x[1]))[:20]
    samples = []
    for exe, recs in top_exes:
        first = min(r.timestamp_utc for r in recs)
        last = max(r.timestamp_utc for r in recs)
        samples.append(f"{exe} ({len(recs)} pf events, first @ {first}, last @ {last})")
    earliest = min(r.timestamp_utc for r in pf_records)
    findings.append(Finding(
        severity="info",
        category="prefetch_observed",
        title="Executables observed via Prefetch entries",
        description=(
            f"{len(by_exe)} unique executables left Prefetch artifacts in the journal "
            f"(top 20 shown). Each '.pf' write event implies that executable ran on this host."
        ),
        timestamp_utc=earliest,
        count=len(pf_records),
        sample_paths=samples,
    ))

    # Suspicious: cross-match against the active filename rule set.
    # An EXE that BOTH matches a YARA-lite rule AND has a Prefetch entry is the
    # strongest correlation we have without an EVTX feed: "this rule-hit binary
    # actually ran".
    if rules:
        suspicious_hits: List[Tuple[str, List[USNRecord], FilenameRule]] = []
        for exe, recs in by_exe.items():
            exe_l = exe.lower()
            for rule in rules:
                if any(pat in exe_l for pat in rule.patterns):
                    suspicious_hits.append((exe, recs, rule))
                    break

        if suspicious_hits:
            # Severity rolls up to the worst rule.
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            worst = min(
                (sev_order.get(rule.severity, 9) for _, _, rule in suspicious_hits),
                default=9,
            )
            sev = {v: k for k, v in sev_order.items()}.get(worst, "high")
            sample_lines = []
            for exe, recs, rule in suspicious_hits[:15]:
                first = min(r.timestamp_utc for r in recs)
                sample_lines.append(
                    f"{exe} matched rule '{rule.name}' (sev={rule.severity}); first pf write @ {first}"
                )
            findings.append(Finding(
                severity=sev,
                category="prefetch_suspicious_execution",
                title="Suspicious executables observed running (Prefetch + filename rules)",
                description=(
                    f"{len(suspicious_hits)} unique executables matched a YARA-lite filename rule "
                    f"AND have a Prefetch entry in this journal. Prefetch is created when an "
                    f"executable is launched - this is execution evidence for the rule hits."
                ),
                timestamp_utc=min(min(r.timestamp_utc for r in recs) for _, recs, _ in suspicious_hits),
                count=sum(len(recs) for _, recs, _ in suspicious_hits),
                sample_paths=sample_lines,
            ))

    return findings, dict(by_exe)


def enrich_findings_with_prefetch_context(
    findings: List[Finding],
    prefetch_by_exe: Dict[str, List[USNRecord]],
    window_seconds: int = 300,
) -> None:
    """For each high/critical finding with a timestamp, append "EXE launched" lines."""
    if not prefetch_by_exe:
        return
    # Build a flat list of (ts_dt, exe, original_iso) sorted by time.
    flat: List[Tuple[dt.datetime, str, str]] = []
    for exe, recs in prefetch_by_exe.items():
        for r in recs:
            ts = parse_iso(r.timestamp_utc)
            if ts:
                flat.append((ts, exe, r.timestamp_utc))
    if not flat:
        return
    flat.sort()
    ts_only = [t for t, _, _ in flat]

    for f in findings:
        if not f.timestamp_utc:
            continue
        if f.severity not in ("critical", "high"):
            continue
        # Skip prefetch-derived findings themselves.
        if f.category.startswith("prefetch"):
            continue
        center = parse_iso(f.timestamp_utc)
        if not center:
            continue
        start = center - dt.timedelta(seconds=window_seconds)
        end = center + dt.timedelta(seconds=window_seconds)
        i_start = bisect.bisect_left(ts_only, start)
        i_end = bisect.bisect_right(ts_only, end)
        window = flat[i_start:i_end]
        if not window:
            continue
        # Dedupe by EXE within the window (one line per EXE).
        seen: Dict[str, str] = {}
        for _, exe, iso in window:
            if exe not in seen:
                seen[exe] = iso
        lines = [f"{iso}  [PF] {exe}" for exe, iso in list(seen.items())[:8]]
        if len(seen) > 8:
            lines.append(f"... and {len(seen) - 8} more executables with pf events in ±{window_seconds}s")
        # Append, do not replace - keep EVTX context if already there.
        f.context_lines = (f.context_lines or []) + lines


def find_new_extension_outliers(
    records: List[USNRecord],
    late_fraction: float = 0.3,
    min_count: int = 10,
    top_n: int = 15,
) -> List[Tuple[str, int, dt.datetime]]:
    """Return extensions whose first appearance falls into the last `late_fraction`
    of the observed time window AND have at least `min_count` total events.

    Records must be sorted by timestamp_utc (`main()` sorts before calling).
    """
    if not records:
        return []
    first_ts = parse_iso(records[0].timestamp_utc)
    last_ts = parse_iso(records[-1].timestamp_utc)
    if not first_ts or not last_ts or last_ts <= first_ts:
        return []
    total_seconds = (last_ts - first_ts).total_seconds()
    threshold = first_ts + dt.timedelta(seconds=total_seconds * (1.0 - late_fraction))

    ext_first: Dict[str, dt.datetime] = {}
    ext_count: Counter = Counter()
    for r in records:
        _, ext = os.path.splitext(r.filename.lower())
        if not ext:
            continue
        ts = parse_iso(r.timestamp_utc)
        if not ts:
            continue
        if ext not in ext_first:
            ext_first[ext] = ts
        ext_count[ext] += 1

    outliers: List[Tuple[str, int, dt.datetime]] = []
    for ext, fs in ext_first.items():
        if fs >= threshold and ext_count[ext] >= min_count:
            outliers.append((ext, ext_count[ext], fs))
    outliers.sort(key=lambda x: -x[1])
    return outliers[:top_n]


def detect_new_extensions_findings(
    records: List[USNRecord],
    late_fraction: float = 0.3,
    min_count: int = 10,
) -> List[Finding]:
    """Finding for extensions emerging only in the late window (early-ransomware signal)."""
    outliers = find_new_extension_outliers(records, late_fraction, min_count)
    if not outliers:
        return []

    has_ransom = any(ext in COMMON_RANSOM_EXTENSIONS for ext, _, _ in outliers)
    has_risk = any(ext in HIGH_RISK_EXTENSIONS for ext, _, _ in outliers)
    if has_ransom:
        sev = "critical"
    elif has_risk:
        sev = "high"
    else:
        sev = "medium"

    earliest = min(fs for _, _, fs in outliers)
    samples = [
        f"{ext}  ({_fmt_int(count)} events, first @ {fs.isoformat()})"
        for ext, count, fs in outliers
    ]
    pct_late = int(late_fraction * 100)
    return [Finding(
        severity=sev,
        category="new_extensions_outlier",
        title="File extensions emerging late in the timeline",
        description=(
            f"{len(outliers)} file extensions appeared only in the last {pct_late}% of the "
            f"observed time window (min {min_count} events each). Sudden new extensions late "
            f"in the timeline are a classic early-stage ransomware signal even when the family "
            f"name does not match any known ransomware list."
        ),
        timestamp_utc=earliest.isoformat(),
        count=sum(c for _, c, _ in outliers),
        sample_paths=samples,
    )]


def find_max_burst(records: List[USNRecord], window_seconds: int = 60) -> Tuple[int, Optional[str]]:
    """Returns (max_burst_count, timestamp_iso) regardless of severity threshold."""
    if not records:
        return 0, None
    records_sorted = sorted(records, key=lambda r: r.timestamp_utc)
    window: Deque[USNRecord] = deque()
    best = 0
    best_ts: Optional[str] = None
    for r in records_sorted:
        ts = parse_iso(r.timestamp_utc)
        if not ts:
            continue
        window.append(r)
        while window:
            first_ts = parse_iso(window[0].timestamp_utc)
            if first_ts and (ts - first_ts).total_seconds() > window_seconds:
                window.popleft()
            else:
                break
        if len(window) > best:
            best = len(window)
            best_ts = r.timestamp_utc
    return best, best_ts


def top_path(records: List[USNRecord], depth: int = 3) -> Tuple[str, int]:
    counter: Counter = Counter()
    for r in records:
        path = r.reconstructed_path or r.filename
        if not path:
            continue
        parts = [p for p in path.split("\\") if p][:depth]
        if parts:
            counter["\\".join(parts)] += 1
    if not counter:
        return ("", 0)
    return counter.most_common(1)[0]


# ---------- HTML report renderers ----------

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _load_plotly_js(override_path: Optional[str] = None) -> str:
    """Returns the content of plotly.min.js for inline embedding, or '' if unavailable."""
    if override_path:
        candidates = [override_path]
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(here, "vendor", "plotly.min.js"),
            os.path.join(here, "plotly.min.js"),
        ]
    for candidate in candidates:
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as exc:
                print(f"Warning: failed to read {candidate}: {exc}", file=sys.stderr)
    return ""


def _safe_json(value: object) -> str:
    """JSON-encode value safely for embedding inside a <script> block."""
    return json.dumps(value, ensure_ascii=False, default=str).replace("</", "<\\/")


def _render_theme_js() -> str:
    """JS for the header light/dark toggle.

    The page UI (header, tables, findings, modal) switches purely via CSS custom
    properties on :root[data-theme]. Plotly charts bake their layout colors at
    generation time (CQURE_COLORS), so on a theme switch we re-style the
    layout-level colors of each chart via Plotly.relayout. Trace colors are left
    untouched - they are mid-tone and read on both themes. Cartesian charts get
    axis colors; sankey/treemap (no axes) only get font/hover/modebar.
    """
    keys = ("text", "text_dim", "text_mute", "bg_2", "bg_3", "line", "line_2", "accent")
    colors = {
        "dark": {k: CQURE_COLORS[k] for k in keys},
        "light": {k: CQURE_COLORS_LIGHT[k] for k in keys},
    }
    return (
        "(function(){"
        f"var C={_safe_json(colors)};"
        "var CART=['chart-timeline','chart-heatmap','chart-reasons','chart-extensions'];"
        "var NONCART=['chart-sankey','chart-treemap'];"
        "function common(c){return {'font.color':c.text_dim,'hoverlabel.bgcolor':c.bg_2,"
        "'hoverlabel.bordercolor':c.line_2,'hoverlabel.font.color':c.text,"
        "'modebar.color':c.text_mute,'modebar.activecolor':c.accent};}"
        "function axes(c){return {'xaxis.gridcolor':c.line,'xaxis.linecolor':c.line_2,"
        "'xaxis.zerolinecolor':c.line_2,'xaxis.tickcolor':c.line_2,'yaxis.gridcolor':c.line,"
        "'yaxis.linecolor':c.line_2,'yaxis.zerolinecolor':c.line_2,'yaxis.tickcolor':c.line_2};}"
        "function relayoutOne(id,patch){var el=document.getElementById(id);"
        "if(!el||!el.data||typeof Plotly==='undefined')return;"
        "try{Plotly.relayout(el,patch);}catch(e){}}"
        "function restyle(theme){if(typeof Plotly==='undefined')return;var c=C[theme]||C.dark;"
        "var base=common(c);CART.forEach(function(id){var p={};for(var k in base)p[k]=base[k];"
        "var a=axes(c);for(var k2 in a)p[k2]=a[k2];"
        "if(id==='chart-timeline')p['xaxis.rangeslider.bgcolor']=c.bg_3;relayoutOne(id,p);});"
        "NONCART.forEach(function(id){relayoutOne(id,base);});}"
        "function current(){return document.documentElement.getAttribute('data-theme')==='light'?'light':'dark';}"
        "function apply(theme){if(theme==='light')document.documentElement.setAttribute('data-theme','light');"
        "else document.documentElement.removeAttribute('data-theme');"
        "try{localStorage.setItem('cqusn-theme',theme);}catch(e){}restyle(theme);}"
        "var btn=document.getElementById('themeToggle');"
        "if(btn)btn.addEventListener('click',function(){apply(current()==='light'?'dark':'light');});"
        "function init(){if(current()==='light')restyle('light');}"
        "if(typeof Plotly!=='undefined'){requestAnimationFrame(init);}"
        "else{window.addEventListener('load',function(){requestAnimationFrame(init);});}"
        "})();"
    )


def _render_section_nav_js() -> str:
    """JS for the fixed section rail (jump-to nav with scrollspy).

    Built client-side by scanning the DOM for content sections so it reflects
    whichever sections were actually emitted (charts are conditional). Each item
    smooth-scrolls to its section; an IntersectionObserver highlights the section
    currently near the top. Uses CSS variables, so it adapts to light/dark.
    """
    return (
        "(function(){"
        "var secs=Array.prototype.slice.call("
        "document.querySelectorAll('section.section[id^=\"section-\"]'));"
        "if(secs.length<2)return;"
        "var nav=document.createElement('nav');nav.className='section-rail';"
        "nav.setAttribute('aria-label','Sections');"
        "var items=secs.map(function(s){"
        "var h2=s.querySelector('.section-head h2');"
        "var label=h2?h2.textContent.trim():s.id;"
        "var b=document.createElement('button');b.className='rail-item';b.type='button';"
        "b.setAttribute('data-target',s.id);b.title=label;"
        "var t=document.createElement('span');t.className='rail-text';t.textContent=label;"
        "var d=document.createElement('span');d.className='rail-dot';"
        "b.appendChild(t);b.appendChild(d);"
        "b.addEventListener('click',function(){"
        "var el=document.getElementById(s.id);"
        "if(el)el.scrollIntoView({behavior:'smooth',block:'start'});});"
        "nav.appendChild(b);return b;});"
        "document.body.appendChild(nav);"
        "function setActive(id){items.forEach(function(it){"
        "it.classList.toggle('active',it.getAttribute('data-target')===id);});}"
        "function spy(){var line=window.innerHeight*0.28;var cur=secs[0].id;"
        "for(var i=0;i<secs.length;i++){"
        "if(secs[i].getBoundingClientRect().top<=line)cur=secs[i].id;}"
        "setActive(cur);}"
        "var raf=null;function onScroll(){if(raf)return;"
        "raf=requestAnimationFrame(function(){raf=null;spy();});}"
        "window.addEventListener('scroll',onScroll,{passive:true});"
        "window.addEventListener('resize',onScroll);"
        "spy();"
        "})();"
    )


def _fmt_int(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def _format_duration(records: List[USNRecord]) -> Tuple[str, str]:
    if not records:
        return ("0", "no data")
    first = parse_iso(records[0].timestamp_utc)
    last = parse_iso(records[-1].timestamp_utc)
    if not first or not last:
        return ("?", "")
    seconds = (last - first).total_seconds()
    if seconds < 3600:
        return (f"{int(seconds / 60)}", "minutes")
    if seconds < 86400:
        return (f"{seconds / 3600:.1f}", "hours")
    if seconds < 86400 * 30:
        return (f"{seconds / 86400:.1f}", "days")
    return (f"{seconds / 86400:.0f}", "days")


def _plotly_layout_base() -> Dict[str, object]:
    grid = CQURE_COLORS["line"]
    line = CQURE_COLORS["line_2"]
    return {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {
            "color": CQURE_COLORS["text_dim"],
            "family": "'JetBrains Mono', 'Cascadia Mono', Consolas, ui-monospace, monospace",
            "size": 11,
        },
        "margin": {"l": 60, "r": 24, "t": 16, "b": 56},
        "xaxis": {"gridcolor": grid, "linecolor": line, "zerolinecolor": line, "tickcolor": line},
        "yaxis": {"gridcolor": grid, "linecolor": line, "zerolinecolor": line, "tickcolor": line},
        "hoverlabel": {
            "bgcolor": CQURE_COLORS["bg_2"],
            "bordercolor": CQURE_COLORS["line_2"],
            "font": {"color": CQURE_COLORS["text"], "family": "'JetBrains Mono', monospace", "size": 11},
        },
        "modebar": {
            "bgcolor": "rgba(0,0,0,0)",
            "color": CQURE_COLORS["text_mute"],
            "activecolor": CQURE_COLORS["accent"],
        },
    }


def _section_open(section_id: str, title: str, crumb: str) -> str:
    return (
        f"<section class='section' id='{html.escape(section_id)}'>"
        f"<div class='section-head'>"
        f"<h2>{html.escape(title)}</h2>"
        f"<div class='crumbs'>{html.escape(crumb)}</div>"
        f"</div>"
    )


def _section_close() -> str:
    return "</section>"


def _render_top_strip(meta: Dict[str, object]) -> str:
    generated = html.escape(str(meta.get("generated_iso", "")))
    record_count = _fmt_int(int(meta.get("record_count", 0)))
    source = html.escape(str(meta.get("source", "")))
    return (
        "<div class='util'><div class='util-inner'>"
        "<div class='util-left'>"
        f"<span>USN ANALYSIS · {generated}</span>"
        f"<span>{record_count} RECORDS</span>"
        f"<span>SRC: {source}</span>"
        "</div>"
        "<div class='util-right'>"
        "<span class='util-dot'></span>"
        "<span>CQUSN DEEP ANALYZER · OFFLINE FORENSIC REPORT</span>"
        "</div>"
        "</div></div>"
    )


def _render_header_nav(meta: Dict[str, object]) -> str:
    rng = meta.get("time_range") or ("", "")
    range_text = ""
    if rng[0] and rng[1]:
        range_text = f"RANGE: {rng[0]}  →  {rng[1]}"
    return (
        "<header class='nav'><div class='nav-inner'>"
        "<a class='logo' href='#'>"
        "<div class='logo-text'>"
        "<span class='brandline'>C<span class='q'>Q</span>URE<span class='cur'></span></span>"
        "<small>/ usn deep analyzer</small>"
        "</div>"
        "</a>"
        "<div class='nav-right'>"
        f"<div class='nav-meta'><span>{html.escape(range_text)}</span></div>"
        "<button class='theme-toggle' id='themeToggle' aria-label='Toggle light/dark theme' title='Toggle light/dark theme'>"
        "<svg class='ic ic-sun' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><circle cx='12' cy='12' r='4.5'></circle><path d='M12 2v2M12 20v2M4 12H2M22 12h-2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19'></path></svg>"
        "<svg class='ic ic-moon' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z'></path></svg>"
        "</button>"
        "</div>"
        "</div></header>"
    )


def _render_hero(records: List[USNRecord], findings: List[Finding], meta: Dict[str, object]) -> str:
    sev_count = Counter(f.severity for f in findings)
    burst_count = int(meta.get("max_burst", 0))
    burst_window = int(meta.get("burst_window", 60))
    span_val, span_unit = _format_duration(records)
    record_count = _fmt_int(len(records))
    finding_total = sum(sev_count[s] for s in ("critical", "high", "medium", "low"))
    crit = sev_count.get("critical", 0)
    high = sev_count.get("high", 0)

    if crit:
        accent_word = "critical"
    elif high:
        accent_word = "elevated"
    else:
        accent_word = "deconstructed"

    top_p, top_p_count = meta.get("top_path", ("", 0))
    top_path_html = html.escape(top_p) if top_p else "no path data"

    return (
        "<section class='hero'>"
        "<div class='grid-bg'></div>"
        "<div class='hero-inner'>"
        "<div class='tag-row'>"
        "<span class='pill'>FORENSIC REPORT · USN $J</span>"
        "<div class='meta'>"
        f"<span>{record_count} RECORDS</span>"
        f"<span>{finding_total} FINDINGS</span>"
        f"<span>{html.escape(str(meta.get('bin_seconds', 60)))}s BIN</span>"
        "</div>"
        "</div>"
        "<h1 class='headline'>Activity timeline<br>"
        f"<span class='accent'>{html.escape(accent_word)}</span></h1>"
        "<p class='sub'>Automated parse of <strong>NTFS USN Journal $J</strong> with behavioral analysis "
        f"across <strong>{record_count}</strong> records. Most active path: "
        f"<strong>{top_path_html}</strong> ({_fmt_int(int(top_p_count))} events).</p>"
        "<div class='facts'>"
        "<div class='fact'>"
        "<div class='fact-label'>Total records</div>"
        f"<div class='fact-value'>{record_count} <small>parsed</small></div>"
        "</div>"
        "<div class='fact'>"
        "<div class='fact-label'>Critical</div>"
        f"<div class='fact-value {('crit' if crit else '')}'>{crit} <small>/ {finding_total} findings</small></div>"
        "</div>"
        "<div class='fact'>"
        "<div class='fact-label'>High</div>"
        f"<div class='fact-value {('high' if high else '')}'>{high} <small>findings</small></div>"
        "</div>"
        "<div class='fact'>"
        "<div class='fact-label'>Max burst</div>"
        f"<div class='fact-value'>{_fmt_int(burst_count)} <small>/ {burst_window}s window</small></div>"
        "</div>"
        "<div class='fact'>"
        "<div class='fact-label'>Time span</div>"
        f"<div class='fact-value'>{span_val} <small>{span_unit}</small></div>"
        "</div>"
        "</div>"
        "</div>"
        "</section>"
    )


def _severity_color(severity: str) -> str:
    return CQURE_COLORS.get(f"sev_{severity}", CQURE_COLORS["accent"])


def _compute_finding_sparkline_counts(
    finding: Finding,
    sorted_records: List[USNRecord],
    sorted_ts_iso: List[str],
    window_seconds: int = 1800,
    buckets: int = 60,
) -> List[int]:
    """Return per-bucket event counts in a window centered on finding.timestamp_utc.

    Uses pre-sorted timestamps + bisect for O(log N + match_count) lookups,
    so calling this for every finding stays cheap even on 300k+ records.
    """
    if not finding.timestamp_utc:
        return []
    pivot = parse_iso(finding.timestamp_utc)
    if not pivot:
        return []
    half = window_seconds / 2
    start_dt = pivot - dt.timedelta(seconds=half)
    end_dt = pivot + dt.timedelta(seconds=half)
    start_iso = start_dt.isoformat()
    end_iso = end_dt.isoformat()
    i_start = bisect.bisect_left(sorted_ts_iso, start_iso)
    i_end = bisect.bisect_right(sorted_ts_iso, end_iso)
    if i_end <= i_start:
        return [0] * buckets
    counts = [0] * buckets
    bucket_dur = window_seconds / buckets
    start_ts = start_dt.timestamp()
    for r in sorted_records[i_start:i_end]:
        rt = parse_iso(r.timestamp_utc)
        if not rt:
            continue
        idx = int((rt.timestamp() - start_ts) / bucket_dur)
        if 0 <= idx < buckets:
            counts[idx] += 1
    return counts


def _render_sparkline_svg(counts: List[int], severity: str, width: int = 160, height: int = 34) -> str:
    """Inline SVG sparkline. Polyline + filled area + dashed vertical peak marker."""
    if not counts or max(counts) == 0:
        return ""
    n = len(counts)
    max_v = max(counts)
    color = _severity_color(severity)
    pad_top = 4
    pad_bot = 2
    avail_h = height - pad_top - pad_bot
    inner_w = width - 2
    pts = []
    for i, v in enumerate(counts):
        x = 1 + i * inner_w / (n - 1) if n > 1 else width / 2
        y = pad_top + avail_h - (v / max_v) * avail_h
        pts.append(f"{x:.1f},{y:.1f}")
    poly_line = " ".join(pts)
    # area = polyline closed down to baseline
    poly_area = poly_line + f" {1 + inner_w:.1f},{height} 1,{height}"
    peak_idx = counts.index(max_v)
    peak_x = 1 + peak_idx * inner_w / (n - 1) if n > 1 else width / 2
    total = sum(counts)
    title = f"{total} events in {n}-bucket window · peak {max_v} at bucket {peak_idx + 1}/{n}"
    return (
        f"<svg class='sparkline' viewBox='0 0 {width} {height}' width='{width}' height='{height}' "
        f"role='img' aria-label='{html.escape(title)}'>"
        f"<title>{html.escape(title)}</title>"
        f"<polyline points='{poly_area}' fill='{color}' fill-opacity='0.18' stroke='none'/>"
        f"<polyline points='{poly_line}' fill='none' stroke='{color}' stroke-width='1.3' stroke-linejoin='round'/>"
        f"<line x1='{peak_x:.1f}' y1='1' x2='{peak_x:.1f}' y2='{height - 1}' "
        f"stroke='{color}' stroke-width='1' stroke-dasharray='2,2' opacity='0.7'/>"
        f"</svg>"
    )


def _render_anomaly_strip(
    findings: List[Finding],
    sorted_records: List[USNRecord],
    width: int = 1360,
    height: int = 42,
) -> str:
    """Top-of-report strip spanning the whole observed time range with finding markers.

    Findings are sorted by severity rank, identically to _render_findings, so that
    `data-finding-idx` lines up with the `id='finding-{idx}'` attribute on each
    finding-card for click-to-scroll.
    """
    if not sorted_records or not findings:
        return ""
    first = parse_iso(sorted_records[0].timestamp_utc)
    last = parse_iso(sorted_records[-1].timestamp_utc)
    if not first or not last or last <= first:
        return ""
    span = (last - first).total_seconds()
    ordered = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 9))
    markers = []
    legend_seen: List[str] = []
    for i, f in enumerate(ordered):
        if not f.timestamp_utc:
            continue
        ts = parse_iso(f.timestamp_utc)
        if not ts:
            continue
        x = max(1, min(width - 1, ((ts - first).total_seconds() / span) * width))
        sev = f.severity if f.severity in SEVERITY_RANK else "info"
        color = _severity_color(sev)
        tooltip = f"[{sev.upper()}] {f.title} · {f.timestamp_utc}"
        markers.append(
            f"<line class='ano-mark sev-{sev}' x1='{x:.1f}' y1='4' x2='{x:.1f}' y2='{height - 4}' "
            f"stroke='{color}' stroke-width='2' data-finding-idx='{i}'>"
            f"<title>{html.escape(tooltip)}</title>"
            f"</line>"
        )
        if sev not in legend_seen:
            legend_seen.append(sev)
    if not markers:
        return ""

    # Baseline line for the strip.
    baseline = (
        f"<line x1='0' y1='{height / 2:.1f}' x2='{width}' y2='{height / 2:.1f}' "
        f"stroke='{CQURE_COLORS['line']}' stroke-width='1'/>"
    )
    legend = " ".join(
        f"<span class='ano-leg sev-{s}' style='--leg:{_severity_color(s)}'>{s}</span>"
        for s in sorted(legend_seen, key=lambda x: SEVERITY_RANK.get(x, 9))
    )
    return (
        "<section class='anomaly-section'>"
        "<div class='anomaly-inner'>"
        "<div class='anomaly-head'>"
        "<span class='anomaly-label'>// ANOMALY STRIP</span>"
        f"<span class='anomaly-range'>{html.escape(sorted_records[0].timestamp_utc)}"
        f" → {html.escape(sorted_records[-1].timestamp_utc)}</span>"
        f"<span class='anomaly-legend'>{legend}</span>"
        "</div>"
        f"<svg class='anomaly-strip' id='anomaly-strip-svg' viewBox='0 0 {width} {height}' "
        f"preserveAspectRatio='none' width='100%' height='{height}'>"
        f"{baseline}{''.join(markers)}"
        "</svg>"
        "</div>"
        "<script>(function(){"
        "var s=document.getElementById('anomaly-strip-svg');"
        "if(!s) return;"
        "s.addEventListener('click', function(e){"
        "var t=e.target;"
        "if(!t.classList||!t.classList.contains('ano-mark')) return;"
        "var idx=t.getAttribute('data-finding-idx');"
        "var el=document.getElementById('finding-'+idx);"
        "if(el){ el.scrollIntoView({behavior:'smooth',block:'start'}); "
        "el.style.transition='outline 0.2s'; el.style.outline='2px solid '+t.getAttribute('stroke'); "
        "setTimeout(function(){ el.style.outline='none'; }, 1500); }"
        "});"
        "})();</script>"
        "</section>"
    )


def _render_findings(findings: List[Finding], records: Optional[List[USNRecord]] = None) -> str:
    if not findings:
        return (
            _section_open("section-findings", "Findings", "// behavioral analysis")
            + "<p class='sub'>No findings produced by the analyzer.</p>"
            + _section_close()
        )
    ordered = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 9))
    sorted_records: List[USNRecord] = records or []
    sorted_ts_iso = [r.timestamp_utc for r in sorted_records]
    cards = []
    for idx, f in enumerate(ordered):
        sev = f.severity if f.severity in SEVERITY_RANK else "info"
        samples_items = "".join(f"<li>{html.escape(s)}</li>" for s in (f.sample_paths or [])[:10])
        samples_html = f"<div class='finding-samples'><ul>{samples_items}</ul></div>" if samples_items else ""
        context_items = "".join(f"<li>{html.escape(s)}</li>" for s in (f.context_lines or []))
        context_html = (
            f"<details class='finding-context'><summary>EVTX context · {len(f.context_lines)} events within ±2 min</summary>"
            f"<ul>{context_items}</ul></details>"
        ) if context_items else ""
        meta_html = (
            f"category: {html.escape(f.category)}"
            + (f" · count: {_fmt_int(f.count)}" if f.count else "")
            + (f" · time: {html.escape(str(f.timestamp_utc))}" if f.timestamp_utc else "")
        )
        spark_html = ""
        if sorted_records and f.timestamp_utc:
            counts = _compute_finding_sparkline_counts(f, sorted_records, sorted_ts_iso)
            spark_svg = _render_sparkline_svg(counts, sev)
            if spark_svg:
                spark_html = f"<div class='finding-spark'>{spark_svg}<span class='finding-spark-cap'>events ±15 min</span></div>"
        cards.append(
            f"<article class='finding {sev}' id='finding-{idx}'>"
            f"<div class='finding-head'>"
            f"<div class='finding-title'>"
            f"<span class='sev-badge {sev}'>{sev}</span>"
            f"<span>{html.escape(f.title)}</span>"
            f"</div>"
            f"<div class='finding-meta'>{meta_html}</div>"
            f"{spark_html}"
            f"</div>"
            f"<p class='finding-desc'>{html.escape(f.description)}</p>"
            f"{samples_html}"
            f"{context_html}"
            f"</article>"
        )
    return (
        _section_open("section-findings", "Findings", "// behavioral analysis")
        + "<div class='findings-grid'>"
        + "".join(cards)
        + "</div>"
        + _section_close()
    )


def _render_timeline_chart(timeline: List[Tuple[str, int]], findings: List[Finding], bin_seconds: int) -> str:
    if not timeline:
        return ""
    burst_points = [
        {"x": f.timestamp_utc, "y": f.count, "severity": f.severity, "title": f.title}
        for f in findings if f.category == "burst_activity" and f.timestamp_utc
    ]
    payload = {
        "buckets": timeline,
        "bursts": burst_points,
        "binSeconds": bin_seconds,
        "colors": {
            "bar": CQURE_COLORS["accent"],
            "critical": CQURE_COLORS["sev_critical"],
            "high": CQURE_COLORS["sev_high"],
            "medium": CQURE_COLORS["sev_medium"],
            "info": CQURE_COLORS["sev_info"],
            "low": CQURE_COLORS["sev_low"],
            "edge": CQURE_COLORS["text"],
        },
    }
    layout = _plotly_layout_base()
    layout["xaxis"].update({"type": "date", "rangeslider": {"thickness": 0.06, "bgcolor": CQURE_COLORS["bg_3"]}})
    layout["yaxis"].update({"title": "records / bucket"})
    layout["showlegend"] = True
    layout["legend"] = {"orientation": "h", "y": 1.08, "x": 0}

    script = (
        "(function(){"
        "if(typeof Plotly==='undefined')return;"
        f"var d={_safe_json(payload)};"
        f"var layout={_safe_json(layout)};"
        "var traces=[{type:'bar',name:'records',"
        "x:d.buckets.map(function(b){return b[0];}),"
        "y:d.buckets.map(function(b){return b[1];}),"
        "marker:{color:d.colors.bar},"
        "hovertemplate:'%{x}<br>%{y} records<extra></extra>'}];"
        "if(d.bursts.length){traces.push({type:'scatter',mode:'markers',name:'bursts',"
        "x:d.bursts.map(function(b){return b.x;}),"
        "y:d.bursts.map(function(b){return b.y;}),"
        "text:d.bursts.map(function(b){return b.title+' ['+b.severity+']';}),"
        "marker:{size:14,color:d.bursts.map(function(b){return d.colors[b.severity]||d.colors.info;}),"
        "line:{color:d.colors.edge,width:2}},"
        "hovertemplate:'%{text}<br>%{x}<br>%{y} events<extra></extra>'});}"
        "Plotly.newPlot('chart-timeline',traces,layout,{responsive:true,displaylogo:false});"
        "})();"
    )
    return (
        _section_open("section-timeline", "Activity timeline", "// time-bucketed event volume")
        + "<div id='chart-timeline' class='chart'></div>"
        + f"<script>{script}</script>"
        + _section_close()
    )


def _render_heatmap_chart(matrix: List[List[int]]) -> str:
    if not matrix or not any(any(row) for row in matrix):
        return ""
    payload = {
        "matrix": matrix,
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "hours": [f"{h:02d}" for h in range(24)],
        "colors": [
            [0.0, CQURE_COLORS["bg_2"]],
            [0.15, CQURE_COLORS["bg_3"]],
            [0.35, CQURE_COLORS["sev_info"]],
            [0.65, CQURE_COLORS["sev_medium"]],
            [0.85, CQURE_COLORS["accent"]],
            [1.0, CQURE_COLORS["sev_critical"]],
        ],
    }
    layout = _plotly_layout_base()
    layout["margin"]["t"] = 16
    layout["yaxis"].update({"autorange": "reversed", "title": ""})
    layout["xaxis"].update({"title": "hour of day"})

    script = (
        "(function(){"
        "if(typeof Plotly==='undefined')return;"
        f"var d={_safe_json(payload)};"
        f"var layout={_safe_json(layout)};"
        "var trace={type:'heatmap',z:d.matrix,x:d.hours,y:d.days,"
        "colorscale:d.colors,showscale:true,"
        "hovertemplate:'%{y} %{x}:00<br>%{z} events<extra></extra>'};"
        "Plotly.newPlot('chart-heatmap',[trace],layout,{responsive:true,displaylogo:false});"
        "})();"
    )
    return (
        _section_open("section-heatmap", "Hour x day heatmap", "// off-hours activity surface")
        + "<div id='chart-heatmap' class='chart'></div>"
        + f"<script>{script}</script>"
        + _section_close()
    )


def _render_reasons_chart(series: Dict[str, List[Tuple[str, int]]]) -> str:
    if not series or not any(buckets for buckets in series.values()):
        return ""
    payload = []
    for name, buckets in series.items():
        payload.append({
            "name": name,
            "x": [b[0] for b in buckets],
            "y": [b[1] for b in buckets],
            "color": REASON_COLOR.get(name, DEFAULT_REASON_COLOR),
        })
    layout = _plotly_layout_base()
    layout["xaxis"].update({"type": "date"})
    layout["yaxis"].update({"title": "records / bucket"})
    layout["showlegend"] = True
    layout["legend"] = {"orientation": "h", "y": 1.10, "x": 0, "font": {"size": 10}}
    layout["hovermode"] = "x unified"

    # Stacked area: scatter + mode:'lines' + stackgroup:'one'. Plotly handles the
    # additive stacking automatically. Filled area uses translucent reason color.
    script = (
        "(function(){"
        "if(typeof Plotly==='undefined')return;"
        f"var series={_safe_json(payload)};"
        f"var layout={_safe_json(layout)};"
        "function hexAlpha(hex,a){var n=hex.replace('#','');"
        "var r=parseInt(n.substring(0,2),16),g=parseInt(n.substring(2,4),16),b=parseInt(n.substring(4,6),16);"
        "return 'rgba('+r+','+g+','+b+','+a+')';}"
        "var traces=series.map(function(s){return {"
        "type:'scatter',mode:'lines',name:s.name,x:s.x,y:s.y,"
        "stackgroup:'one',"
        "line:{color:s.color,width:1,shape:'spline',smoothing:0.6},"
        "fillcolor:hexAlpha(s.color,0.55),"
        "hovertemplate:'%{x}<br>'+s.name+': %{y}<extra></extra>'};});"
        "Plotly.newPlot('chart-reasons',traces,layout,{responsive:true,displaylogo:false});"
        "})();"
    )
    return (
        _section_open("section-reasons", "Reason flags over time", "// stacked event types · area")
        + "<div id='chart-reasons' class='chart'></div>"
        + f"<script>{script}</script>"
        + _section_close()
    )


def _render_sankey_chart(data: Dict[str, List[Dict[str, object]]]) -> str:
    if not data or not data.get("nodes") or not data.get("links"):
        return ""
    layout = _plotly_layout_base()
    layout["margin"] = {"l": 10, "r": 10, "t": 16, "b": 10}
    layout["showlegend"] = False
    layout["font"]["size"] = 11

    script = (
        "(function(){"
        "if(typeof Plotly==='undefined')return;"
        f"var d={_safe_json(data)};"
        f"var layout={_safe_json(layout)};"
        "var trace={type:'sankey',arrangement:'snap',"
        "node:{label:d.nodes.map(function(n){return n.label;}),"
        "color:d.nodes.map(function(n){return n.color;}),"
        "pad:14,thickness:14,line:{color:'#534F4A',width:0.5},"
        "hovertemplate:'%{label}<br>%{value} events<extra></extra>'},"
        "link:{source:d.links.map(function(l){return l.source;}),"
        "target:d.links.map(function(l){return l.target;}),"
        "value:d.links.map(function(l){return l.value;}),"
        "color:d.links.map(function(l){return l.color;}),"
        "hovertemplate:'%{source.label} → %{target.label}<br>%{value} events<extra></extra>'}};"
        "Plotly.newPlot('chart-sankey',[trace],layout,{responsive:true,displaylogo:false});"
        "})();"
    )
    return (
        _section_open(
            "section-sankey", "Reason flow",
            "// reason → extension → path bucket"
        )
        + "<div id='chart-sankey' class='chart' style='min-height: 540px;'></div>"
        + f"<script>{script}</script>"
        + _section_close()
    )


def _render_extensions_chart(rows: List[Tuple[str, int, str]]) -> str:
    if not rows:
        return ""
    risk_colors = {
        "neutral": CQURE_COLORS["risk_neutral"],
        "high_risk": CQURE_COLORS["risk_high_risk"],
        "ransom": CQURE_COLORS["risk_ransom"],
    }
    payload = {
        "labels": list(reversed([r[0] for r in rows])),
        "counts": list(reversed([r[1] for r in rows])),
        "colors": list(reversed([risk_colors.get(r[2], CQURE_COLORS["risk_neutral"]) for r in rows])),
        "risks": list(reversed([r[2] for r in rows])),
    }
    layout = _plotly_layout_base()
    layout["margin"]["l"] = 110
    layout["yaxis"].update({"automargin": True, "tickfont": {"family": "'JetBrains Mono', monospace"}})
    layout["xaxis"].update({"title": "records"})
    layout["showlegend"] = False

    script = (
        "(function(){"
        "if(typeof Plotly==='undefined')return;"
        f"var d={_safe_json(payload)};"
        f"var layout={_safe_json(layout)};"
        "var trace={type:'bar',orientation:'h',x:d.counts,y:d.labels,"
        "marker:{color:d.colors},text:d.risks,"
        "hovertemplate:'%{y}<br>%{x} records<br>risk: %{text}<extra></extra>'};"
        "Plotly.newPlot('chart-extensions',[trace],layout,{responsive:true,displaylogo:false});"
        "})();"
    )
    legend = (
        "<div class='legend-row'>"
        f"<span class='lg lg-neutral'></span> neutral "
        f"<span class='lg lg-high'></span> high-risk extension "
        f"<span class='lg lg-ransom'></span> ransomware-like"
        "</div>"
    )
    return (
        _section_open("section-extensions", "Top file extensions", "// risk-classed by signature lists")
        + legend
        + "<div id='chart-extensions' class='chart'></div>"
        + f"<script>{script}</script>"
        + _section_close()
    )


def _render_treemap_chart(tree: Tuple[List[str], List[str], List[str], List[int]]) -> str:
    ids, labels, parents, values = tree
    if not ids:
        return ""
    payload = {
        "ids": ids,
        "labels": labels,
        "parents": parents,
        "values": values,
        "color_bar": CQURE_COLORS["accent"],
        "color_text": CQURE_COLORS["text"],
        "color_line": CQURE_COLORS["bg"],
    }
    layout = _plotly_layout_base()
    layout["margin"] = {"l": 0, "r": 0, "t": 36, "b": 0}

    script = (
        "(function(){"
        "if(typeof Plotly==='undefined')return;"
        f"var d={_safe_json(payload)};"
        f"var layout={_safe_json(layout)};"
        "var trace={type:'treemap',ids:d.ids,labels:d.labels,parents:d.parents,values:d.values,"
        # `remainder` is safe even when child counts don't sum to parent (we truncate at top_n).
        "branchvalues:'remainder',"
        # Start with 2 visible levels; clicking a tile drills in. Pathbar gives breadcrumbs back up.
        "maxdepth:2,"
        "pathbar:{visible:true,side:'top',thickness:22,textfont:{size:11,color:d.color_text,family:\"'JetBrains Mono', monospace\"}},"
        "tiling:{packing:'squarify'},"
        "textinfo:'label+value',"
        "marker:{colors:d.ids.map(function(){return d.color_bar;}),line:{color:d.color_line,width:2}},"
        "textfont:{family:\"'JetBrains Mono', monospace\",color:d.color_text,size:12},"
        "hovertemplate:'%{label}<br>%{value} records<extra></extra>'};"
        "Plotly.newPlot('chart-treemap',[trace],layout,{responsive:true,displaylogo:false});"
        "})();"
    )
    return (
        _section_open(
            "section-paths", "Path treemap",
            "// directory hotspots · click tile to drill in · pathbar to go back"
        )
        + "<div id='chart-treemap' class='chart' style='min-height: 560px;'></div>"
        + f"<script>{script}</script>"
        + _section_close()
    )


def _render_records_table(records: List[USNRecord], max_rows: int) -> str:
    shown = records[:max_rows]
    capped = len(records) > max_rows

    # Columnar payload (much smaller JSON than list-of-dicts).
    ts_list = [r.timestamp_utc for r in shown]
    reason_list = [r.reason for r in shown]
    path_list = [(r.reconstructed_path or r.filename) for r in shown]
    frn_list = [r.file_reference_number for r in shown]
    parent_list = [r.parent_file_reference_number for r in shown]

    # Extension popularity for the dropdown.
    ext_counter: Counter = Counter()
    for r in shown:
        _, ext = os.path.splitext(r.filename.lower())
        if ext:
            ext_counter[ext] += 1
    top_exts = [ext for ext, _ in ext_counter.most_common(60)]

    # Reasons present in this dataset (bit, name) sorted by bit.
    bits_present = 0
    for v in reason_list:
        bits_present |= v
    reasons_avail = [
        {"bit": bit, "name": name, "color": REASON_COLOR.get(name, DEFAULT_REASON_COLOR)}
        for bit, name in sorted(REASON_FLAGS.items())
        if bits_present & bit
    ]

    payload = {
        "ts": ts_list,
        "reason": reason_list,
        "path": path_list,
        "frn": frn_list,
        "parent": parent_list,
        "reasonsAvail": reasons_avail,
        "extsAvail": top_exts,
        "reasonMap": [{"bit": bit, "name": name, "color": REASON_COLOR.get(name, DEFAULT_REASON_COLOR)}
                      for bit, name in sorted(REASON_FLAGS.items())],
        "total": len(records),
        "shown": len(shown),
        "rowHeight": 28,
        "viewportHeight": 720,
    }

    crumb = (
        f"// first {_fmt_int(max_rows)} of {_fmt_int(len(records))} rows · multi-filter · sortable · virtual scroll"
        if capped else
        f"// all {_fmt_int(len(records))} rows · multi-filter · sortable · virtual scroll"
    )

    # Build reason chip options markup (rendered server-side, JS reads `data-bit`).
    reason_chips = "".join(
        f"<label class='vchip' data-bit='{r['bit']}' style='--chip:{html.escape(r['color'])}'>"
        f"<input type='checkbox' data-reason-bit='{r['bit']}'><span>{html.escape(r['name'])}</span>"
        f"</label>"
        for r in reasons_avail
    )
    ext_chips = "".join(
        f"<label class='vchip'><input type='checkbox' data-ext='{html.escape(e)}'><span>{html.escape(e)}</span></label>"
        for e in top_exts
    )

    toolbar = (
        "<div class='vt-toolbar'>"
        "<div class='vt-row'>"
        "<input id='vt-text' class='vt-input' placeholder=\"filter (/ to focus)...\" />"
        "<div class='vt-spacer'></div>"
        "<button class='vt-btn' id='vt-clear' title='Clear all filters (Esc)'>CLEAR</button>"
        "<button class='vt-btn primary' id='vt-export' title='Export filtered rows as CSV'>EXPORT CSV</button>"
        f"<div class='vt-count'><b id='vt-shown'>{len(shown)}</b> / {_fmt_int(len(shown))}"
        + (f" <span class='vt-mute'>(of {_fmt_int(len(records))})</span>" if capped else "")
        + "</div>"
        "</div>"
        "<div class='vt-row'>"
        "<details class='vt-drop'><summary>REASON <span class='vt-tag' id='vt-reason-tag'>any</span></summary>"
        f"<div class='vt-drop-body'>{reason_chips}</div></details>"
        "<details class='vt-drop'><summary>EXTENSION <span class='vt-tag' id='vt-ext-tag'>any</span></summary>"
        f"<div class='vt-drop-body'>{ext_chips}</div></details>"
        "<div class='vt-daterange'>"
        "<span class='vt-label'>FROM</span><input id='vt-from' class='vt-input vt-date' type='text' placeholder='YYYY-MM-DD HH:MM' />"
        "<span class='vt-label'>TO</span><input id='vt-to' class='vt-input vt-date' type='text' placeholder='YYYY-MM-DD HH:MM' />"
        "</div>"
        "</div>"
        "</div>"
    )

    header = (
        "<div class='vt-head'>"
        "<div class='vt-cell vt-col-ts' data-sort='ts'>TIMESTAMP UTC <span class='vt-sort'>⇅</span></div>"
        "<div class='vt-cell vt-col-reason' data-sort='reason'>REASON <span class='vt-sort'>⇅</span></div>"
        "<div class='vt-cell vt-col-path' data-sort='path'>PATH <span class='vt-sort'>⇅</span></div>"
        "<div class='vt-cell vt-col-frn' data-sort='frn'>FRN <span class='vt-sort'>⇅</span></div>"
        "<div class='vt-cell vt-col-actions'>QUICK</div>"
        "</div>"
    )

    body = (
        "<div class='vt-scroll' id='vt-scroll'>"
        "<div class='vt-sizer' id='vt-sizer'></div>"
        "<div class='vt-viewport' id='vt-viewport'></div>"
        "</div>"
    )

    note_html = (
        "<div class='vt-note'>Table is server-capped via "
        "<code>--max-html-rows</code>; the full event set is in CSV/JSON.</div>"
    ) if capped else ""

    payload_script = f"<script id='vt-data' type='application/json'>{_safe_json(payload)}</script>"

    # FRN drill-down modal (initially hidden, populated by JS on row click).
    modal_html = (
        "<div id='frn-modal' class='frn-modal' hidden>"
        "<div class='frn-modal-backdrop' id='frn-modal-backdrop'></div>"
        "<div class='frn-modal-card' role='dialog' aria-modal='true' aria-labelledby='frn-modal-title'>"
        "<div class='frn-modal-head'>"
        "<span class='frn-modal-title' id='frn-modal-title'>(no selection)</span>"
        "<button class='frn-modal-close' id='frn-modal-close' title='Close (Esc)'>× close</button>"
        "</div>"
        "<div class='frn-modal-body' id='frn-modal-body'></div>"
        "</div>"
        "</div>"
    )

    return (
        _section_open("section-records", "Records", crumb)
        + toolbar
        + "<div class='vt-wrap'>"
        + header
        + body
        + "</div>"
        + note_html
        + payload_script
        + modal_html
        + _section_close()
    )


def _render_inline_table_js() -> str:
    return r"""
(function(){
  var dataEl=document.getElementById('vt-data');
  if(!dataEl) return;
  var D=JSON.parse(dataEl.textContent);
  var N=D.shown;
  var rowH=D.rowHeight;
  var scrollEl=document.getElementById('vt-scroll');
  var viewportEl=document.getElementById('vt-viewport');
  var sizerEl=document.getElementById('vt-sizer');
  if(!scrollEl||!viewportEl||!sizerEl) return;

  // Precompute extension per row + numeric timestamp.
  var exts=new Array(N), tsNum=new Float64Array(N);
  for(var i=0;i<N;i++){
    var p=D.path[i]||'';
    var s=Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'));
    var nm=(s>=0)?p.substring(s+1):p;
    var dot=nm.lastIndexOf('.');
    exts[i]=(dot>0)?nm.substring(dot).toLowerCase():'';
    var t=Date.parse(D.ts[i]||'');
    tsNum[i]=isNaN(t)?0:t;
  }

  var state={text:'', reasonMask:0, extSet:new Set(), fromMs:-Infinity, toMs:Infinity, sort:'ts', dir:1};
  var indices=[];

  function htmlEsc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function attrEsc(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');}
  function hi(s,needle){
    if(!needle) return htmlEsc(s);
    var ls=s.toLowerCase(); var idx=ls.indexOf(needle);
    if(idx<0) return htmlEsc(s);
    return htmlEsc(s.substring(0,idx))+'<mark>'+htmlEsc(s.substring(idx,idx+needle.length))+'</mark>'+htmlEsc(s.substring(idx+needle.length));
  }
  function reasonsHtml(bits){
    var out='';
    for(var k=0;k<D.reasonMap.length;k++){
      var rm=D.reasonMap[k];
      if(bits & rm.bit){
        out+='<span class="vt-rbadge" style="--rb:'+attrEsc(rm.color)+'">'+htmlEsc(rm.name)+'</span>';
      }
    }
    return out;
  }

  function rebuildIndices(){
    var needle=state.text, rm=state.reasonMask, es=state.extSet, hasE=es.size>0;
    var fm=state.fromMs, tm=state.toMs;
    var arr=[];
    for(var i=0;i<N;i++){
      if(rm && (D.reason[i] & rm)===0) continue;
      if(hasE && !es.has(exts[i])) continue;
      var t=tsNum[i]; if(t<fm||t>tm) continue;
      if(needle){
        var hay=(D.path[i]+' '+D.frn[i]+' '+D.parent[i]+' '+D.ts[i]).toLowerCase();
        if(hay.indexOf(needle)<0) continue;
      }
      arr.push(i);
    }
    var key=state.sort, dir=state.dir;
    if(key==='ts') arr.sort(function(a,b){return (tsNum[a]-tsNum[b])*dir;});
    else if(key==='reason') arr.sort(function(a,b){return (D.reason[a]-D.reason[b])*dir;});
    else if(key==='path') arr.sort(function(a,b){var x=D.path[a],y=D.path[b]; return x<y?-dir:x>y?dir:0;});
    else if(key==='frn') arr.sort(function(a,b){var x=D.frn[a],y=D.frn[b]; return x<y?-dir:x>y?dir:0;});
    indices=arr;
    document.getElementById('vt-shown').textContent=arr.length.toLocaleString('en').replace(/,/g,' ');
    sizerEl.style.height=(arr.length*rowH)+'px';
    render();
  }

  function render(){
    var top=scrollEl.scrollTop;
    var h=scrollEl.clientHeight||D.viewportHeight;
    var startIdx=Math.max(0, Math.floor(top/rowH)-5);
    var endIdx=Math.min(indices.length, Math.ceil((top+h)/rowH)+5);
    var html='', needle=state.text;
    for(var k=startIdx;k<endIdx;k++){
      var i=indices[k];
      var ypx=k*rowH;
      html+='<div class="vt-row-r" style="top:'+ypx+'px" data-frn="'+attrEsc(D.frn[i])+'">';
      html+='<div class="vt-cell vt-col-ts">'+htmlEsc(D.ts[i])+'</div>';
      html+='<div class="vt-cell vt-col-reason">'+reasonsHtml(D.reason[i])+'</div>';
      html+='<div class="vt-cell vt-col-path">'+hi(D.path[i]||'',needle)+'</div>';
      html+='<div class="vt-cell vt-col-frn">'+htmlEsc(D.frn[i])+'</div>';
      html+='<div class="vt-cell vt-col-actions">';
      html+='<button class="vt-qa" data-act="frn" data-val="'+attrEsc(D.frn[i])+'" title="Filter to this FRN">F</button>';
      html+='<button class="vt-qa" data-act="parent" data-val="'+attrEsc(D.parent[i])+'" title="Filter to this parent FRN">P</button>';
      if(exts[i]) html+='<button class="vt-qa" data-act="ext" data-val="'+attrEsc(exts[i])+'" title="Toggle extension '+attrEsc(exts[i])+'">'+htmlEsc(exts[i])+'</button>';
      html+='</div></div>';
    }
    viewportEl.innerHTML=html;
  }

  var scrollPending=false;
  scrollEl.addEventListener('scroll', function(){
    if(scrollPending) return;
    scrollPending=true;
    requestAnimationFrame(function(){ scrollPending=false; render(); });
  });

  var textInput=document.getElementById('vt-text'), textTimer=null;
  textInput.addEventListener('input', function(){
    clearTimeout(textTimer);
    textTimer=setTimeout(function(){ state.text=textInput.value.toLowerCase(); rebuildIndices(); }, 120);
  });

  function updReasonTag(){
    var n=0; document.querySelectorAll('input[data-reason-bit]:checked').forEach(function(){n++;});
    document.getElementById('vt-reason-tag').textContent=n?(n+' selected'):'any';
  }
  document.querySelectorAll('input[data-reason-bit]').forEach(function(cb){
    cb.addEventListener('change', function(){
      var bit=parseInt(cb.getAttribute('data-reason-bit'),10)|0;
      if(cb.checked) state.reasonMask=(state.reasonMask|bit)>>>0;
      else state.reasonMask=(state.reasonMask & ~bit)>>>0;
      updReasonTag(); rebuildIndices();
    });
  });

  function updExtTag(){
    document.getElementById('vt-ext-tag').textContent=state.extSet.size?(state.extSet.size+' selected'):'any';
  }
  document.querySelectorAll('input[data-ext]').forEach(function(cb){
    cb.addEventListener('change', function(){
      var v=cb.getAttribute('data-ext');
      if(cb.checked) state.extSet.add(v); else state.extSet.delete(v);
      updExtTag(); rebuildIndices();
    });
  });

  function parseDt(s){
    if(!s) return null;
    s=s.trim(); if(!s) return null;
    var iso=s.replace(' ','T');
    if(iso.length<=10) iso+='T00:00';
    var v=Date.parse(iso+'Z');
    if(isNaN(v)) v=Date.parse(s);
    return isNaN(v)?null:v;
  }
  document.getElementById('vt-from').addEventListener('change', function(e){
    var v=parseDt(e.target.value); state.fromMs=(v==null)?-Infinity:v; rebuildIndices();
  });
  document.getElementById('vt-to').addEventListener('change', function(e){
    var v=parseDt(e.target.value); state.toMs=(v==null)?Infinity:v; rebuildIndices();
  });

  document.querySelectorAll('[data-sort]').forEach(function(el){
    el.addEventListener('click', function(){
      var key=el.getAttribute('data-sort');
      if(state.sort===key) state.dir=-state.dir; else { state.sort=key; state.dir=1; }
      document.querySelectorAll('.vt-sort').forEach(function(s){ s.textContent='⇅'; });
      var mk=el.querySelector('.vt-sort'); if(mk) mk.textContent=(state.dir>0?'↑':'↓');
      rebuildIndices();
    });
  });

  viewportEl.addEventListener('click', function(e){
    var t=e.target;
    if(t.classList && t.classList.contains('vt-qa')){
      var act=t.getAttribute('data-act'), val=t.getAttribute('data-val');
      if(act==='frn'||act==='parent'){
        textInput.value=val; state.text=(val||'').toLowerCase();
      } else if(act==='ext'){
        var cb=document.querySelector('input[data-ext="'+val.replace(/"/g,'\\"')+'"]');
        if(cb){ cb.checked=!cb.checked; if(cb.checked) state.extSet.add(val); else state.extSet.delete(val); updExtTag(); }
        else { textInput.value=val; state.text=(val||'').toLowerCase(); }
      }
      rebuildIndices();
      return;
    }
    // Otherwise, treat any click inside a row as "drill into this FRN".
    var row=t.closest && t.closest('.vt-row-r');
    if(row){
      var frn=row.getAttribute('data-frn');
      if(frn) openFrnModal(frn);
    }
  });

  function openFrnModal(frn){
    // Collect ALL records for this FRN (not just current filter).
    var idx=[];
    for(var i=0;i<N;i++){ if(D.frn[i]===frn) idx.push(i); }
    if(!idx.length) return;
    idx.sort(function(a,b){ return tsNum[a]-tsNum[b]; });
    var first=tsNum[idx[0]], last=tsNum[idx[idx.length-1]];
    var span=Math.max(1, last-first);
    var firstPath=D.path[idx[0]]||'(no path)';

    // Title
    document.getElementById('frn-modal-title').innerHTML=
      "<span class='frn-modal-frn'>FRN "+htmlEsc(frn)+"</span>"+
      " · <span class='frn-modal-path'>"+htmlEsc(firstPath)+"</span>"+
      " · <span class='frn-modal-count'>"+idx.length+" event(s)</span>";

    // Mini SVG timeline (markers per event, colored by dominant reason).
    var W=1080, H=64, padX=8;
    function colorOf(bits){
      for(var k=0;k<D.reasonMap.length;k++){
        var rm=D.reasonMap[k];
        if(bits & rm.bit) return rm.color;
      }
      return '#837C72';
    }
    var sv="<svg class='frn-tl' viewBox='0 0 "+W+" "+H+"' preserveAspectRatio='none' width='100%' height='"+H+"'>";
    sv+="<line x1='0' y1='"+(H/2)+"' x2='"+W+"' y2='"+(H/2)+"' stroke='#423E3A' stroke-width='1'/>";
    for(var j=0;j<idx.length;j++){
      var k=idx[j], x;
      if(idx.length>1){ x=padX + ((tsNum[k]-first)/span)*(W-2*padX); }
      else { x=W/2; }
      var col=colorOf(D.reason[k]);
      var names=[];
      for(var m=0;m<D.reasonMap.length;m++){ if(D.reason[k] & D.reasonMap[m].bit) names.push(D.reasonMap[m].name); }
      var tip=D.ts[k]+'  '+names.join('|');
      sv+="<line x1='"+x.toFixed(1)+"' y1='8' x2='"+x.toFixed(1)+"' y2='"+(H-8)+"' stroke='"+col+"' stroke-width='2'><title>"+htmlEsc(tip)+"</title></line>";
    }
    sv+="<text x='"+padX+"' y='"+(H-1)+"' font-family='monospace' font-size='9' fill='#837C72'>"+htmlEsc(D.ts[idx[0]])+"</text>";
    sv+="<text x='"+(W-padX)+"' y='"+(H-1)+"' text-anchor='end' font-family='monospace' font-size='9' fill='#837C72'>"+htmlEsc(D.ts[idx[idx.length-1]])+"</text>";
    sv+="</svg>";

    // Event list (truncate at 500 for sanity).
    var max=500;
    var list="<div class='frn-events-wrap'><table class='frn-events'><thead><tr>"+
      "<th>TIMESTAMP UTC</th><th>REASONS</th><th>PATH</th></tr></thead><tbody>";
    for(var p=0;p<Math.min(idx.length, max);p++){
      var k2=idx[p];
      list+="<tr><td class='ts'>"+htmlEsc(D.ts[k2])+"</td>"+
        "<td>"+reasonsHtml(D.reason[k2])+"</td>"+
        "<td class='path'>"+htmlEsc(D.path[k2]||'')+"</td></tr>";
    }
    list+="</tbody></table></div>";
    if(idx.length>max){
      list+="<div class='frn-events-trim'>... truncated at "+max+" of "+idx.length+" events</div>";
    }

    document.getElementById('frn-modal-body').innerHTML=sv+list;
    document.getElementById('frn-modal').hidden=false;
  }

  function closeFrnModal(){
    var el=document.getElementById('frn-modal');
    if(el) el.hidden=true;
  }
  var mClose=document.getElementById('frn-modal-close');
  var mBack=document.getElementById('frn-modal-backdrop');
  if(mClose) mClose.addEventListener('click', closeFrnModal);
  if(mBack) mBack.addEventListener('click', closeFrnModal);

  document.getElementById('vt-clear').addEventListener('click', function(){
    textInput.value=''; state.text='';
    state.reasonMask=0; state.extSet.clear();
    state.fromMs=-Infinity; state.toMs=Infinity;
    document.querySelectorAll('input[data-reason-bit], input[data-ext]').forEach(function(cb){ cb.checked=false; });
    document.getElementById('vt-from').value=''; document.getElementById('vt-to').value='';
    updReasonTag(); updExtTag();
    rebuildIndices();
  });

  document.getElementById('vt-export').addEventListener('click', function(){
    function q(v){ v=String(v==null?'':v); if(v.indexOf(',')>=0||v.indexOf('"')>=0||v.indexOf('\n')>=0||v.indexOf('\r')>=0) return '"'+v.replace(/"/g,'""')+'"'; return v; }
    var lines=['timestamp_utc,reason_names,path,frn,parent_frn'];
    for(var k=0;k<indices.length;k++){
      var i=indices[k]; var names=[];
      for(var m=0;m<D.reasonMap.length;m++){ if(D.reason[i] & D.reasonMap[m].bit) names.push(D.reasonMap[m].name); }
      lines.push(q(D.ts[i])+','+q(names.join(';'))+','+q(D.path[i])+','+q(D.frn[i])+','+q(D.parent[i]));
    }
    var csv='﻿'+lines.join('\r\n');
    var blob=new Blob([csv],{type:'text/csv;charset=utf-8'});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='records_filtered.csv';
    document.body.appendChild(a); a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  });

  document.addEventListener('keydown', function(e){
    var tag=(e.target && e.target.tagName)||'';
    // Esc inside FRN modal closes it first, regardless of focused element.
    var modal=document.getElementById('frn-modal');
    if(e.key==='Escape' && modal && !modal.hidden){ closeFrnModal(); e.preventDefault(); return; }
    if(tag==='INPUT'||tag==='TEXTAREA'){
      if(e.key==='Escape') e.target.blur();
      return;
    }
    if(e.key==='/'){ e.preventDefault(); textInput.focus(); textInput.select(); }
    else if(e.key==='Escape'){ document.getElementById('vt-clear').click(); }
  });

  rebuildIndices();
})();
"""


def _render_active_filter_banner() -> str:
    """Sticky banner shown when a chart drives the table filter (brush/click)."""
    return (
        "<div id='active-filter-banner' class='filter-banner' hidden>"
        "<span class='banner-label'>FILTER</span>"
        "<span id='banner-content'>(none)</span>"
        "<button id='banner-clear' class='banner-clear' title='Clear cross-filter'>× clear</button>"
        "</div>"
    )


def _render_crossfilter_js() -> str:
    """Wire Plotly events (timeline brush, heatmap click) to the records-table filters."""
    return r"""
(function(){
  var banner=document.getElementById('active-filter-banner');
  var content=document.getElementById('banner-content');
  var clearBtn=document.getElementById('banner-clear');
  function show(label, text){
    if(!banner||!content) return;
    content.textContent=label+': '+text;
    banner.hidden=false;
  }
  function hide(){ if(banner) banner.hidden=true; }

  function trim(s){ return String(s).slice(0,19).replace('T',' '); }

  function setRange(fromStr, toStr){
    var f=document.getElementById('vt-from');
    var t=document.getElementById('vt-to');
    if(!f||!t) return;
    f.value=String(fromStr).slice(0,19).replace('T',' ');
    t.value=String(toStr).slice(0,19).replace('T',' ');
    f.dispatchEvent(new Event('change'));
    t.dispatchEvent(new Event('change'));
  }
  function setText(val){
    var i=document.getElementById('vt-text');
    if(!i) return;
    i.value=val;
    i.dispatchEvent(new Event('input'));
  }
  function scrollToTable(){
    var sec=document.getElementById('section-records');
    if(sec) sec.scrollIntoView({behavior:'smooth', block:'start'});
  }

  if(clearBtn) clearBtn.addEventListener('click', function(){
    var c=document.getElementById('vt-clear');
    if(c) c.click();
    hide();
  });

  var tries=0;
  var iv=setInterval(function(){
    tries++;
    var tl=document.getElementById('chart-timeline');
    var hm=document.getElementById('chart-heatmap');
    var wired=false;
    if(tl && tl.on){
      tl.on('plotly_relayout', function(e){
        if(!e) return;
        // Plotly emits either 'xaxis.range[0]'/'xaxis.range[1]' on brush+drag
        // or 'xaxis.autorange' on reset.
        if(e['xaxis.autorange']){ hide(); return; }
        var f=e['xaxis.range[0]'];
        var t=e['xaxis.range[1]'];
        if(!f && e['xaxis.range']){ f=e['xaxis.range'][0]; t=e['xaxis.range'][1]; }
        if(f && t){
          setRange(f, t);
          show('Time window', trim(f)+' → '+trim(t));
          scrollToTable();
        }
      });
      wired=true;
    }
    if(hm && hm.on){
      hm.on('plotly_click', function(d){
        if(!d || !d.points || !d.points.length) return;
        var p=d.points[0];
        var hour=String(p.x);
        var day=String(p.y);
        setText('T'+hour+':');
        show('Hour filter', day+' '+hour+':00 (all weeks · text="T'+hour+':")');
        scrollToTable();
      });
      wired=true;
    }
    if(wired || tries>300) clearInterval(iv);
  }, 50);
})();
"""


def _render_warning(message: str) -> str:
    return (
        "<section class='section' style='padding-top:24px;padding-bottom:0'>"
        f"<div class='warn'><b>NOTE</b> {html.escape(message)}</div>"
        "</section>"
    )


def _render_footer(meta: Dict[str, object]) -> str:
    generated = html.escape(str(meta.get("generated_iso", "")))
    return (
        "<footer class='foot'>"
        "<span><b>CQUSNDeepAnalyzer</b> · Apache License 2.0 · CQURE / Paula Januszkiewicz</span>"
        f"<span>Generated: {generated}</span>"
        "</footer>"
    )


def _render_styles() -> str:
    return """
:root {
  --bg: oklch(0.17 0.008 40);
  --bg-2: oklch(0.21 0.010 40);
  --bg-3: oklch(0.25 0.012 40);
  --line: oklch(0.30 0.010 40);
  --line-2: oklch(0.38 0.012 40);
  --text: oklch(0.96 0.005 80);
  --text-dim: oklch(0.72 0.008 60);
  --text-mute: oklch(0.55 0.010 60);
  --accent: oklch(0.72 0.19 45);
  --accent-2: oklch(0.62 0.22 30);
  --accent-ink: oklch(0.16 0.02 40);
  --sev-critical: oklch(0.55 0.20 25);
  --sev-high: oklch(0.72 0.19 45);
  --sev-medium: oklch(0.78 0.17 75);
  --sev-info: oklch(0.68 0.14 230);
  --sev-low: oklch(0.55 0.010 60);
  --font-display: 'Inter', 'Segoe UI', system-ui, sans-serif;
  --font-body: 'Inter', 'Segoe UI', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', 'Cascadia Mono', 'Consolas', ui-monospace, monospace;
}
:root[data-theme="light"] {
  --bg:        oklch(0.97 0.006 80);
  --bg-2:      oklch(0.995 0.003 80);
  --bg-3:      oklch(0.93 0.007 75);
  --line:      oklch(0.88 0.008 70);
  --line-2:    oklch(0.80 0.012 70);
  --text:      oklch(0.24 0.012 50);
  --text-dim:  oklch(0.44 0.012 50);
  --text-mute: oklch(0.58 0.012 60);
}
html { transition: background .25s ease; }
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); }
body {
  font-family: var(--font-body);
  font-size: 14px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
a { color: inherit; text-decoration: none; }

.util {
  border-bottom: 1px solid var(--line);
  background: var(--bg);
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.08em;
  color: var(--text-mute);
}
.util-inner {
  max-width: 1440px; margin: 0 auto;
  padding: 8px 40px;
  display: flex; justify-content: space-between; align-items: center;
  gap: 24px;
}
.util-left { display: flex; gap: 28px; flex-wrap: wrap; }
.util-left span::before { content: '// '; color: var(--accent); }
.util-right { display: flex; gap: 14px; align-items: center; }
.util-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in oklch, var(--accent) 20%, transparent);
}

header.nav {
  background: var(--bg);
  border-bottom: 1px solid var(--line);
}
.nav-inner {
  max-width: 1440px; margin: 0 auto;
  padding: 0 40px;
  height: 76px;
  display: flex; justify-content: space-between; align-items: center;
}
.logo { display: flex; align-items: center; gap: 13px; }
.logo-text { font-family: var(--font-display); font-weight: 600; font-size: 19px; letter-spacing: 0.01em; line-height: 1.05; }
.logo-text .brandline { display: inline-flex; align-items: center; }
.logo-text .q { color: var(--accent); }
.logo-text .cur {
  display: inline-block;
  width: 0.42em; height: 0.92em;
  background: var(--accent);
  margin-left: 0.12em;
  transform: translateY(0.04em);
  animation: blink 1.1s steps(1) infinite;
}
.logo-text small { display: block; font-family: var(--font-mono); font-size: 10px; color: var(--text-mute); font-weight: 400; letter-spacing: 0.14em; text-transform: uppercase; margin-top: 2px; }
@keyframes blink { 50% { opacity: 0; } }
.nav-right { display: flex; align-items: center; gap: 18px; }
.nav-meta {
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-mute); letter-spacing: 0.08em;
  display: flex; gap: 18px;
}
.nav-meta span::before { content: '// '; color: var(--accent); }
.theme-toggle {
  width: 38px; height: 38px;
  display: grid; place-items: center;
  background: none; cursor: pointer;
  border: 1px solid var(--line-2); border-radius: 4px;
  color: var(--text-dim);
  transition: background .15s, color .15s, border-color .15s;
}
.theme-toggle:hover { background: var(--bg-2); color: var(--text); border-color: var(--text-dim); }
.theme-toggle .ic { width: 17px; height: 17px; }
.theme-toggle .ic-sun { display: block; }
.theme-toggle .ic-moon { display: none; }
:root[data-theme="light"] .theme-toggle .ic-sun { display: none; }
:root[data-theme="light"] .theme-toggle .ic-moon { display: block; }

.hero {
  position: relative;
  max-width: 1440px; margin: 0 auto;
  padding: 56px 40px 56px;
  overflow: hidden;
}
.grid-bg {
  position: absolute; inset: 0;
  background-image:
    linear-gradient(to right, var(--line) 1px, transparent 1px),
    linear-gradient(to bottom, var(--line) 1px, transparent 1px);
  background-size: 80px 80px;
  opacity: 0.30;
  pointer-events: none;
  mask-image: radial-gradient(ellipse 80% 60% at 25% 40%, black 40%, transparent 85%);
  -webkit-mask-image: radial-gradient(ellipse 80% 60% at 25% 40%, black 40%, transparent 85%);
}
.hero-inner { position: relative; }
.tag-row {
  display: flex; align-items: center; gap: 14px;
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-mute); letter-spacing: 0.12em; text-transform: uppercase;
  margin-bottom: 28px; flex-wrap: wrap;
}
.tag-row .pill {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 5px 10px 5px 8px;
  border: 1px solid var(--line-2);
  border-radius: 2px;
  color: var(--text);
  background: var(--bg-2);
}
.tag-row .pill::before {
  content: ''; width: 5px; height: 5px; border-radius: 50%;
  background: var(--accent);
}
.tag-row .meta { display: flex; gap: 14px; flex-wrap: wrap; }
.tag-row .meta span::before { content: '['; margin-right: 4px; color: var(--accent); }
.tag-row .meta span::after { content: ']'; margin-left: 4px; color: var(--accent); }

h1.headline {
  font-family: var(--font-display);
  font-weight: 700;
  font-size: 72px;
  line-height: 0.95;
  letter-spacing: -0.035em;
  margin: 0 0 18px;
  text-wrap: balance;
}
h1.headline .accent {
  color: var(--accent);
  font-style: italic;
  font-weight: 500;
}
.sub {
  max-width: 720px;
  font-size: 16px;
  line-height: 1.55;
  color: var(--text-dim);
  margin: 0 0 32px;
}
.sub strong { color: var(--text); font-weight: 600; }

.facts {
  display: flex; flex-wrap: wrap;
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}
.fact {
  flex: 1 1 180px;
  padding: 18px 0 18px 0;
  display: flex; flex-direction: column; gap: 4px;
}
.fact + .fact { border-left: 1px solid var(--line); padding-left: 24px; }
.fact-label {
  font-family: var(--font-mono); font-size: 10px;
  color: var(--text-mute); letter-spacing: 0.16em; text-transform: uppercase;
}
.fact-value {
  font-family: var(--font-display); font-size: 28px; font-weight: 500;
  letter-spacing: -0.02em;
  display: flex; align-items: baseline; gap: 6px;
}
.fact-value small {
  font-family: var(--font-mono); font-size: 12px; color: var(--text-mute); font-weight: 400;
}
.fact-value.crit { color: var(--sev-critical); }
.fact-value.high { color: var(--accent); }

.section {
  max-width: 1440px; margin: 0 auto;
  padding: 48px 40px;
  border-top: 1px solid var(--line);
  scroll-margin-top: 16px;
}
/* ---------- section rail (jump-to nav) ---------- */
.section-rail {
  position: fixed; right: 18px; top: 50%; transform: translateY(-50%);
  z-index: 60;
  display: flex; flex-direction: column; gap: 2px;
  padding: 8px 6px; border-radius: 8px;
  border: 1px solid transparent;
  transition: background .15s, border-color .15s;
}
.section-rail:hover {
  background: color-mix(in oklch, var(--bg-2) 92%, transparent);
  border-color: var(--line);
  backdrop-filter: blur(6px);
  -webkit-backdrop-filter: blur(6px);
}
.rail-item {
  display: flex; align-items: center; justify-content: flex-end; gap: 10px;
  padding: 5px 4px; border-radius: 4px;
  background: none; border: 0; cursor: pointer; font: inherit;
  color: var(--text-mute);
  transition: color .15s;
}
.rail-item:hover { color: var(--text); }
.rail-item .rail-text {
  font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.06em;
  white-space: nowrap;
  max-width: 0; opacity: 0; overflow: hidden;
  transition: max-width .2s ease, opacity .2s ease;
}
.section-rail:hover .rail-text { max-width: 220px; opacity: 1; }
.rail-item .rail-dot {
  width: 8px; height: 8px; border-radius: 50%; flex: none;
  background: var(--line-2);
  transition: background .15s, box-shadow .15s;
}
.rail-item:hover .rail-dot { background: var(--text-dim); }
.rail-item.active { color: var(--accent); }
.rail-item.active .rail-text { color: var(--accent); }
.rail-item.active .rail-dot {
  background: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in oklch, var(--accent) 22%, transparent);
}
.section-head {
  display: flex; justify-content: space-between; align-items: baseline;
  margin-bottom: 24px; gap: 16px; flex-wrap: wrap;
}
.section-head h2 {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 28px;
  letter-spacing: -0.02em;
  margin: 0;
}
.section-head .crumbs {
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-mute); letter-spacing: 0.12em; text-transform: uppercase;
}

.findings-grid { display: grid; grid-template-columns: 1fr; gap: 12px; }
.finding {
  background: var(--bg-2);
  border: 1px solid var(--line);
  border-left: 4px solid var(--sev-low);
  border-radius: 4px;
  padding: 18px 22px;
}
.finding.critical { border-left-color: var(--sev-critical); }
.finding.high { border-left-color: var(--sev-high); }
.finding.medium { border-left-color: var(--sev-medium); }
.finding.info { border-left-color: var(--sev-info); }
.finding-head {
  display: flex; justify-content: space-between; align-items: baseline;
  gap: 16px; margin-bottom: 6px; flex-wrap: wrap;
}
.finding-title {
  font-family: var(--font-display); font-weight: 600; font-size: 16px;
  display: flex; align-items: center; gap: 10px;
}
.sev-badge {
  font-family: var(--font-mono); font-size: 10px;
  letter-spacing: 0.16em; text-transform: uppercase;
  padding: 3px 8px; border-radius: 2px;
  border: 1px solid currentColor;
}
.sev-badge.critical { color: var(--sev-critical); }
.sev-badge.high { color: var(--sev-high); }
.sev-badge.medium { color: var(--sev-medium); }
.sev-badge.info { color: var(--sev-info); }
.sev-badge.low { color: var(--sev-low); }
.finding-meta {
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-mute); letter-spacing: 0.06em;
}
.finding-desc { color: var(--text-dim); font-size: 14px; margin: 4px 0 10px; }
.finding-samples {
  font-family: var(--font-mono); font-size: 12px;
  color: var(--text-dim);
  background: var(--bg-3);
  padding: 10px 14px; border-radius: 3px;
  border: 1px solid var(--line);
}
.finding-samples ul { list-style: none; margin: 0; padding: 0; }
.finding-samples li { padding: 2px 0; word-break: break-all; }
.finding-samples li::before { content: '$ '; color: var(--accent); }

.finding-context {
  margin-top: 10px;
  background: var(--bg-3);
  border: 1px solid var(--line);
  border-left: 3px solid var(--sev-info);
  border-radius: 3px;
  padding: 6px 14px;
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-dim);
}
.finding-context summary {
  cursor: pointer; user-select: none;
  color: var(--sev-info); letter-spacing: 0.08em;
  padding: 4px 0;
}
.finding-context summary::-webkit-details-marker { display: none; }
.finding-context summary::before { content: '▸ '; }
.finding-context[open] summary::before { content: '▾ '; }
.finding-context ul { list-style: none; margin: 6px 0 4px; padding: 0; }
.finding-context li { padding: 2px 0; word-break: break-all; }
.finding-context li::before { content: '» '; color: var(--sev-info); }

.finding-spark {
  display: flex; flex-direction: column; align-items: flex-end;
  gap: 2px;
  margin-left: auto;
}
.finding-spark .sparkline { display: block; }
.finding-spark-cap {
  font-family: var(--font-mono); font-size: 9px;
  letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--text-mute);
}

/* ---- anomaly strip under hero ---- */
.anomaly-section {
  max-width: 1440px; margin: 0 auto;
  padding: 12px 40px 28px;
  border-top: 1px solid var(--line);
}
.anomaly-inner {
  background: var(--bg-2);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 10px 14px 6px;
}
.anomaly-head {
  display: flex; align-items: center; gap: 16px;
  font-family: var(--font-mono); font-size: 10px;
  letter-spacing: 0.14em; color: var(--text-mute);
  margin-bottom: 6px;
  flex-wrap: wrap;
}
.anomaly-label { color: var(--accent); }
.anomaly-range { font-size: 10px; color: var(--text-dim); letter-spacing: 0.06em; }
.anomaly-legend { display: flex; gap: 10px; margin-left: auto; flex-wrap: wrap; }
.ano-leg {
  display: inline-flex; align-items: center; gap: 5px;
  color: var(--text-dim); text-transform: uppercase;
}
.ano-leg::before {
  content: ''; width: 8px; height: 8px;
  background: var(--leg, var(--accent));
  border-radius: 1px;
}
.anomaly-strip {
  display: block; width: 100%; height: 42px;
}
.anomaly-strip .ano-mark { cursor: pointer; }
.anomaly-strip .ano-mark:hover { stroke-width: 4; }

/* ---- cross-filter sticky banner ---- */
.filter-banner {
  position: sticky; top: 0; z-index: 30;
  background: var(--bg-2);
  border-bottom: 2px solid var(--accent);
  padding: 10px 40px;
  max-width: 1440px; margin: 0 auto;
  display: flex; align-items: center; gap: 14px;
  font-family: var(--font-mono); font-size: 12px;
  color: var(--text);
  box-shadow: 0 2px 8px rgba(0,0,0,0.4);
}
.filter-banner[hidden] { display: none; }
.filter-banner .banner-label {
  background: var(--accent); color: var(--accent-ink);
  padding: 3px 10px; border-radius: 2px;
  font-weight: 600; letter-spacing: 0.14em; font-size: 10px;
}
.filter-banner .banner-clear {
  margin-left: auto;
  background: transparent;
  border: 1px solid var(--line-2);
  color: var(--text-dim);
  cursor: pointer;
  padding: 4px 12px;
  border-radius: 2px;
  font: inherit;
  letter-spacing: 0.08em;
}
.filter-banner .banner-clear:hover {
  color: var(--accent); border-color: var(--accent);
}
#chart-timeline, #chart-heatmap { cursor: crosshair; }

.chart {
  width: 100%; min-height: 380px;
  background: var(--bg-2);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 16px;
}

.legend-row {
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-mute); letter-spacing: 0.08em;
  display: flex; gap: 20px; flex-wrap: wrap;
  margin-bottom: 12px;
}
.legend-row .lg {
  display: inline-block; width: 10px; height: 10px; border-radius: 2px;
  margin-right: 6px; vertical-align: -1px;
}
.legend-row .lg-neutral { background: #5089B8; }
.legend-row .lg-high { background: #D9A04A; }
.legend-row .lg-ransom { background: #B53521; }

.table-controls {
  display: flex; gap: 12px; margin-bottom: 12px; flex-wrap: wrap;
  font-family: var(--font-mono); font-size: 12px;
}
.table-controls input {
  background: var(--bg-2);
  border: 1px solid var(--line-2);
  color: var(--text);
  font: inherit;
  padding: 8px 12px;
  border-radius: 3px;
  min-width: 280px;
}
.table-controls input::placeholder { color: var(--text-mute); }
.table-controls .count { color: var(--text-mute); align-self: center; }
.table-controls .count b { color: var(--text); font-weight: 500; }

.table-wrap {
  border: 1px solid var(--line); border-radius: 4px;
  overflow: auto; background: var(--bg-2);
  max-height: 720px;
}
table.records {
  width: 100%; border-collapse: collapse;
  font-family: var(--font-mono); font-size: 12px;
}
table.records thead th {
  background: var(--bg-3); color: var(--text-mute);
  font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase;
  padding: 10px 12px; text-align: left;
  border-bottom: 1px solid var(--line);
  cursor: pointer; user-select: none;
  position: sticky; top: 0; z-index: 1;
}
table.records thead th:hover { color: var(--accent); }
table.records thead th .sort-mark { opacity: 0.5; margin-left: 6px; }
table.records tbody td {
  padding: 7px 12px;
  border-bottom: 1px solid var(--line);
  color: var(--text-dim);
  vertical-align: top;
  word-break: break-all;
}
table.records tbody tr:hover td { background: var(--bg-3); color: var(--text); }
table.records td.path { color: var(--text); }
table.records td.reasons { color: var(--accent); }

/* ---- virtualized records table (v2) ---- */
.vt-toolbar {
  position: sticky; top: 0; z-index: 5;
  background: var(--bg); padding: 12px 0 16px;
  border-bottom: 1px solid var(--line);
  margin-bottom: 14px;
}
.vt-row {
  display: flex; align-items: center; gap: 10px;
  flex-wrap: wrap; margin-bottom: 8px;
  font-family: var(--font-mono); font-size: 12px;
}
.vt-row:last-child { margin-bottom: 0; }
.vt-input {
  background: var(--bg-2);
  border: 1px solid var(--line-2);
  color: var(--text);
  font: inherit; padding: 7px 10px;
  border-radius: 3px;
  min-width: 280px;
}
.vt-input.vt-date { min-width: 170px; font-size: 11px; }
.vt-input::placeholder { color: var(--text-mute); }
.vt-input:focus { outline: none; border-color: var(--accent); }
.vt-spacer { flex: 1 1 auto; }
.vt-btn {
  background: var(--bg-2);
  border: 1px solid var(--line-2);
  color: var(--text-dim);
  font: inherit; padding: 7px 12px;
  border-radius: 3px; cursor: pointer;
  letter-spacing: 0.08em;
}
.vt-btn:hover { color: var(--text); border-color: var(--text-mute); }
.vt-btn.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); font-weight: 600; }
.vt-btn.primary:hover { background: var(--accent-2); border-color: var(--accent-2); }
.vt-count {
  color: var(--text-mute); align-self: center;
  letter-spacing: 0.08em; padding: 0 6px;
}
.vt-count b { color: var(--text); font-weight: 500; }
.vt-mute { color: var(--text-mute); }
.vt-drop {
  position: relative;
  background: var(--bg-2);
  border: 1px solid var(--line-2);
  border-radius: 3px;
}
.vt-drop summary {
  list-style: none; cursor: pointer;
  padding: 7px 12px;
  color: var(--text-dim);
  letter-spacing: 0.08em;
  display: flex; align-items: center; gap: 8px;
}
.vt-drop summary::-webkit-details-marker { display: none; }
.vt-drop summary::after { content: '▾'; font-size: 9px; color: var(--text-mute); margin-left: 2px; }
.vt-drop[open] summary { color: var(--text); border-bottom: 1px solid var(--line); }
.vt-tag {
  background: var(--bg-3); color: var(--text-mute);
  padding: 1px 7px; border-radius: 999px;
  font-size: 10px; letter-spacing: 0.06em;
}
.vt-drop-body {
  position: absolute; top: 100%; left: -1px;
  min-width: 280px; max-width: 480px;
  max-height: 360px; overflow-y: auto;
  background: var(--bg-2);
  border: 1px solid var(--line-2);
  border-top: none;
  border-bottom-left-radius: 3px;
  border-bottom-right-radius: 3px;
  padding: 8px;
  display: flex; flex-wrap: wrap; gap: 4px;
  z-index: 10;
}
.vchip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 8px; border-radius: 2px;
  background: var(--bg-3); color: var(--text-dim);
  border: 1px solid transparent;
  cursor: pointer; font-size: 11px;
  white-space: nowrap;
}
.vchip:hover { color: var(--text); }
.vchip input { margin: 0; accent-color: var(--accent); }
.vchip:has(input:checked) {
  background: color-mix(in oklch, var(--chip, var(--accent)) 18%, var(--bg-3));
  border-color: var(--chip, var(--accent));
  color: var(--text);
}
.vt-daterange {
  display: flex; align-items: center; gap: 8px;
  color: var(--text-mute); letter-spacing: 0.08em;
}
.vt-label { font-size: 10px; }
.vt-note {
  margin-top: 10px; padding: 8px 12px;
  background: var(--bg-2); border: 1px solid var(--line);
  border-radius: 3px; color: var(--text-mute);
  font-family: var(--font-mono); font-size: 11px;
}
.vt-note code { color: var(--accent); }

.vt-wrap {
  border: 1px solid var(--line); border-radius: 4px;
  background: var(--bg-2); overflow: hidden;
}
.vt-head, .vt-row-r {
  display: flex; align-items: stretch;
  font-family: var(--font-mono); font-size: 12px;
  width: 100%; box-sizing: border-box;
}
.vt-head {
  background: var(--bg-3); color: var(--text-mute);
  font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase;
  border-bottom: 1px solid var(--line);
  position: sticky; top: 0; z-index: 2;
}
.vt-head .vt-cell { cursor: pointer; user-select: none; padding: 10px 12px; }
.vt-head .vt-cell:hover { color: var(--accent); }
.vt-sort { opacity: 0.55; margin-left: 6px; }
.vt-cell {
  padding: 6px 12px;
  color: var(--text-dim);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.vt-col-ts      { flex: 0 0 200px; }
.vt-col-reason  { flex: 0 0 280px; overflow-x: auto; white-space: nowrap; scrollbar-width: thin; }
.vt-col-path    { flex: 1 1 auto; color: var(--text); min-width: 200px; word-break: break-all; white-space: normal; }
.vt-col-frn     { flex: 0 0 110px; font-size: 11px; }
.vt-col-actions { flex: 0 0 220px; display: flex; gap: 4px; align-items: center; }

.vt-scroll {
  position: relative;
  height: 720px;
  overflow-y: auto;
  background: var(--bg-2);
}
.vt-sizer { width: 1px; pointer-events: none; }
.vt-viewport { position: absolute; top: 0; left: 0; right: 0; }
.vt-row-r {
  position: absolute; left: 0; right: 0;
  height: 28px; box-sizing: border-box;
  border-bottom: 1px solid var(--line);
  align-items: center;
}
.vt-row-r { cursor: pointer; }
.vt-row-r:hover { background: var(--bg-3); }
.vt-row-r:hover .vt-cell { color: var(--text); }

/* ---- FRN drill-down modal ---- */
.frn-modal {
  position: fixed; inset: 0;
  z-index: 100;
}
.frn-modal[hidden] { display: none; }
.frn-modal-backdrop {
  position: absolute; inset: 0;
  background: rgba(0,0,0,0.65);
  cursor: pointer;
}
.frn-modal-card {
  position: absolute;
  top: 50%; left: 50%; transform: translate(-50%, -50%);
  background: var(--bg-2);
  border: 1px solid var(--line-2);
  border-radius: 4px;
  width: min(94vw, 1200px);
  max-height: 86vh;
  display: flex; flex-direction: column;
  box-shadow: 0 12px 48px rgba(0,0,0,0.6);
}
.frn-modal-head {
  padding: 14px 18px;
  border-bottom: 1px solid var(--line);
  display: flex; align-items: center; gap: 16px;
  flex-wrap: wrap;
}
.frn-modal-title {
  flex: 1;
  font-family: var(--font-mono); font-size: 12px;
  color: var(--text);
  word-break: break-all;
  letter-spacing: 0.04em;
}
.frn-modal-title .frn-modal-frn {
  color: var(--accent); font-weight: 600;
}
.frn-modal-title .frn-modal-path { color: var(--text); }
.frn-modal-title .frn-modal-count { color: var(--text-mute); }
.frn-modal-close {
  background: transparent;
  border: 1px solid var(--line-2);
  color: var(--text-dim);
  font: inherit;
  padding: 5px 12px;
  border-radius: 2px;
  cursor: pointer;
  letter-spacing: 0.08em;
}
.frn-modal-close:hover { color: var(--accent); border-color: var(--accent); }
.frn-modal-body {
  overflow-y: auto;
  padding: 14px 18px 20px;
  font-family: var(--font-mono); font-size: 12px;
}
.frn-tl {
  display: block;
  width: 100%;
  margin-bottom: 14px;
  background: var(--bg-3);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 4px;
}
.frn-tl line { cursor: crosshair; }
.frn-tl line:hover { stroke-width: 4; }
.frn-events-wrap {
  border: 1px solid var(--line);
  border-radius: 3px;
  overflow-x: auto;
}
table.frn-events {
  width: 100%; border-collapse: collapse;
  font-size: 11px;
}
table.frn-events thead th {
  background: var(--bg-3); color: var(--text-mute);
  padding: 6px 10px; text-align: left;
  letter-spacing: 0.06em; font-weight: 500;
  border-bottom: 1px solid var(--line);
  position: sticky; top: 0;
}
table.frn-events tbody td {
  padding: 4px 10px;
  border-bottom: 1px solid var(--line);
  color: var(--text-dim);
  vertical-align: top;
}
table.frn-events tbody tr:hover td { background: var(--bg-3); color: var(--text); }
table.frn-events td.ts { white-space: nowrap; color: var(--text); }
table.frn-events td.path { word-break: break-all; color: var(--text); }
.frn-events-trim {
  padding: 8px 12px;
  color: var(--text-mute);
  font-size: 11px;
  letter-spacing: 0.08em;
}

.vt-rbadge {
  display: inline-block;
  padding: 1px 6px;
  margin-right: 3px;
  font-size: 10px;
  border-radius: 2px;
  background: color-mix(in oklch, var(--rb, var(--accent)) 22%, var(--bg-3));
  color: var(--text);
  border-left: 2px solid var(--rb, var(--accent));
  white-space: nowrap;
}
.vt-qa {
  font-family: var(--font-mono); font-size: 10px;
  padding: 2px 6px; border-radius: 2px;
  border: 1px solid var(--line-2);
  background: transparent; color: var(--text-mute);
  cursor: pointer;
}
.vt-qa:hover { color: var(--accent); border-color: var(--accent); }
mark {
  background: color-mix(in oklch, var(--accent) 35%, transparent);
  color: var(--text); padding: 0 1px;
}

.foot {
  max-width: 1440px; margin: 0 auto;
  padding: 32px 40px; border-top: 1px solid var(--line);
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-mute); letter-spacing: 0.08em;
  display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap;
}
.foot b { color: var(--text); font-weight: 500; }

.warn {
  background: var(--bg-2);
  border: 1px solid var(--sev-medium);
  border-left: 4px solid var(--sev-medium);
  border-radius: 3px;
  padding: 12px 16px;
  font-family: var(--font-mono); font-size: 12px;
  color: var(--text-dim);
  max-width: 1360px; margin: 0 auto;
}
.warn b { color: var(--sev-medium); margin-right: 8px; }
"""


def write_csv(records: List[USNRecord], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(records[0]).keys()) if records else [
            "offset", "record_length", "major_version", "minor_version", "file_reference_number",
            "parent_file_reference_number", "usn", "timestamp_utc", "reason", "reason_names",
            "source_info", "security_id", "file_attributes", "file_attribute_names", "filename", "reconstructed_path"
        ])
        writer.writeheader()
        for r in records:
            d = asdict(r)
            d["reason_names"] = ";".join(r.reason_names)
            d["file_attribute_names"] = ";".join(r.file_attribute_names)
            writer.writerow(d)


def write_json(records: List[USNRecord], findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "tool": "CQUSNDeepAnalyzer",
            "records": [asdict(r) for r in records],
            "findings": [asdict(x) for x in findings],
        }, f, indent=2, ensure_ascii=False)


# Mapping USN reason flag -> Plaso/Timesketch timestamp_desc label.
_USN_REASON_TIMESTAMP_DESC = {
    "FILE_CREATE":        "File Created (USN)",
    "FILE_DELETE":        "File Deleted (USN)",
    "RENAME_NEW_NAME":    "File Renamed New Name (USN)",
    "RENAME_OLD_NAME":    "File Renamed Old Name (USN)",
    "DATA_OVERWRITE":     "Content Modification (USN)",
    "DATA_EXTEND":        "Content Modification (USN)",
    "DATA_TRUNCATION":    "Content Modification (USN)",
    "NAMED_DATA_OVERWRITE": "Named Stream Modification (USN)",
    "NAMED_DATA_EXTEND":    "Named Stream Modification (USN)",
    "NAMED_DATA_TRUNCATION":"Named Stream Modification (USN)",
    "EA_CHANGE":          "Extended Attribute Change (USN)",
    "SECURITY_CHANGE":    "Security Change (USN)",
    "INDEXABLE_CHANGE":   "Indexable Change (USN)",
    "BASIC_INFO_CHANGE":  "Basic Info Change (USN)",
    "HARD_LINK_CHANGE":   "Hard Link Change (USN)",
    "COMPRESSION_CHANGE": "Compression Change (USN)",
    "ENCRYPTION_CHANGE":  "Encryption Change (USN)",
    "OBJECT_ID_CHANGE":   "Object ID Change (USN)",
    "REPARSE_POINT_CHANGE":"Reparse Point Change (USN)",
    "STREAM_CHANGE":      "Stream Change (USN)",
    "CLOSE":              "File Handle Closed (USN)",
}


def _usn_timestamp_desc(reason_names: List[str]) -> str:
    """Pick a Plaso-style timestamp_desc for a USN record's reason bitmask."""
    if not reason_names:
        return "USN Event"
    # Prefer the most informative reason if multiple are set.
    priority = [
        "FILE_DELETE", "FILE_CREATE", "RENAME_NEW_NAME", "RENAME_OLD_NAME",
        "DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION",
        "ENCRYPTION_CHANGE", "REPARSE_POINT_CHANGE", "HARD_LINK_CHANGE",
        "BASIC_INFO_CHANGE", "SECURITY_CHANGE", "CLOSE",
    ]
    for name in priority:
        if name in reason_names:
            return _USN_REASON_TIMESTAMP_DESC.get(name, name)
    return _USN_REASON_TIMESTAMP_DESC.get(reason_names[0], reason_names[0])


def write_jsonl(
    records: List[USNRecord],
    findings: List[Finding],
    mft_records: Optional[List[MFTRecord]],
    mft_path_map: Optional[Dict[str, str]],
    evtx_records: Optional[List[EvtxRecord]],
    path: str,
) -> int:
    """Write a Plaso/Timesketch-compatible JSONL super-timeline. Returns count of lines."""
    written = 0
    with open(path, "w", encoding="utf-8") as f:
        # 1) USN events - one per record.
        for r in records:
            entry: Dict[str, object] = {
                "datetime": r.timestamp_utc,
                "timestamp_desc": _usn_timestamp_desc(r.reason_names),
                "source": "USN",
                "source_long": "NTFS USN Journal Change",
                "message": (
                    f"{r.reconstructed_path or r.filename} "
                    f"[{';'.join(r.reason_names)}]"
                ),
                "parser": "cqusn_deep_analyzer:usn",
                "data_type": "fs:ntfs:usn_change",
                "filename": r.reconstructed_path or r.filename,
                "file_reference_number": r.file_reference_number,
                "parent_file_reference_number": r.parent_file_reference_number,
                "usn": r.usn,
                "reasons": r.reason_names,
                "file_attributes": r.file_attribute_names,
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            written += 1

        # 2) MFT timestamps - up to 8 events per non-zero ($SI x4 + $FN x4).
        if mft_records:
            ts_specs = [
                ("si_created",      "$SI Created",              "fs:ntfs:mft:si_created"),
                ("si_modified",     "$SI Content Modification", "fs:ntfs:mft:si_modified"),
                ("si_mft_modified", "$SI MFT Record Change",    "fs:ntfs:mft:si_mft_changed"),
                ("si_accessed",     "$SI Last Access",          "fs:ntfs:mft:si_accessed"),
                ("fn_created",      "$FN Created",              "fs:ntfs:mft:fn_created"),
                ("fn_modified",     "$FN Content Modification", "fs:ntfs:mft:fn_modified"),
                ("fn_mft_modified", "$FN MFT Record Change",    "fs:ntfs:mft:fn_mft_changed"),
                ("fn_accessed",     "$FN Last Access",          "fs:ntfs:mft:fn_accessed"),
            ]
            for m in mft_records:
                base_path = mft_path_map.get(m.frn) if mft_path_map else None
                full = (base_path + "\\" + m.filename) if base_path else m.filename
                tags: List[str] = []
                if m.si_lt_fn:
                    tags.append("timestomping_si_lt_fn")
                if m.usec_zeros:
                    tags.append("timestomping_usec_zeros")
                if m.has_ads:
                    tags.append("ads")
                if m.motw_zone_id:
                    tags.append(f"motw_zone_{m.motw_zone_id}")
                for attr_name, desc, dtype in ts_specs:
                    ft = getattr(m, attr_name)
                    if not ft:
                        continue
                    iso = filetime_to_iso(ft)
                    if not iso:
                        continue
                    entry = {
                        "datetime": iso,
                        "timestamp_desc": desc,
                        "source": "MFT",
                        "source_long": "NTFS $MFT Record",
                        "message": f"{full}  [{desc}]",
                        "parser": "cqusn_deep_analyzer:mft",
                        "data_type": dtype,
                        "filename": full,
                        "file_reference_number": m.frn,
                        "parent_file_reference_number": m.parent_frn,
                        "is_directory": m.is_directory,
                        "in_use": m.in_use,
                    }
                    if m.ads_names:
                        entry["ads_names"] = m.ads_names
                    if m.motw_host_url:
                        entry["motw_host_url"] = m.motw_host_url
                    if m.motw_referrer_url:
                        entry["motw_referrer_url"] = m.motw_referrer_url
                    if tags:
                        entry["tag"] = tags
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    written += 1

        # 3) Behavioral findings (severity + samples).
        for fnd in findings:
            if not fnd.timestamp_utc:
                continue
            entry = {
                "datetime": fnd.timestamp_utc,
                "timestamp_desc": f"CQUSN Finding ({fnd.severity})",
                "source": "FINDING",
                "source_long": "CQUSNDeepAnalyzer Behavioral Finding",
                "message": f"[{fnd.severity.upper()}] {fnd.title} :: {fnd.description}",
                "parser": "cqusn_deep_analyzer:finding",
                "data_type": f"cqusn:finding:{fnd.category}",
                "severity": fnd.severity,
                "category": fnd.category,
                "title": fnd.title,
                "count": fnd.count,
                "samples": fnd.sample_paths,
                "context": fnd.context_lines,
                "tag": ["finding", fnd.severity, fnd.category],
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            written += 1

        # 4) EVTX events (only when --evtx was passed).
        if evtx_records:
            for e in evtx_records:
                entry = {
                    "datetime": e.timestamp.isoformat(),
                    "timestamp_desc": f"Windows Event Log [{e.event_id}]",
                    "source": "EVT",
                    "source_long": "Windows Event Log (pre-parsed)",
                    "message": (
                        f"[{e.event_id} @ {e.channel}] user={e.username or '?'} "
                        f":: {(e.executable_info or e.payload or '')[:240]}"
                    ),
                    "parser": "cqusn_deep_analyzer:evtx",
                    "data_type": "windows:evtx:record",
                    "event_identifier": e.event_id,
                    "provider": e.provider,
                    "channel": e.channel,
                    "username": e.username,
                    "executable_info": e.executable_info,
                    "source_file": e.source,
                }
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                written += 1
    return written


def write_html(
    records: List[USNRecord],
    findings: List[Finding],
    path: str,
    max_rows: int = 1000,
    *,
    source: str = "",
    burst_window: int = 60,
    title: str = "CQUSNDeepAnalyzer Report",
    plotly_path: Optional[str] = None,
    charts_enabled: bool = True,
) -> None:
    """Render the full HTML report (CQURE-styled) at `path`."""
    bin_seconds = pick_bin_seconds(records)
    timeline_data = aggregate_timeline(records, bin_seconds)
    hour_day_matrix = aggregate_hour_day_matrix(records)
    reasons_series = aggregate_reasons_over_time(records, bin_seconds)
    sankey_data = aggregate_sankey(records)
    extensions = aggregate_extensions(records)
    paths_tree = aggregate_paths_tree(records)
    max_burst, _ = find_max_burst(records, burst_window)

    first_ts = records[0].timestamp_utc if records else ""
    last_ts = records[-1].timestamp_utc if records else ""

    meta: Dict[str, object] = {
        "title": title,
        "generated_iso": dt.datetime.now(dt.timezone.utc).isoformat(),
        "record_count": len(records),
        "time_range": (first_ts, last_ts),
        "bin_seconds": bin_seconds,
        "source": source,
        "burst_window": burst_window,
        "max_burst": max_burst,
        "top_path": top_path(records),
        "max_rows": max_rows,
    }

    plotly_js = _load_plotly_js(plotly_path) if charts_enabled else ""
    if charts_enabled and not plotly_js:
        print(
            "Warning: plotly.min.js not found in vendor/ (and no --plotly-path given). "
            "Rendering degraded HTML without interactive charts.",
            file=sys.stderr,
        )

    parts: List[str] = []
    parts.append(_render_top_strip(meta))
    parts.append(_render_header_nav(meta))
    parts.append(_render_hero(records, findings, meta))
    parts.append(_render_active_filter_banner())
    parts.append(_render_anomaly_strip(findings, records))

    if charts_enabled and not plotly_js:
        parts.append(_render_warning(
            "plotly.min.js not found; charts omitted. Place a copy at vendor/plotly.min.js or pass --plotly-path."
        ))

    parts.append(_render_findings(findings, records=records))

    if plotly_js:
        parts.append(_render_timeline_chart(timeline_data, findings, bin_seconds))
        parts.append(_render_heatmap_chart(hour_day_matrix))
        parts.append(_render_reasons_chart(reasons_series))
        parts.append(_render_sankey_chart(sankey_data))
        parts.append(_render_extensions_chart(extensions))
        parts.append(_render_treemap_chart(paths_tree))

    parts.append(_render_records_table(records, max_rows))
    parts.append(_render_footer(meta))

    body = "\n".join(parts)
    table_js = _render_inline_table_js()
    crossfilter_js = _render_crossfilter_js() if plotly_js else ""
    plotly_script = f"<script>{plotly_js}</script>" if plotly_js else ""

    content = (
        "<!doctype html>"
        "<html lang='en'>"
        "<head>"
        "<meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<meta name='viewport' content='width=1280'>"
        f"<style>{_render_styles()}</style>"
        "<script>(function(){try{if(localStorage.getItem('cqusn-theme')==='light')"
        "document.documentElement.setAttribute('data-theme','light');}catch(e){}})();</script>"
        f"{plotly_script}"
        "</head>"
        "<body>"
        f"{body}"
        f"<script>{table_js}</script>"
        + (f"<script>{crossfilter_js}</script>" if crossfilter_js else "")
        + f"<script>{_render_theme_js()}</script>"
        + f"<script>{_render_section_nav_js()}</script>"
        + "</body>"
        "</html>"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def severity_allowed(finding: Finding, min_severity: str) -> bool:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(finding.severity, 0) >= order.get(min_severity, 0)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="CQUSNDeepAnalyzer",
        description="Parse raw NTFS USN Journal $J and generate forensic timeline outputs."
    )
    parser.add_argument("--input", "-i", required=True, help="Path to raw $UsnJrnl:$J binary stream")
    parser.add_argument("--mft", help="Optional path to raw $MFT for full parent-path reconstruction (and, in later stages, timestomping/ADS findings).")
    parser.add_argument("--baseline", help="Path to text file with extra baseline path patterns (one substring per line, # for comment, case-insensitive). Matched files are excluded from timestomping findings on top of built-in defaults.")
    parser.add_argument("--no-baseline", action="store_true", help="Disable built-in baseline path patterns (Windows Update / WinSxS / .NET / Defender / etc.). Patterns from --baseline still apply if provided.")
    parser.add_argument("--rules", help="Path to JSON file with additional filename rules (array of {name, patterns, severity, category, description}). Combined with built-in rules unless --no-builtin-rules is set.")
    parser.add_argument("--no-builtin-rules", action="store_true", help="Disable built-in YARA-lite filename rules (Mimikatz, vssadmin, Cobalt Strike, ransomware family names, etc.).")
    parser.add_argument("--new-ext-late-fraction", type=float, default=0.3, help="For the 'new extensions outliers' detector: how late in the timeline an extension must first appear to be flagged. Range (0, 1]. Default 0.3 means: only the last 30%% of the window.")
    parser.add_argument("--new-ext-min-count", type=int, default=10, help="Minimum total event count for a late-emerging extension to be reported. Default 10.")
    parser.add_argument("--evtx", help="Path to a pre-parsed EVTX CSV (e.g. from EvtxECmd) to enrich findings with Windows event context and produce standalone EVTX findings (1102/4720/4732/7045/etc.).")
    parser.add_argument("--evtx-window", type=int, default=120, help="Seconds around each high/critical finding to pull EVTX context from. Default 120.")
    parser.add_argument("--no-prefetch", action="store_true", help="Disable Prefetch execution detection (which works purely from .pf files observed in USN, no external tool required).")
    parser.add_argument("--prefetch-window", type=int, default=300, help="Seconds around each high/critical finding to pull Prefetch context from. Default 300.")
    parser.add_argument("--csv", help="Write timeline CSV")
    parser.add_argument("--json", help="Write full JSON report")
    parser.add_argument("--html", help="Write HTML report")
    parser.add_argument("--jsonl", help="Write a Plaso/Timesketch-compatible JSONL super-timeline (USN + MFT $SI/$FN times + behavioral findings + EVTX, one JSON object per line).")
    parser.add_argument("--max-records", type=int, help="Limit number of records parsed")
    parser.add_argument("--include-path", help="Keep only records whose reconstructed path contains this string")
    parser.add_argument("--exclude-path", help="Exclude records whose reconstructed path contains this string")
    parser.add_argument("--burst-window", type=int, default=60, help="Burst detection window in seconds, default 60")
    parser.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="info")
    parser.add_argument("--quiet", action="store_true", help="Do not print console findings")
    parser.add_argument("--plotly-path", help="Path to plotly.min.js for embedding in the HTML report (default: vendor/plotly.min.js next to this script)")
    parser.add_argument("--no-charts", action="store_true", help="Render HTML without interactive charts (debug / minimal report)")
    parser.add_argument("--html-title", default="CQUSNDeepAnalyzer Report", help="Title text used in the HTML report header")
    parser.add_argument("--max-html-rows", type=int, default=1000,
                        help="Max rows rendered in the HTML records table. 0 = all (warning: >30000 rows is slow in the browser).")

    args = parser.parse_args(argv)

    if not os.path.exists(args.input):
        print(f"Input not found: {args.input}", file=sys.stderr)
        return 2

    if args.baseline and not os.path.exists(args.baseline):
        print(f"--baseline file not found: {args.baseline}", file=sys.stderr)
        return 2
    baseline_patterns = _load_baseline_patterns(
        args.baseline, include_defaults=not args.no_baseline
    )

    rules: List[FilenameRule] = []
    if not args.no_builtin_rules:
        rules.extend(_BUILTIN_FILENAME_RULES)
    if args.rules:
        if not os.path.exists(args.rules):
            print(f"--rules file not found: {args.rules}", file=sys.stderr)
            return 2
        try:
            rules.extend(load_filename_rules_from_json(args.rules))
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"--rules: {exc}", file=sys.stderr)
            return 2

    mft_path_map: Optional[Dict[str, str]] = None
    mft_records: List[MFTRecord] = []
    mft_findings: List[Finding] = []
    if args.mft:
        if not os.path.exists(args.mft):
            print(f"$MFT input not found: {args.mft}", file=sys.stderr)
            return 2
        with open(args.mft, "rb") as fm:
            mft_records = list(parse_mft_records(fm))
        mft_path_map = build_mft_path_map(mft_records)
        mft_findings = (
            detect_timestomping_findings(mft_records, mft_path_map, baseline_patterns)
            + detect_ads_findings(mft_records, mft_path_map)
            + detect_motw_findings(mft_records, mft_path_map)
        )
        if not args.quiet:
            print(
                f"Loaded {len(mft_records)} MFT records, "
                f"built {sum(1 for v in mft_path_map.values() if v)} non-empty path entries, "
                f"{len(mft_findings)} MFT-derived findings",
                file=sys.stderr,
            )

    with open(args.input, "rb") as f:
        records = list(parse_usn_records(f, args.max_records))

    reconstruct_paths(records, mft_path_map=mft_path_map)
    records = filter_records(records, args.include_path, args.exclude_path)
    records.sort(key=lambda r: (r.timestamp_utc, r.usn))

    yara_findings = detect_filename_rule_findings(records, rules, baseline_patterns) if rules else []
    if rules and not args.quiet:
        print(
            f"Active filename rules: {len(rules)} ({len(yara_findings)} hit)",
            file=sys.stderr,
        )

    new_ext_findings = detect_new_extensions_findings(
        records,
        late_fraction=max(0.0, min(1.0, args.new_ext_late_fraction)),
        min_count=max(1, args.new_ext_min_count),
    )

    evtx_records: List[EvtxRecord] = []
    evtx_findings: List[Finding] = []
    if args.evtx:
        if not os.path.exists(args.evtx):
            print(f"--evtx file not found: {args.evtx}", file=sys.stderr)
            return 2
        evtx_records = load_evtx_csv(args.evtx)
        evtx_findings = detect_evtx_standalone_findings(evtx_records)
        if not args.quiet:
            print(
                f"Loaded {len(evtx_records)} EVTX records, "
                f"{len(evtx_findings)} standalone EVTX findings",
                file=sys.stderr,
            )

    prefetch_findings: List[Finding] = []
    prefetch_by_exe: Dict[str, List[USNRecord]] = {}
    if not args.no_prefetch:
        prefetch_findings, prefetch_by_exe = detect_prefetch_executions(records, rules)
        if prefetch_by_exe and not args.quiet:
            print(
                f"Prefetch: {len(prefetch_by_exe)} unique executables observed, "
                f"{len(prefetch_findings)} prefetch finding(s)",
                file=sys.stderr,
            )

    all_findings = (
        mft_findings
        + yara_findings
        + new_ext_findings
        + evtx_findings
        + prefetch_findings
        + analyze(records, args.burst_window)
    )

    if evtx_records:
        enrich_findings_with_evtx_context(all_findings, evtx_records, window_seconds=max(10, args.evtx_window))
    if prefetch_by_exe:
        enrich_findings_with_prefetch_context(all_findings, prefetch_by_exe, window_seconds=max(10, args.prefetch_window))

    findings = [
        f for f in all_findings if severity_allowed(f, args.min_severity)
    ]

    if args.csv:
        write_csv(records, args.csv)
    if args.json:
        write_json(records, findings, args.json)
    if args.jsonl:
        jsonl_count = write_jsonl(
            records,
            findings,
            mft_records or None,
            mft_path_map,
            evtx_records or None,
            args.jsonl,
        )
        if not args.quiet:
            print(f"Wrote {jsonl_count} JSONL entries to {args.jsonl}", file=sys.stderr)
    if args.html:
        html_rows = args.max_html_rows if args.max_html_rows > 0 else len(records)
        write_html(
            records,
            findings,
            args.html,
            max_rows=html_rows,
            source=args.input,
            burst_window=args.burst_window,
            title=args.html_title,
            plotly_path=args.plotly_path,
            charts_enabled=not args.no_charts,
        )

    if not args.quiet:
        print(f"CQUSNDeepAnalyzer parsed {len(records)} records")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.title}: {f.description}")
            for sample in f.sample_paths[:5]:
                print(f"  - {sample}")

    if not any([args.csv, args.json, args.html, args.jsonl]):
        print("No output selected. Use --csv, --json, --jsonl, or --html.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
