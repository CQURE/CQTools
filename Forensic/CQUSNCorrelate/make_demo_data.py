#!/usr/bin/env python3
"""Generate a realistic demo dataset for CQUSNDeepAnalyzer and CQUSNCorrelate.

Produces a synthetic but coherent intrusion story so every detector and every
correlation has something real to find. Nothing here touches a live system.

    py -3 tools/make_demo_data.py samples/

Outputs
-------
    demo_J.bin        raw $UsnJrnl:$J stream (USN_RECORD_V2)
    demo_MFT.raw      raw $MFT with three planted timestamp anomalies
    demo_evtx.csv     EvtxECmd-style CSV with logon sessions and notable events
    demo_README.md    the planted scenario, so demo answers can be checked

The scenario, "Operation Amber", on host WKS-041
------------------------------------------------
    08:41  svc_backup logs on as a service, runs a nightly job
    09:02  jdoe logs on interactively, ordinary document work
    09:58  invoice_2026.docm arrives in Downloads (phishing lure)
    10:04  svchost32.exe dropped to AppData Temp, runs 11 s later
    10:12  attacker RDP session opens from 10.10.7.66 and never logs off
    10:19  recon tooling runs: whoami, net, ipconfig
    10:31  mimi.exe dropped, runs, deleted 41 s later
    10:52  archive_7z staging file grows then is deleted
    11:05  a new local admin is created, a service is installed
    11:20  47 documents renamed to .amberlock
    11:31  Security event log is cleared

What each correlation should surface
------------------------------------
    exec-evidence   svchost32.exe (+11 s), mimi.exe (+6 s), rclone.exe (+9 s)
                    dropped and never run: cleanup.exe
                    ran but not created here: cmd.exe, powershell.exe, net.exe
    lifecycle       mimi.exe 41 s, stage_01.tmp 18 s, archive.7z 6.2 m,
                    plus 12 short-lived .tmp files
    metadata-changed  svchost32.exe, mimi.exe and rclone.exe have BASIC_INFO_CHANGE
                    with no write beside it; minutes_final.docx is the benign
                    counter-example where metadata moved together with a write
    si-vs-fn        svchost32.exe backdated two years, mimi.exe backdated to 06:00,
                    UpdateHealthCheck carries whole-second stamps only
    sessions        jdoe owns the morning document activity,
                    the RDP session owns the tooling and the mass rename,
                    and it has no logoff, so the over-attribution warning fires

Author: Paula Januszkiewicz | CQURE
License: Apache License 2.0
"""
from __future__ import annotations

import datetime as dt
import os
import struct
import sys
from typing import List

WINDOWS_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)

# USN reason bits, mirroring REASON_FLAGS in CQUSNDeepAnalyzer.py
CREATE = 0x00000100
DELETE = 0x00000200
EXTEND = 0x00000002
OVERWRITE = 0x00000001
RENAME_OLD = 0x00001000
RENAME_NEW = 0x00002000
BASIC_INFO = 0x00008000
SECURITY = 0x00000800
CLOSE = 0x80000000

ATTR_ARCHIVE = 0x00000020
ATTR_DIR = 0x00000010

DAY = dt.datetime(2026, 3, 17, tzinfo=dt.timezone.utc)


def at(h: int, m: int, s: float = 0) -> dt.datetime:
    return DAY + dt.timedelta(hours=h, minutes=m, seconds=s)


def to_filetime(d: dt.datetime) -> int:
    return int((d - WINDOWS_EPOCH).total_seconds() * 10_000_000)


def pack_v2(frn: int, parent: int, usn: int, ts: dt.datetime,
            reason: int, attrs: int, name: str) -> bytes:
    fn = name.encode("utf-16le")
    rec = 60 + len(fn)
    pad = (8 - (rec % 8)) % 8
    head = struct.pack("<IHHQQqQIIIIHH", rec + pad, 2, 0, frn, parent, usn,
                       to_filetime(ts), reason, 0, 0, attrs, len(fn), 60)
    return head + fn + (b"\x00" * pad)


class Journal:
    """Accumulates USN records and keeps FRN and USN counters sane."""

    def __init__(self) -> None:
        self.parts: List[bytes] = []
        self._usn = 4096
        self._entry = 200

    def new_frn(self) -> int:
        self._entry += 1
        return (1 << 48) | self._entry          # sequence 1, as real NTFS does

    def rec(self, name: str, parent: int, ts: dt.datetime,
            reason: int, frn: int, attrs: int = ATTR_ARCHIVE) -> int:
        self._usn += 96
        self.parts.append(pack_v2(frn, parent, self._usn, ts, reason, attrs, name))
        return frn

    def touched(self, name: str, parent: int, ts: dt.datetime, frn: int,
                seconds: float = 1.0) -> None:
        """A write followed by a close, the ordinary shape of a file edit."""
        self.rec(name, parent, ts, EXTEND, frn)
        self.rec(name, parent, ts + dt.timedelta(seconds=seconds), EXTEND | CLOSE, frn)

    def created(self, name: str, parent: int, ts: dt.datetime,
                attrs: int = ATTR_ARCHIVE) -> int:
        frn = self.new_frn()
        self.rec(name, parent, ts, CREATE, frn, attrs)
        self.rec(name, parent, ts + dt.timedelta(seconds=0.4), EXTEND | CLOSE, frn, attrs)
        return frn

    def deleted(self, name: str, parent: int, ts: dt.datetime, frn: int) -> None:
        self.rec(name, parent, ts, DELETE | CLOSE, frn)

    def ran(self, exe: str, ts: dt.datetime, pf_dir: int, tag: str = "A1B2C3D4") -> None:
        """A Prefetch file appearing is the evidence that the binary executed."""
        self.created("{}-{}.pf".format(exe.upper(), tag), pf_dir, ts)

    def blob(self) -> bytes:
        return b"".join(self.parts)


# directory FRNs, low numbers so they read as ordinary NTFS entries
ROOT, USERS, JDOE, DOWNLOADS, DOCS, TEMP, PF, SYS32, TASKS = 5, 40, 41, 42, 43, 44, 45, 46, 47


def build_journal() -> Journal:
    j = Journal()

    # directory skeleton, so path reconstruction has parents to chain
    for name, frn, parent in [
        (".", ROOT, ROOT), ("Users", USERS, ROOT), ("jdoe", JDOE, USERS),
        ("Downloads", DOWNLOADS, JDOE), ("Documents", DOCS, JDOE),
        ("Temp", TEMP, JDOE), ("Prefetch", PF, ROOT),
        ("System32", SYS32, ROOT), ("Tasks", TASKS, SYS32),
    ]:
        j.rec(name, parent, at(8, 0), CREATE, frn, ATTR_DIR)

    # ---- 08:41  nightly backup service ------------------------------------
    f = j.created("backup_0317.bak", DOCS, at(8, 41))
    j.touched("backup_0317.bak", DOCS, at(8, 43), f, 120)
    j.ran("robocopy.exe", at(8, 41, 20), PF, "2B7C91E0")

    # ---- 09:02  jdoe starts work ------------------------------------------
    j.ran("explorer.exe", at(9, 2, 30), PF, "AF3D5521")
    j.ran("outlook.exe", at(9, 3, 10), PF, "7C2E19BB")
    for i, doc in enumerate(["q1_forecast.xlsx", "team_notes.docx", "budget.xlsx",
                             "roadmap.pptx", "minutes.docx"]):
        f = j.created(doc, DOCS, at(9, 10 + i * 7))
        j.touched(doc, DOCS, at(9, 12 + i * 7), f, 90)

    # ---- 09:58  the lure ---------------------------------------------------
    lure = j.created("invoice_2026.docm", DOWNLOADS, at(9, 58))
    j.rec("invoice_2026.docm:Zone.Identifier", DOWNLOADS, at(9, 58, 1),
          CREATE | 0x00000020, lure)          # NAMED_DATA_EXTEND, the MOTW stream
    j.ran("winword.exe", at(10, 1, 15), PF, "5E8A2210")

    # ---- 10:04  dropper lands and runs ------------------------------------
    drop = j.created("svchost32.exe", TEMP, at(10, 4))
    j.touched("svchost32.exe", TEMP, at(10, 4, 2), drop, 3)
    j.ran("svchost32.exe", at(10, 4, 11), PF, "9F10CC42")

    # ---- 10:12  attacker RDP session --------------------------------------
    j.ran("cmd.exe", at(10, 14), PF, "4A81B364")
    j.ran("powershell.exe", at(10, 16, 40), PF, "6B3C7710")

    # ---- 10:19  discovery --------------------------------------------------
    for exe, mm, tag in [("whoami.exe", 19, "11AA22BB"), ("net.exe", 20, "33CC44DD"),
                         ("ipconfig.exe", 21, "55EE66FF"), ("systeminfo.exe", 22, "77AA88BB")]:
        j.ran(exe, at(10, mm), PF, tag)

    # ---- 10:31  credential tooling, dropped, run, then removed ------------
    mimi = j.created("mimi.exe", TEMP, at(10, 31))
    j.ran("mimi.exe", at(10, 31, 6), PF, "C0FFEE01")
    j.deleted("mimi.exe", TEMP, at(10, 31, 41), mimi)

    # a tool that was dropped but never executed
    j.created("cleanup.exe", TEMP, at(10, 35))

    # ---- 10:41  exfil client ----------------------------------------------
    rcl = j.created("rclone.exe", TEMP, at(10, 41))
    j.ran("rclone.exe", at(10, 41, 9), PF, "DE4D1234")

    # ---- 10:52  staging, grows then disappears ----------------------------
    arc = j.created("archive.7z", TEMP, at(10, 52))
    for k in range(6):
        j.touched("archive.7z", TEMP, at(10, 53 + k * 1), arc, 40)
    j.deleted("archive.7z", TEMP, at(10, 58, 12), arc)

    # short-lived scratch files, the classic staging signature
    for k in range(12):
        t = at(10, 53 + (k // 3), 5 + (k % 3) * 9)
        f = j.created("stage_{:02d}.tmp".format(k + 1), TEMP, t)
        j.deleted("stage_{:02d}.tmp".format(k + 1), TEMP,
                  t + dt.timedelta(seconds=18 + k * 2), f)

    # ---- 10:46  timestomp: metadata rewritten, content never touched --------
    # BASIC_INFO_CHANGE with no data reason beside it. In the journal this is
    # the whole visible footprint of a SetFileTime call.
    j.rec("svchost32.exe", TEMP, at(10, 46), BASIC_INFO, drop)
    j.rec("svchost32.exe", TEMP, at(10, 46, 1), BASIC_INFO | CLOSE, drop)
    j.rec("mimi.exe", TEMP, at(10, 31, 20), BASIC_INFO | CLOSE, mimi)
    j.rec("rclone.exe", TEMP, at(10, 47), BASIC_INFO | CLOSE, rcl)
    # an ACL change on the staging directory, metadata of a different kind
    j.rec("Temp", JDOE, at(10, 48), SECURITY | CLOSE, TEMP, ATTR_DIR)
    # ordinary counter-example: a document whose metadata moved WITH a write
    f = j.created("minutes_final.docx", DOCS, at(9, 45))
    j.rec("minutes_final.docx", DOCS, at(9, 46), EXTEND | BASIC_INFO | CLOSE, f)

    # ---- 11:05  persistence ------------------------------------------------
    j.created("UpdateHealthCheck", TASKS, at(11, 5, 30))
    j.ran("schtasks.exe", at(11, 5, 40), PF, "90AB12CD")
    j.ran("sc.exe", at(11, 6, 10), PF, "AB90CD12")

    # ---- 11:20  mass rename to a ransom extension -------------------------
    for i in range(47):
        t = at(11, 20, i * 1.5)
        frn = j.new_frn()
        base = "report_{:03d}.docx".format(i)
        j.rec(base, DOCS, t, RENAME_OLD, frn)
        j.rec(base + ".amberlock", DOCS, t + dt.timedelta(seconds=0.2), RENAME_NEW, frn)

    j.created("HOW_TO_RESTORE.txt", DOCS, at(11, 22))
    return j



# =============================================================================
# Synthetic $MFT
# =============================================================================
# Enough of a real MFT record to exercise parse_mft_records: FILE magic, the
# update sequence array, a resident $STANDARD_INFORMATION (0x10) and a resident
# $FILE_NAME (0x30). That is exactly the pair the si-vs-fn subcommand compares.

MFT_RECORD_SIZE = 1024
MFT_SECTOR_SIZE = 512
NAME_TYPE_WIN32 = 1


def _attr_standard_information(created, modified, mft_modified, accessed):
    content = struct.pack("<QQQQ", created, modified, mft_modified, accessed)
    content += struct.pack("<IIIIQQQQ", 0x20, 0, 0, 0, 0, 0, 0, 0)[:24]   # pad to 56
    header = struct.pack("<IIBBHHHHI",
                         0x10,                 # type
                         24 + len(content),    # length
                         0,                    # resident
                         0,                    # name length
                         0,                    # name offset
                         0,                    # flags
                         0,                    # attribute id
                         0, 0)[:16]
    header = struct.pack("<II", 0x10, 24 + len(content))
    header += struct.pack("<BBHHH", 0, 0, 0, 0, 0)      # non_res, name_len, name_off, flags, id
    header += struct.pack("<IHBB", len(content), 24, 0, 0)  # content len, content off, indexed, pad
    return header + content


def _attr_file_name(parent_ref, created, modified, mft_modified, accessed, name):
    nm = name.encode("utf-16le")
    content = struct.pack("<Q", parent_ref)
    content += struct.pack("<QQQQ", created, modified, mft_modified, accessed)
    content += struct.pack("<QQII", 0, 0, 0, 0)          # alloc, real size, flags, reparse
    content += struct.pack("<BB", len(name), NAME_TYPE_WIN32)
    content += nm
    while len(content) % 8:
        content += b"\x00"
    header = struct.pack("<II", 0x30, 24 + len(content))
    header += struct.pack("<BBHHH", 0, 0, 0, 0, 1)
    header += struct.pack("<IHBB", len(content), 24, 0, 0)
    return header + content


def build_mft_record(entry, seq, parent_ref, name, si_times, fn_times, is_dir=False):
    """Assemble one 1024 byte $MFT record with the USA fixup applied."""
    attrs = _attr_standard_information(*si_times) + _attr_file_name(parent_ref, *fn_times, name)
    attrs += struct.pack("<I", 0xFFFFFFFF)               # end of attributes marker

    usa_offset = 48
    usa_count = (MFT_RECORD_SIZE // MFT_SECTOR_SIZE) + 1   # 3 for a 1024 byte record
    attr_offset = usa_offset + 2 * usa_count
    attr_offset += (8 - attr_offset % 8) % 8

    rec = bytearray(MFT_RECORD_SIZE)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, usa_offset, usa_count)
    struct.pack_into("<Q", rec, 8, 0)                    # $LogFile LSN
    struct.pack_into("<HHHH", rec, 16, seq, 1, attr_offset, 0x1 | (0x2 if is_dir else 0))
    struct.pack_into("<II", rec, 24, attr_offset + len(attrs), MFT_RECORD_SIZE)
    struct.pack_into("<Q", rec, 32, 0)                   # base record reference
    struct.pack_into("<H", rec, 40, 0)                   # next attribute id
    struct.pack_into("<I", rec, 44, entry)               # this record number

    rec[attr_offset:attr_offset + len(attrs)] = attrs

    # Update sequence array: the signature replaces the last two bytes of every
    # sector, and the originals are stashed in the array. parse_mft_records
    # reverses this, so the record has to be written the way NTFS writes it.
    usn_sig = b"\x01\x00"
    originals = []
    for i in range(1, usa_count):
        tail = i * MFT_SECTOR_SIZE - 2
        originals.append(bytes(rec[tail:tail + 2]))
        rec[tail:tail + 2] = usn_sig
    rec[usa_offset:usa_offset + 2] = usn_sig
    for i, orig in enumerate(originals, start=1):
        rec[usa_offset + 2 * i:usa_offset + 2 * i + 2] = orig
    return bytes(rec)


def ref(entry, seq=1):
    return (seq << 48) | entry


def build_mft():
    """One MFT covering the demo tree, with three planted timestamp anomalies."""
    def ft(d):
        return to_filetime(d)

    def jitter(d, entry):
        """Deterministic sub-second offset.

        Real NTFS timestamps carry 100 ns precision, so whole-second values are
        themselves a signal. Ordinary demo files therefore get a fractional part,
        which leaves usec_zeros meaning what it is supposed to mean instead of
        firing on every record.
        """
        return ft(d) + ((entry * 7919) % 9_999_999) + 1

    def same(d, entry=0):
        """Four identical stamps. entry=0 keeps them whole-second on purpose."""
        t = ft(d) if entry == 0 else jitter(d, entry)
        return (t, t, t, t)

    records = []

    # 0..15 are reserved in a real volume; emit $MFT itself so the range looks real
    records.append(build_mft_record(0, 1, ref(5), "$MFT",
                                    same(at(0, 0), 1), same(at(0, 0), 1)))
    records.append(build_mft_record(5, 5, ref(5), ".",
                                    same(at(0, 0), 2), same(at(0, 0), 2), is_dir=True))

    for entry, parent, name in [
        (40, 5, "Users"), (41, 40, "jdoe"), (42, 41, "Downloads"),
        (43, 41, "Documents"), (44, 41, "Temp"), (45, 5, "Prefetch"),
        (46, 5, "System32"), (47, 46, "Tasks"),
        (48, 5, "Windows"), (49, 48, "WinSxS"),
    ]:
        records.append(build_mft_record(entry, 1, ref(parent), name,
                                        same(at(8, 0), entry), same(at(8, 0), entry),
                                        is_dir=True))

    # --- ordinary files: $SI and $FN agree, which is the normal state ---------
    normal = [
        (300, 43, "q1_forecast.xlsx", at(9, 10)),
        (301, 43, "team_notes.docx", at(9, 17)),
        (302, 43, "budget.xlsx", at(9, 24)),
        (303, 42, "invoice_2026.docm", at(9, 58)),
        (304, 44, "rclone.exe", at(10, 41)),
        (305, 44, "cleanup.exe", at(10, 35)),
    ]
    for entry, parent, name, when in normal:
        records.append(build_mft_record(entry, 1, ref(parent), name,
                                        same(when, entry), same(when, entry)))

    # --- PLANT 1: svchost32.exe backdated by two years -----------------------
    # $SI rewritten to 2024, $FN left at the real creation time. This is what
    # SetFileTime does, and it is the signature si-vs-fn exists to catch.
    real = at(10, 4)
    fake = dt.datetime(2024, 3, 17, 10, 4, tzinfo=dt.timezone.utc)
    records.append(build_mft_record(
        310, 1, ref(44), "svchost32.exe",
        (ft(fake), ft(fake), jitter(real, 310), ft(fake)),  # $MFT-modified left honest
        same(real, 310)))

    # --- PLANT 2: mimi.exe backdated a few hours, sub-second zeroed ----------
    real = at(10, 31)
    fake = at(6, 0)
    records.append(build_mft_record(
        311, 1, ref(44), "mimi.exe",
        (ft(fake), ft(fake), jitter(real, 311), ft(fake)),
        same(real, 311)))

    # --- PLANT 3: whole-second stamps only, no backdating --------------------
    # A hand-set time that happens to land after $FN. Flags usec-zero alone.
    real = at(11, 5, 30)
    records.append(build_mft_record(
        312, 1, ref(47), "UpdateHealthCheck",
        same(at(12, 0)), same(real, 312)))

    # --- a file under Windows\WinSxS\, which the built-in baseline suppresses.
    # Backdated exactly like a real patch payload, and exactly the sort of benign
    # anomaly that buries a genuine finding when the baseline is switched off.
    records.append(build_mft_record(
        313, 1, ref(49), "winsxs_patch.dll",
        (ft(dt.datetime(2019, 1, 1, tzinfo=dt.timezone.utc)),) * 4,
        same(at(9, 0), 313)))

    return b"".join(records)


SESSIONS = [
    # logon_id, user, type, logon, logoff (None means never logged off)
    ("0x2f1a", "CORP\\svc_backup", 5, at(8, 40), at(9, 5)),
    ("0x4c7b", "CORP\\jdoe", 2, at(9, 2), at(17, 30)),
    ("0x6e29", "CORP\\jdoe_adm", 10, at(10, 12), None),
]

NOTABLE = [
    (at(10, 1, 20), 4688, "CORP\\jdoe", "winword.exe",
     "Process Create: C:\\Program Files\\Microsoft Office\\WINWORD.EXE"),
    (at(10, 4, 10), 4688, "CORP\\jdoe", "svchost32.exe",
     "Process Create: C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe"),
    (at(10, 16, 40), 4688, "CORP\\jdoe_adm", "powershell.exe",
     "Process Create: powershell.exe -nop -w hidden -enc SQBFAFgA"),
    (at(11, 5, 0), 4720, "CORP\\jdoe_adm", "",
     "A user account was created. TargetUserName: svc_update"),
    (at(11, 5, 12), 4732, "CORP\\jdoe_adm", "",
     "A member was added to a security-enabled local group. Group: Administrators"),
    (at(11, 6, 5), 7045, "CORP\\jdoe_adm", "",
     "A service was installed: UpdateHealthCheck, ImagePath: C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost32.exe"),
    (at(11, 5, 35), 4698, "CORP\\jdoe_adm", "",
     "A scheduled task was created: \\UpdateHealthCheck"),
    (at(11, 31, 0), 1102, "CORP\\jdoe_adm", "",
     "The audit log was cleared"),
]


def build_evtx() -> str:
    rows = ["TimeCreated,EventId,Provider,Channel,UserName,ExecutableInfo,Payload,SourceFile"]
    prov = "Microsoft-Windows-Security-Auditing"

    def esc(s: str) -> str:
        return s.replace('"', "'")

    events = []
    for lid, user, ltype, start, end in SESSIONS:
        dom, acct = user.split("\\", 1)
        events.append((start, 4624, user, "", (
            "{{'TargetUserName':'{}','TargetDomainName':'{}','TargetLogonId':'{}',"
            "'LogonType':'{}','IpAddress':'{}','WorkstationName':'WKS-041'}}"
        ).format(acct, dom, lid, ltype, "10.10.7.66" if ltype == 10 else "-")))
        if end is not None:
            events.append((end, 4634, user, "", (
                "{{'TargetUserName':'{}','TargetDomainName':'{}','TargetLogonId':'{}'}}"
            ).format(acct, dom, lid)))
    events.extend(NOTABLE)

    for ts, eid, user, exe, payload in sorted(events, key=lambda e: e[0]):
        rows.append('{},{},{},Security,{},{},"{}",Security.evtx'.format(
            ts.isoformat(), eid, prov, user, exe, esc(payload)))
    return "\n".join(rows) + "\n"


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "samples"
    os.makedirs(outdir, exist_ok=True)

    j = build_journal()
    blob = j.blob()
    jp = os.path.join(outdir, "demo_J.bin")
    with open(jp, "wb") as fh:
        fh.write(blob)

    mft = build_mft()
    mp = os.path.join(outdir, "demo_MFT.raw")
    with open(mp, "wb") as fh:
        fh.write(mft)

    ep = os.path.join(outdir, "demo_evtx.csv")
    with open(ep, "w", encoding="utf-8", newline="") as fh:
        fh.write(build_evtx())

    rp = os.path.join(outdir, "demo_README.md")
    with open(rp, "w", encoding="utf-8", newline="") as fh:
        fh.write("# Demo dataset, Operation Amber\n\n")
        fh.write("Generated by `tools/make_demo_data.py`. Entirely synthetic.\n\n")
        fh.write("```\n" + (__doc__ or "").split("The scenario")[1] + "```\n")

    print("demo_J.bin     {:>8,} bytes, {:,} USN records".format(len(blob), len(j.parts)))
    print("demo_MFT.raw   {:>8,} bytes, {:,} MFT records".format(
        len(mft), len(mft) // MFT_RECORD_SIZE))
    print("demo_evtx.csv  {:>8,} bytes".format(os.path.getsize(ep)))
    print("demo_README.md {:>8,} bytes".format(os.path.getsize(rp)))
    print("\nwritten to: {}".format(os.path.abspath(outdir)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
