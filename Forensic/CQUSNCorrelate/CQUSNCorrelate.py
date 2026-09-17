#!/usr/bin/env python3
"""CQUSNCorrelate, ready-to-launch correlations over CQUSNDeepAnalyzer parsers.

Three correlations that come up in almost every NTFS investigation, each as a
subcommand. All of them reuse the parsers in `CQUSNDeepAnalyzer.py`, so binary
handling, path reconstruction and FRN conventions stay in one place.

    exec-evidence     EXE created AND its Prefetch created  (dropped, then ran)
    lifecycle         file created and later deleted        (staging, cleanup)
    sessions          file creations vs. open logon sessions (who was on the box)
    metadata-changed  metadata touched, and whether content moved with it
    si-vs-fn          $SI (0x10) vs $FN (0x30) timestamps    (timestomp, needs $MFT)

Examples
--------
    py -3 tools/CQUSNCorrelate.py exec-evidence --input J.bin --mft MFT.raw
    py -3 tools/CQUSNCorrelate.py lifecycle --input J.bin --max-lifetime 3600
    py -3 tools/CQUSNCorrelate.py sessions --input J.bin --evtx Security.csv
    py -3 tools/CQUSNCorrelate.py metadata-changed --input J.bin --no-data-change
    py -3 tools/CQUSNCorrelate.py si-vs-fn --mft MFT.raw --only si-lt-fn

Every subcommand prints a table and can also write --csv / --json.

Author: Paula Januszkiewicz | CQURE
License: Apache License 2.0
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import unicodedata
from typing import Dict, List, Optional, Sequence, Tuple

# CQUSNDeepAnalyzer.py holds the parsers. Look for it beside this file first, so
# the tool works as a self contained folder, then in the parent, which is the
# layout inside the repository (tools/ next to the analyzer).
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _candidate in (
    _HERE,                                             # standalone folder
    _PARENT,                                           # repo layout: tools/ beside the analyzer
    os.path.join(_PARENT, "CQUSNDeepAnalyzer"),        # CQTools layout: sibling tool folder
):
    if os.path.isfile(os.path.join(_candidate, "CQUSNDeepAnalyzer.py")):
        if _candidate not in sys.path:
            sys.path.insert(0, _candidate)
        break

try:
    import CQUSNDeepAnalyzer as cq  # noqa: E402
except ImportError:
    sys.stderr.write(
        "CQUSNCorrelate needs CQUSNDeepAnalyzer.py, which supplies the $J and $MFT\n"
        "parsers. Put it beside this script, or run this script from the tools/\n"
        "directory of the CQUSNDeepAnalyzer repository.\n")
    raise SystemExit(2)


def _use_utf8_streams():
    """Force UTF-8 on stdout and stderr where the runtime allows it.

    NTFS filenames are UTF-16 and can hold anything, so a report that prints
    them must not depend on the console codepage. Without this, a cp1252 console
    turns non-ASCII evidence names into '?' or aborts the run outright.
    """
    for stream in ("stdout", "stderr"):
        handle = getattr(sys, stream, None)
        reconfigure = getattr(handle, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_use_utf8_streams()


__tool__ = "CQUSNCorrelate"
__version__ = "1.0"
__author__ = "Paula Januszkiewicz | CQURE"
__license__ = "Apache License 2.0"


# ---------------------------------------------------------------- colour

# CQURE brand tones mapped to the nearest 256 colour terminal slots.
# Orange #EB5B27 is the major colour, pink #FF005C the gradient partner.
_TONE = {
    "accent": "38;5;202",   # brand orange
    "pink":   "38;5;198",   # brand pink, used for the worst findings
    "ok":     "38;5;78",    # granted / benign
    "warn":   "38;5;179",   # amber
    "dim":    "38;5;245",
    "faint":  "38;5;240",
    "text":   "0",
}
_STYLE = {"bold": "1", "under": "4"}

_COLOR_ON = False


def _enable_windows_vt():
    """Turn on virtual terminal processing so ANSI works in cmd.exe and PowerShell."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        ok = False
        for handle_id in (-11, -12):          # stdout, stderr
            h = k.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                ok = True
        return ok
    except Exception:
        return False


def init_color(mode="auto"):
    """Decide whether to emit ANSI. Honours NO_COLOR and a non tty stdout."""
    global _COLOR_ON
    if mode == "never" or os.environ.get("NO_COLOR"):
        _COLOR_ON = False
    elif mode == "always":
        _COLOR_ON = True
        _enable_windows_vt()
    else:
        _COLOR_ON = bool(getattr(sys.stdout, "isatty", lambda: False)()) and _enable_windows_vt()
    return _COLOR_ON


def paint(text, tone=None, *styles):
    """Wrap text in a tone and optional styles, or return it untouched."""
    if not _COLOR_ON or (tone is None and not styles):
        return str(text)
    parts = [_STYLE[x] for x in styles if x in _STYLE]
    if tone in _TONE:
        parts.append(_TONE[tone])
    if not parts:
        return str(text)
    return "\033[" + ";".join(parts) + "m" + str(text) + "\033[0m"

# ---------------------------------------------------------------- shared load

def load_usn(args: argparse.Namespace) -> List["cq.USNRecord"]:
    """Parse $J (and optionally $MFT) exactly the way the main tool does."""
    with open(args.input, "rb") as fh:
        records = list(cq.parse_usn_records(fh, getattr(args, "max_records", None)))

    mft_path_map: Optional[Dict[str, str]] = None
    if getattr(args, "mft", None):
        with open(args.mft, "rb") as fh:
            mft_records = list(cq.parse_mft_records(fh))
        mft_path_map = cq.build_mft_path_map(mft_records)
        if not args.quiet:
            print("[*] $MFT: {:,} records, {:,} paths".format(
                len(mft_records), len(mft_path_map)), file=sys.stderr)

    cq.reconstruct_paths(records, mft_path_map)

    if getattr(args, "include_path", None) or getattr(args, "exclude_path", None):
        before = len(records)
        records = cq.filter_records(records, args.include_path, args.exclude_path)
        if not args.quiet:
            print("[*] path filter: {:,} -> {:,}".format(before, len(records)), file=sys.stderr)

    if getattr(args, "skip_directories", False):
        before = len(records)
        records = [r for r in records if "DIRECTORY" not in r.file_attribute_names]
        if not args.quiet:
            print("[*] dropped directory records: {:,} -> {:,}".format(
                before, len(records)), file=sys.stderr)

    if not args.quiet:
        print(paint("[*] $J: {:,} USN records".format(len(records)), "dim"), file=sys.stderr)
    return records


def _ts(rec_ts: str) -> Optional[dt.datetime]:
    return cq.parse_iso(rec_ts) if rec_ts else None


def _delta_seconds(a: str, b: str) -> Optional[float]:
    """Seconds from a to b, or None if either timestamp will not parse."""
    da, db = _ts(a), _ts(b)
    if not da or not db:
        return None
    return (db - da).total_seconds()


def _human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "?"
    neg = seconds < 0
    s = abs(seconds)
    if s < 60:
        out = "{:.1f}s".format(s)
    elif s < 3600:
        out = "{:.1f}m".format(s / 60)
    elif s < 86400:
        out = "{:.1f}h".format(s / 3600)
    else:
        out = "{:.1f}d".format(s / 86400)
    return ("-" + out) if neg else out


def _ext(name: str) -> str:
    base = name.rsplit("\\", 1)[-1]
    return ("." + base.rsplit(".", 1)[-1].lower()) if "." in base else ""


# ---------------------------------------------------------------- output

def _cells(text: str) -> int:
    """Display width of text in terminal cells.

    CJK and other East Asian glyphs occupy two cells but one code point, so
    len() under counts them and the columns drift. NTFS filenames are UTF-16 and
    routinely carry such characters, so the table has to measure what the
    terminal will actually draw. Combining marks take no cell at all.
    """
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _fit(text: str, cells: int) -> str:
    """Truncate to `cells` display cells, then pad to exactly that width."""
    if _cells(text) > cells:
        out = ""
        used = 0
        for ch in text:
            w = 0 if unicodedata.combining(ch) else (
                2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
            if used + w > cells - 3:
                break
            out += ch
            used += w
        text = out + "..."
    return text + " " * max(0, cells - _cells(text))

def render_table(rows: List[Dict[str, object]], columns: Sequence[Tuple[str, str]],
                 limit: int = 0, tones=None) -> str:
    """Render rows as a fixed-width table. `columns` is [(key, header), ...].

    `tones` optionally maps a column key to a function(value, row) -> tone name.
    Colour is applied AFTER padding, because ANSI escapes would otherwise be
    counted as visible width and wreck the column alignment.
    """
    tones = tones or {}
    if not rows:
        return "  (no matches)"
    shown = rows[:limit] if limit else rows
    widths = []
    for key, header in columns:
        w = _cells(header)
        for r in shown:
            w = max(w, _cells(str(r.get(key, ""))))
        widths.append(min(w, 64))

    out = []
    out.append("  " + "  ".join(paint(_fit(h.upper(), w), "dim", "bold")
                                for (_, h), w in zip(columns, widths)))
    out.append("  " + paint("  ".join("-" * w for w in widths), "faint"))
    for r in shown:
        cells = []
        for (key, _), w in zip(columns, widths):
            v = str(r.get(key, ""))
            padded = _fit(v, w)
            picker = tones.get(key)
            tone = picker(v, r) if picker else None
            cells.append(paint(padded, tone) if tone else padded)
        out.append("  " + "  ".join(cells))
    if limit and len(rows) > limit:
        out.append("  " + paint("... {:,} more (raise --limit, or use --csv)".format(
            len(rows) - limit), "faint"))
    return "\n".join(out)


def write_outputs(rows: List[Dict[str, object]], columns: Sequence[Tuple[str, str]],
                  args: argparse.Namespace) -> None:
    """Write the FULL row set to CSV/JSON.

    The console table shows a readable subset, but the files carry every field,
    including the precise numerics (delta_s, lifetime_s) and the raw reason
    list, which is what you want when pivoting in Excel or Timesketch.
    """
    fieldnames = [k for k, _ in columns]
    for r in rows:
        for k in r:
            if k not in fieldnames:
                fieldnames.append(k)

    if getattr(args, "csv", None):
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print("[+] CSV  -> {}  ({:,} rows)".format(args.csv, len(rows)), file=sys.stderr)
    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, default=str)
        print("[+] JSON -> {}  ({:,} rows)".format(args.json, len(rows)), file=sys.stderr)


def credit() -> None:
    """One line of provenance at the head of a run.

    Printed once per invocation. Analysts paste this output into case notes and
    tickets, so the tool and its author should travel with the findings rather
    than living only in the source header.
    """
    print()
    print("  " + paint(__tool__, "accent", "bold") +
          paint(" v" + __version__, "dim") +
          paint("  -  ", "faint") + paint(__author__, "text") +
          paint("  -  ", "faint") + paint(__license__, "dim"))


def _banner(title: str, subtitle: str = "") -> None:
    print()
    print(paint("=" * 78, "accent"))
    print(" " + paint(title, "accent", "bold"))
    if subtitle:
        print(" " + paint(subtitle, "dim"))
    print(paint("=" * 78, "accent"))


def _sec(row):
    """Numeric delta or lifetime from a row, or None when it is not available."""
    for key in ("delta_s", "lifetime_s"):
        v = row.get(key)
        if isinstance(v, (int, float)):
            return float(v)
    return None

# =============================================================================
# 1. exec-evidence : EXE created AND Prefetch created
# =============================================================================

def cmd_exec_evidence(args: argparse.Namespace) -> int:
    """Pair .exe creations with .pf creations, i.e. dropped AND executed.

    A Prefetch file proves the executable actually ran. Pairing it with the
    creation of the binary itself gives the strongest sequence available without
    EVTX: the binary appeared on disk, then it was run.

    CAVEAT, also printed in the output: the Prefetch filename hash encodes the
    executable's full path, but we do not recompute it. Matching is therefore by
    executable NAME. Two same-named binaries in different directories cannot be
    told apart here, so read a pair as "a binary by this name ran", not "this
    exact file on this exact path ran".
    """
    records = load_usn(args)

    exe_creates: Dict[str, List["cq.USNRecord"]] = {}
    pf_creates: Dict[str, List["cq.USNRecord"]] = {}

    for r in records:
        if "FILE_CREATE" not in r.reason_names:
            continue
        name = r.filename or ""
        low = name.lower()
        if low.endswith(".exe"):
            exe_creates.setdefault(name.upper(), []).append(r)
        elif low.endswith(".pf"):
            exe = cq._prefetch_exe_from_filename(name).upper()
            if exe:
                pf_creates.setdefault(exe, []).append(r)

    for bucket in (exe_creates, pf_creates):
        for lst in bucket.values():
            lst.sort(key=lambda x: x.timestamp_utc)

    rows: List[Dict[str, object]] = []
    for exe, creates in exe_creates.items():
        pfs = pf_creates.get(exe)
        if not pfs:
            continue
        for c in creates:
            after = [p for p in pfs if p.timestamp_utc >= c.timestamp_utc]
            pf = after[0] if after else pfs[0]
            delta = _delta_seconds(c.timestamp_utc, pf.timestamp_utc)
            if args.max_delta and delta is not None and abs(delta) > args.max_delta:
                continue
            rows.append({
                "exe": exe,
                "created_utc": c.timestamp_utc,
                "prefetch_utc": pf.timestamp_utc,
                "delta": _human_duration(delta),
                "delta_s": round(delta, 3) if delta is not None else "",
                "order": "create->run" if (delta is not None and delta >= 0) else "ran BEFORE create",
                "created_path": c.reconstructed_path or c.filename,
                "prefetch_name": pf.filename,
                "frn": c.file_reference_number,
                "usn": c.usn,
            })

    rows.sort(key=lambda r: str(r["created_utc"]))

    _banner("EXEC EVIDENCE, binary created AND prefetch created",
            "a .pf file proves the binary ran; pairing with the create shows drop-then-run")
    print("  .exe created : " + paint("{:,}".format(
        sum(len(v) for v in exe_creates.values())), "text", "bold") +
        paint("  ({:,} distinct names)".format(len(exe_creates)), "dim"))
    print("  .pf  created : " + paint("{:,}".format(
        sum(len(v) for v in pf_creates.values())), "text", "bold") +
        paint("  ({:,} distinct executables)".format(len(pf_creates)), "dim"))
    print("  paired       : " + paint("{:,}".format(len(rows)),
                                  "accent" if rows else "dim", "bold"))
    print()
    print(paint("  NOTE: matched by executable NAME. The Prefetch hash encodes the binary's", "dim"))
    print(paint("        path but is not recomputed here, so same-named binaries in different", "dim"))
    print(paint("        directories are indistinguishable.", "dim"))
    print()

    columns = [("exe", "executable"), ("created_utc", "created (utc)"),
               ("prefetch_utc", "prefetch (utc)"), ("delta", "delta"),
               ("order", "order"), ("created_path", "path")]
    tones = {
        "exe":          lambda v, r: "accent",
        "created_utc":  lambda v, r: "dim",
        "prefetch_utc": lambda v, r: "dim",
        # a tight create -> run gap is the strongest signal, so grade it
        "delta":        lambda v, r: ("pink" if _sec(r) is not None and _sec(r) < 0
                                      else "ok" if _sec(r) is not None and _sec(r) <= 60
                                      else "warn"),
        "order":        lambda v, r: "pink" if "BEFORE" in v else "ok",
        "created_path": lambda v, r: "dim",
    }
    print(render_table(rows, columns, args.limit, tones))

    if args.unpaired:
        dropped = sorted(k for k in exe_creates if k not in pf_creates)
        ran_only = sorted(k for k in pf_creates if k not in exe_creates)
        cap = args.limit or 40
        print()
        print(paint("  -- created but NO prefetch ({:,}): dropped, no execution seen".format(
            len(dropped)), "warn", "bold"))
        for name in dropped[:cap]:
            r0 = exe_creates[name][0]
            print("     " + paint(r0.timestamp_utc, "dim") + "  " +
                  paint("{:<34}".format(name), "warn") + " " +
                  paint(r0.reconstructed_path or r0.filename, "dim"))
        print()
        print(paint("  -- prefetch but NO create ({:,}): ran, binary predates this journal".format(
            len(ran_only)), "dim", "bold"))
        for name in ran_only[:cap]:
            r0 = pf_creates[name][0]
            print("     " + paint(r0.timestamp_utc, "faint") + "  " + paint(name, "dim"))

    write_outputs(rows, columns, args)
    return 0


# =============================================================================
# 2. lifecycle : created, then deleted
# =============================================================================

def cmd_lifecycle(args: argparse.Namespace) -> int:
    """Files that were created and later deleted, with how long they survived.

    Grouped by FRN, which the project formats as `entry-seq`. Because the
    sequence number increments when NTFS reuses an MFT entry, that key does not
    collide across two different files that occupied the same entry.
    """
    records = load_usn(args)

    agg: Dict[str, Dict[str, object]] = {}
    for r in records:
        e = agg.get(r.file_reference_number)
        if e is None:
            e = {"name": "", "path": "", "create": None, "delete": None,
                 "reasons": set(), "events": 0}
            agg[r.file_reference_number] = e
        e["events"] = int(e["events"]) + 1
        if r.filename:
            e["name"] = r.filename
        if r.reconstructed_path:
            e["path"] = r.reconstructed_path
        e["reasons"].update(r.reason_names)
        ts = r.timestamp_utc
        if "FILE_CREATE" in r.reason_names:
            if e["create"] is None or ts < str(e["create"]):
                e["create"] = ts
        if "FILE_DELETE" in r.reason_names:
            if e["delete"] is None or ts > str(e["delete"]):
                e["delete"] = ts

    rows: List[Dict[str, object]] = []
    for frn, e in agg.items():
        if not e["create"] or not e["delete"]:
            continue
        if str(e["delete"]) < str(e["create"]):
            # deleted before created inside this journal window: not a full lifecycle
            continue
        life = _delta_seconds(str(e["create"]), str(e["delete"]))
        if life is None:
            continue
        if args.min_lifetime is not None and life < args.min_lifetime:
            continue
        if args.max_lifetime is not None and life > args.max_lifetime:
            continue
        name = str(e["name"])
        if args.ext and _ext(name) not in args.ext:
            continue
        rows.append({
            "created_utc": e["create"],
            "deleted_utc": e["delete"],
            "lifetime": _human_duration(life),
            "lifetime_s": round(life, 3),
            "filename": name,
            "ext": _ext(name),
            "path": str(e["path"]) or name,
            "frn": frn,
            "events": e["events"],
            "reasons": ",".join(sorted(e["reasons"])),
        })

    if args.sort in ("shortest", "longest"):
        rows.sort(key=lambda r: float(r["lifetime_s"]), reverse=(args.sort == "longest"))
    else:
        rows.sort(key=lambda r: str(r["created_utc"]))

    _banner("LIFECYCLE, files created and then deleted",
            "short lifetimes are the interesting ones: staging, drop-and-clean, temp payloads")
    print("  distinct FRNs in journal : " + paint("{:,}".format(len(agg)), "dim"))
    print("  created AND deleted      : " + paint("{:,}".format(len(rows)), "text", "bold"))
    if rows:
        quick = sum(1 for r in rows if float(r["lifetime_s"]) <= 60)
        print("  of those, lived <= 60s   : " +
              paint("{:,}".format(quick), "pink" if quick else "dim", "bold"))
    print()

    columns = [("created_utc", "created (utc)"), ("deleted_utc", "deleted (utc)"),
               ("lifetime", "lifetime"), ("filename", "filename"),
               ("path", "path"), ("frn", "frn"), ("events", "usn")]
    # Lifetime is the whole point of this view, so it carries the colour scale:
    # seconds is suspicious, minutes worth a look, hours is ordinary housekeeping.
    tones = {
        "created_utc": lambda v, r: "dim",
        "deleted_utc": lambda v, r: "dim",
        "lifetime":    lambda v, r: ("pink" if _sec(r) is not None and _sec(r) <= 60
                                     else "accent" if _sec(r) is not None and _sec(r) <= 600
                                     else "warn" if _sec(r) is not None and _sec(r) <= 3600
                                     else "dim"),
        "filename":    lambda v, r: "text",
        "path":        lambda v, r: "dim",
        "frn":         lambda v, r: "faint",
        "events":      lambda v, r: "faint",
    }
    print(render_table(rows, columns, args.limit, tones))
    write_outputs(rows, columns, args)
    return 0


# =============================================================================
# 3. sessions : file creation vs. open logon sessions
# =============================================================================

_RE_LOGON_ID = re.compile(r'(?:Target)?LogonId["\']?\s*[:=]\s*["\']?(0x[0-9a-fA-F]+|\d+)', re.I)
_RE_LOGON_TYPE = re.compile(r'LogonType["\']?\s*[:=]\s*["\']?(\d+)', re.I)
_RE_TARGET_USER = re.compile(r'TargetUserName["\']?\s*[:=]\s*["\']?([^"\',}\s]+)', re.I)
_RE_TARGET_DOMAIN = re.compile(r'TargetDomainName["\']?\s*[:=]\s*["\']?([^"\',}\s]+)', re.I)
_RE_IP = re.compile(r'IpAddress["\']?\s*[:=]\s*["\']?([0-9a-fA-F.:]+)', re.I)

# Logon types worth naming in output. 2/10/11 are interactive-ish, 3 is network.
_LOGON_TYPE_NAME = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive",
}

_LOGON_EVENTS = {4624}
_LOGOFF_EVENTS = {4634, 4647}


class Session:
    __slots__ = ("key", "user", "logon_type", "start", "end", "source_ip",
                 "synthetic", "files")

    def __init__(self, key: str, user: str, logon_type: str,
                 start: dt.datetime, source_ip: str = "", synthetic: bool = False):
        self.key = key
        self.user = user
        self.logon_type = logon_type
        self.start = start
        self.end: Optional[dt.datetime] = None
        self.source_ip = source_ip
        self.synthetic = synthetic
        self.files: List["cq.USNRecord"] = []

    def covers(self, when: dt.datetime) -> bool:
        if when < self.start:
            return False
        return True if self.end is None else when <= self.end

    def label(self) -> str:
        return "{} [{}]".format(self.user or "?", self.key)


def _field(payload: str, rx: re.Pattern, default: str = "") -> str:
    m = rx.search(payload or "")
    return m.group(1) if m else default


def build_sessions(evtx: List["cq.EvtxRecord"]) -> Tuple[List[Session], str]:
    """Reconstruct logon sessions from 4624 paired with 4634/4647.

    Returns (sessions, mode). Mode is "logon-id" when TargetLogonId was present
    in the payloads, otherwise "username" for the degraded fallback, where each
    4624 is paired with the next logoff for the same user. The mode is reported
    so nobody mistakes the fallback for real session-ID correlation.
    """
    have_ids = any(_RE_LOGON_ID.search(e.payload or "") for e in evtx
                   if e.event_id in _LOGON_EVENTS | _LOGOFF_EVENTS)
    mode = "logon-id" if have_ids else "username"

    sessions: List[Session] = []
    open_by_key: Dict[str, Session] = {}

    for e in sorted(evtx, key=lambda x: x.timestamp):
        if e.event_id not in _LOGON_EVENTS and e.event_id not in _LOGOFF_EVENTS:
            continue
        payload = e.payload or ""
        user = _field(payload, _RE_TARGET_USER) or e.username or ""
        domain = _field(payload, _RE_TARGET_DOMAIN)
        if domain and user and "\\" not in user:
            user = domain + "\\" + user

        if mode == "logon-id":
            key = _field(payload, _RE_LOGON_ID)
            if not key:
                continue
        else:
            key = (user or "?").upper()

        if e.event_id in _LOGON_EVENTS:
            lt_raw = _field(payload, _RE_LOGON_TYPE)
            lt = ""
            if lt_raw.isdigit():
                lt = _LOGON_TYPE_NAME.get(int(lt_raw), "Type" + lt_raw)
            s = Session(key=key, user=user, logon_type=lt, start=e.timestamp,
                        source_ip=_field(payload, _RE_IP),
                        synthetic=(mode == "username"))
            # a second logon on the same key closes the previous one
            prev = open_by_key.get(key)
            if prev is not None and prev.end is None:
                prev.end = e.timestamp
            sessions.append(s)
            open_by_key[key] = s
        else:
            s = open_by_key.get(key)
            if s is not None and s.end is None:
                s.end = e.timestamp
                open_by_key.pop(key, None)

    return sessions, mode


def cmd_sessions(args: argparse.Namespace) -> int:
    """Attribute file creations to the logon sessions that were open at the time."""
    evtx = cq.load_evtx_csv(args.evtx)
    sessions, mode = build_sessions(evtx)
    records = load_usn(args)

    creates = [r for r in records if "FILE_CREATE" in r.reason_names]
    if args.ext:
        creates = [r for r in creates if _ext(r.filename or "") in args.ext]

    per_file: List[Dict[str, object]] = []
    unattributed = 0
    for r in creates:
        when = _ts(r.timestamp_utc)
        if not when:
            continue
        hits = [s for s in sessions if s.covers(when)]
        if not hits:
            unattributed += 1
        for s in hits:
            s.files.append(r)
        per_file.append({
            "created_utc": r.timestamp_utc,
            "filename": r.filename,
            "path": r.reconstructed_path or r.filename,
            "ext": _ext(r.filename or ""),
            "sessions": "; ".join(s.label() for s in hits) if hits else "(none open)",
            "session_count": len(hits),
            "frn": r.file_reference_number,
        })

    summary: List[Dict[str, object]] = []
    for s in sessions:
        files = s.files
        if args.only_active and not files:
            continue
        sample = ", ".join(sorted({(f.filename or "") for f in files})[:4])
        summary.append({
            "logon_id": s.key,
            "user": s.user or "?",
            "logon_type": s.logon_type or "?",
            "start_utc": s.start.isoformat(),
            "end_utc": s.end.isoformat() if s.end else "(still open)",
            "duration": _human_duration((s.end - s.start).total_seconds()) if s.end else "open",
            "files_created": len(files),
            "source_ip": s.source_ip,
            "sample_files": sample,
        })
    summary.sort(key=lambda r: int(r["files_created"]), reverse=True)

    _banner("SESSIONS, file creations vs. open logon sessions",
            "which account was logged on while these files appeared")
    print("  EVTX records loaded : " + paint("{:,}".format(len(evtx)), "dim"))
    print("  logon sessions      : " + paint("{:,}".format(len(sessions)), "text", "bold"))
    print("  file creations      : " + paint("{:,}".format(len(creates)), "text", "bold"))
    print("  not inside any session : " +
          paint("{:,}".format(unattributed), "warn" if unattributed else "dim", "bold"))
    open_ended = [s for s in sessions if s.end is None]
    if open_ended:
        print()
        print(paint("  WARNING: {:,} session(s) have no logoff event in this EVTX, so they are".format(
            len(open_ended)), "warn", "bold"))
        print(paint("  treated as open forever and will match EVERY later file creation.", "warn"))
        print(paint("  Over-attribution is likely past the end of the log. Sessions affected:", "warn"))
        for s in open_ended[:8]:
            print("    " + paint(s.key, "accent") + "  " + paint(s.user or "?", "text") +
                  paint("  opened " + s.start.isoformat(), "dim"))
    print()
    if mode == "logon-id":
        print("  correlation mode: " + paint("LOGON-ID", "ok", "bold") +
              paint("  (4624/4634/4647 paired on TargetLogonId)", "dim"))
    else:
        print("  correlation mode: " + paint("USERNAME FALLBACK", "warn", "bold"))
        print(paint("  No TargetLogonId was present in the EVTX payloads, so sessions are", "dim"))
        print(paint("  approximated by pairing each 4624 with the next logoff for the same", "dim"))
        print(paint("  user. Concurrent sessions for one user cannot be separated this way.", "dim"))
    print()

    cols_summary = [("logon_id", "logon id"), ("user", "user"), ("logon_type", "type"),
                    ("start_utc", "logon (utc)"), ("end_utc", "logoff (utc)"),
                    ("duration", "duration"), ("files_created", "files"),
                    ("sample_files", "sample")]
    tones_summary = {
        "logon_id":   lambda v, r: "accent",
        "user":       lambda v, r: "text",
        # remote interactive is the logon type that matters most in an intrusion
        "logon_type": lambda v, r: "pink" if "Remote" in v else "dim",
        "start_utc":  lambda v, r: "dim",
        "end_utc":    lambda v, r: "warn" if "still open" in v else "dim",
        "duration":   lambda v, r: "warn" if v == "open" else "dim",
        "files_created": lambda v, r: "accent" if str(v) not in ("", "0") else "faint",
        "sample_files":  lambda v, r: "dim",
    }
    print(render_table(summary, cols_summary, args.limit, tones_summary))

    if args.per_file:
        print()
        print("  -- per created file --")
        cols_file = [("created_utc", "created (utc)"), ("filename", "filename"),
                     ("sessions", "sessions open"), ("path", "path")]
        tones_file = {
            "created_utc": lambda v, r: "dim",
            "filename":    lambda v, r: "text",
            # a file nobody was logged on for is an attribution gap, flag it
            "sessions":    lambda v, r: "warn" if "none open" in v else "accent",
            "path":        lambda v, r: "dim",
        }
        print(render_table(per_file, cols_file, args.limit, tones_file))
        write_outputs(per_file, cols_file, args)
    else:
        write_outputs(summary, cols_summary, args)
    return 0


# =============================================================================
# 4. metadata-changed : attributes or timestamps touched, content maybe not
# =============================================================================

# USN reasons that describe METADATA rather than content. BASIC_INFO_CHANGE is
# the one a timestomp raises: SetFileTime writes new $SI timestamps and NTFS
# records exactly this, with no data reason alongside it.
_META_REASONS = {
    "BASIC_INFO_CHANGE":     "timestamps or attributes",
    "SECURITY_CHANGE":       "ACL or owner",
    "EA_CHANGE":             "extended attributes",
    "OBJECT_ID_CHANGE":      "object id",
    "REPARSE_POINT_CHANGE":  "reparse point",
    "COMPRESSION_CHANGE":    "compression",
    "ENCRYPTION_CHANGE":     "encryption",
    "INDEXABLE_CHANGE":      "indexing",
    "HARD_LINK_CHANGE":      "hard links",
}
_DATA_REASONS = {"DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION",
                 "NAMED_DATA_OVERWRITE", "NAMED_DATA_EXTEND", "NAMED_DATA_TRUNCATION"}


def cmd_metadata_changed(args: argparse.Namespace) -> int:
    """Files whose metadata changed, and whether the content changed with it.

    The interesting column is CONTENT. Metadata changing on its own means
    somebody altered timestamps, attributes or an ACL without writing a byte of
    the file. That is the shape a timestomp leaves in the journal. Metadata
    changing alongside a write is ordinary: an editor saving a file touches both.
    """
    records = load_usn(args)

    wanted = set(args.kind) if args.kind else set(_META_REASONS)

    # Two passes. First record when each file's CONTENT was written, then judge
    # every metadata event against that. Creating a file writes it, so "was this
    # ever written" answers yes for everything and tells you nothing.
    writes: Dict[str, List[dt.datetime]] = {}
    for r in records:
        if _DATA_REASONS.intersection(r.reason_names):
            when = _ts(r.timestamp_utc)
            if when:
                writes.setdefault(r.file_reference_number, []).append(when)

    agg: Dict[str, Dict[str, object]] = {}
    for r in records:
        hits = wanted.intersection(r.reason_names)
        if not hits:
            continue
        e = agg.get(r.file_reference_number)
        if e is None:
            e = {"name": "", "path": "", "first": None, "last": None,
                 "reasons": set(), "meta_events": 0, "standalone": 0, "nearest": None}
            agg[r.file_reference_number] = e
        if r.filename:
            e["name"] = r.filename
        if r.reconstructed_path:
            e["path"] = r.reconstructed_path

        e["meta_events"] = int(e["meta_events"]) + 1
        e["reasons"].update(hits)

        when = _ts(r.timestamp_utc)
        gap = None
        if when:
            for w in writes.get(r.file_reference_number, ()):
                d = abs((w - when).total_seconds())
                if gap is None or d < gap:
                    gap = d
        # a metadata flag riding in the same USN record as a write is never isolated
        if _DATA_REASONS.intersection(r.reason_names):
            gap = 0.0
        if gap is None or gap > args.window:
            e["standalone"] = int(e["standalone"]) + 1
        if gap is not None and (e["nearest"] is None or gap < float(e["nearest"])):
            e["nearest"] = gap

        ts = r.timestamp_utc
        if e["first"] is None or ts < str(e["first"]):
            e["first"] = ts
        if e["last"] is None or ts > str(e["last"]):
            e["last"] = ts

    rows: List[Dict[str, object]] = []
    for frn, e in agg.items():
        if not e["meta_events"]:
            continue
        name = str(e["name"])
        if args.ext and _ext(name) not in args.ext:
            continue
        isolated = int(e["standalone"]) > 0
        if args.no_data_change and not isolated:
            continue
        nearest = e["nearest"]
        rows.append({
            "first_utc": e["first"],
            "last_utc": e["last"],
            "content": "NO WRITE" if isolated else "with write",
            "nearest_write": ("never" if nearest is None else _human_duration(float(nearest))),
            "nearest_write_s": ("" if nearest is None else round(float(nearest), 3)),
            "standalone": e["standalone"],
            "changes": ", ".join(_META_REASONS.get(x, x) for x in sorted(e["reasons"])),
            "filename": name,
            "ext": _ext(name),
            "path": str(e["path"]) or name,
            "frn": frn,
            "meta_events": e["meta_events"],
            "reasons": ",".join(sorted(e["reasons"])),
        })

    rows.sort(key=lambda r: (r["content"] != "NO WRITE", str(r["first_utc"])))

    silent = sum(1 for r in rows if r["content"] == "NO WRITE")
    _banner("METADATA CHANGED, attributes or timestamps touched",
            "metadata changing with no write is the shape a timestomp leaves")
    print("  files with metadata changes : " + paint("{:,}".format(len(rows)), "text", "bold"))
    print("  metadata changed in isolation: " +
          paint("{:,}".format(silent), "pink" if silent else "dim", "bold"))
    print()
    print(paint("  NO WRITE means the content was not written within {:g}s of the metadata".format(
        args.window), "dim"))
    print(paint("  change, so somebody altered timestamps, attributes or an ACL without", "dim"))
    print(paint("  touching the file. Confirm against $MFT with the si-vs-fn subcommand.", "dim"))
    print()

    columns = [("first_utc", "first (utc)"), ("last_utc", "last (utc)"),
               ("content", "content"), ("nearest_write", "nearest write"),
               ("changes", "what changed"), ("filename", "filename"), ("path", "path")]
    tones = {
        "first_utc": lambda v, r: "dim",
        "last_utc":  lambda v, r: "dim",
        "content":   lambda v, r: "pink" if v == "NO WRITE" else "ok",
        "nearest_write": lambda v, r: "pink" if r.get("content") == "NO WRITE" else "dim",
        "changes":   lambda v, r: "warn" if "timestamps" in v else "dim",
        "filename":  lambda v, r: "text",
        "path":      lambda v, r: "dim",
    }
    print(render_table(rows, columns, args.limit, tones))
    write_outputs(rows, columns, args)
    return 0


# =============================================================================
# 5. si-vs-fn : $STANDARD_INFORMATION (0x10) against $FILE_NAME (0x30)
# =============================================================================

def _ft_delta_seconds(a: int, b: int) -> Optional[float]:
    """Seconds between two Windows FILETIME values, or None if either is unset."""
    if not a or not b:
        return None
    return (a - b) / 10_000_000.0


def cmd_si_vs_fn(args: argparse.Namespace) -> int:
    """Compare $SI (0x10) timestamps against $FN (0x30) for every MFT record.

    Windows updates $STANDARD_INFORMATION freely, but $FILE_NAME timestamps are
    only rewritten when the file is created, renamed, moved or hard linked. Tools
    that backdate a file almost always write $SI and leave $FN alone, so $SI
    earlier than $FN is a state NTFS does not reach on its own.

    Reads the $MFT directly, so it needs --mft rather than --input.
    """
    with open(args.mft, "rb") as fh:
        mft_records = list(cq.parse_mft_records(fh))
    path_map = cq.build_mft_path_map(mft_records)
    if not args.quiet:
        print(paint("[*] $MFT: {:,} records, {:,} paths".format(
            len(mft_records), len(path_map)), "dim"), file=sys.stderr)

    patterns: List[str] = []
    if not args.no_baseline:
        patterns = cq._load_baseline_patterns(args.baseline, include_defaults=True)

    rows: List[Dict[str, object]] = []
    skipped_internal = 0
    skipped_baseline = 0

    for rec in mft_records:
        if cq._is_ntfs_internal(rec):
            skipped_internal += 1
            continue
        if patterns and cq._baseline_matches(rec, path_map, patterns):
            skipped_baseline += 1
            continue

        d_created = _ft_delta_seconds(rec.si_created, rec.fn_created)
        d_modified = _ft_delta_seconds(rec.si_modified, rec.fn_modified)

        flags = []
        if rec.si_lt_fn:
            flags.append("SI<FN")
        if rec.usec_zeros:
            flags.append("usec-zero")

        if args.only == "si-lt-fn" and "SI<FN" not in flags:
            continue
        if args.only == "usec-zeros" and "usec-zero" not in flags:
            continue
        if args.only == "both" and len(flags) < 2:
            continue
        if args.only == "any" and not flags:
            continue
        if args.min_delta is not None:
            if d_created is None or abs(d_created) < args.min_delta:
                continue

        rows.append({
            "si_created": cq.filetime_to_iso(rec.si_created),
            "fn_created": cq.filetime_to_iso(rec.fn_created),
            "delta": _human_duration(d_created),
            "delta_s": round(d_created, 3) if d_created is not None else "",
            "flags": " ".join(flags) or "-",
            "filename": rec.filename,
            "path": cq._mft_full_path(rec, path_map),
            "frn": rec.frn,
            "si_modified": cq.filetime_to_iso(rec.si_modified),
            "fn_modified": cq.filetime_to_iso(rec.fn_modified),
            "delta_modified_s": round(d_modified, 3) if d_modified is not None else "",
            "is_directory": rec.is_directory,
        })

    # most negative delta first: the further $SI is backdated behind $FN, the louder
    rows.sort(key=lambda r: (r["delta_s"] if isinstance(r["delta_s"], float) else 0.0))

    si_lt = sum(1 for r in rows if "SI<FN" in str(r["flags"]))
    usec = sum(1 for r in rows if "usec-zero" in str(r["flags"]))

    _banner("SI vs FN, $STANDARD_INFORMATION (0x10) against $FILE_NAME (0x30)",
            "$FN is only rewritten on create, rename, move or hard link; $SI is not")
    print("  MFT records parsed      : " + paint("{:,}".format(len(mft_records)), "dim"))
    print("  NTFS internals skipped  : " + paint("{:,}".format(skipped_internal), "dim"))
    if patterns:
        print("  baseline suppressed     : " + paint("{:,}".format(skipped_baseline), "dim") +
              paint("  ({} patterns)".format(len(patterns)), "faint"))
    print("  reported                : " + paint("{:,}".format(len(rows)), "text", "bold"))
    print("    SI earlier than FN    : " + paint("{:,}".format(si_lt), "pink" if si_lt else "dim", "bold"))
    print("    sub-second zeroed     : " + paint("{:,}".format(usec), "warn" if usec else "dim", "bold"))
    print()
    print(paint("  SI<FN means $SI.Created predates $FN.Created. NTFS does not produce", "dim"))
    print(paint("  that on its own, because $FN is stamped when the name is written.", "dim"))
    print(paint("  usec-zero means an $SI timestamp lands exactly on a whole second,", "dim"))
    print(paint("  which hand-set times do and real filesystem activity rarely does.", "dim"))
    if not patterns:
        print(paint("  Baseline filtering is OFF, expect Windows Update and WinSxS noise.", "warn"))
    print()

    columns = [("si_created", "$SI created"), ("fn_created", "$FN created"),
               ("delta", "delta"), ("flags", "flags"),
               ("filename", "filename"), ("path", "path")]
    tones = {
        "si_created": lambda v, r: "dim",
        "fn_created": lambda v, r: "dim",
        "delta":      lambda v, r: ("pink" if isinstance(r.get("delta_s"), float) and r["delta_s"] < 0
                                    else "warn" if isinstance(r.get("delta_s"), float) and abs(r["delta_s"]) > 1
                                    else "dim"),
        "flags":      lambda v, r: ("pink" if "SI<FN" in v
                                    else "warn" if "usec" in v else "faint"),
        "filename":   lambda v, r: "text",
        "path":       lambda v, r: "dim",
    }
    print(render_table(rows, columns, args.limit, tones))
    write_outputs(rows, columns, args)
    return 0


# =============================================================================
# CLI
# =============================================================================

def _add_common(p: argparse.ArgumentParser, need_evtx: bool = False) -> None:
    p.add_argument("--input", required=True, metavar="J.bin",
                   help="raw $UsnJrnl:$J stream")
    p.add_argument("--mft", metavar="MFT.raw",
                   help="raw $MFT, enables full path reconstruction")
    if need_evtx:
        p.add_argument("--evtx", required=True, metavar="CSV",
                       help="EvtxECmd CSV export (needs 4624 and 4634/4647)")
    p.add_argument("--max-records", type=int, metavar="N",
                   help="stop parsing $J after N records")
    p.add_argument("--include-path", metavar="SUBSTR", help="keep only paths containing SUBSTR")
    p.add_argument("--exclude-path", metavar="SUBSTR", help="drop paths containing SUBSTR")
    p.add_argument("--limit", type=int, default=50, metavar="N",
                   help="rows to print, 0 for all (default 50). Does not affect --csv")
    p.add_argument("--csv", metavar="FILE", help="write full result set to CSV")
    p.add_argument("--json", metavar="FILE", help="write full result set to JSON")
    p.add_argument("--skip-directories", action="store_true",
                   help="ignore records whose attributes say DIRECTORY")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="colourise output (default auto: on for a terminal, off when piped)")
    p.add_argument("--quiet", action="store_true", help="suppress parse progress on stderr")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=__tool__,
        description="Ready-to-launch NTFS correlations built on CQUSNDeepAnalyzer parsers.\n"
                    "{} v{},  {},  {}".format(__tool__, __version__, __author__, __license__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples")[-1] +
               "\n{} v{}\nAuthor:  {}\nLicense: {}\n".format(
                   __tool__, __version__, __author__, __license__),
    )
    ap.add_argument("--version", "-V", action="version",
                    version="{} v{}  -  {}  -  {}".format(
                        __tool__, __version__, __author__, __license__))
    sub = ap.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("exec-evidence", help="EXE created AND prefetch created")
    _add_common(p1)
    p1.add_argument("--max-delta", type=float, metavar="SECONDS",
                    help="only pairs where |create -> prefetch| is within SECONDS")
    p1.add_argument("--unpaired", action="store_true",
                    help="also list created-but-never-run and ran-but-not-created")
    p1.set_defaults(func=cmd_exec_evidence)

    p2 = sub.add_parser("lifecycle", help="file created and then deleted")
    _add_common(p2)
    p2.add_argument("--min-lifetime", type=float, metavar="SECONDS")
    p2.add_argument("--max-lifetime", type=float, metavar="SECONDS")
    p2.add_argument("--ext", nargs="*", metavar=".EXT",
                    help="restrict to these extensions, e.g. --ext .exe .dll .ps1")
    p2.add_argument("--sort", choices=["shortest", "longest", "created"],
                    default="shortest", help="row order (default shortest-lived first)")
    p2.set_defaults(func=cmd_lifecycle)

    p3 = sub.add_parser("sessions", help="file creations vs. open logon sessions")
    _add_common(p3, need_evtx=True)
    p3.add_argument("--per-file", action="store_true",
                    help="also print one row per created file with its open sessions")
    p3.add_argument("--only-active", action="store_true",
                    help="hide sessions that created no files")
    p3.add_argument("--ext", nargs="*", metavar=".EXT",
                    help="restrict creations to these extensions")
    p3.set_defaults(func=cmd_sessions)

    p4 = sub.add_parser("metadata-changed",
                        help="files whose metadata or timestamps changed")
    _add_common(p4)
    p4.add_argument("--kind", nargs="*", metavar="REASON",
                    choices=sorted(_META_REASONS),
                    help="restrict to these USN metadata reasons "
                         "(default: all of " + ", ".join(sorted(_META_REASONS)) + ")")
    p4.add_argument("--no-data-change", action="store_true",
                    help="only metadata changes with no nearby write, the timestomp shape")
    p4.add_argument("--window", type=float, default=60.0, metavar="SECONDS",
                    help="how close a content write must be to count as related (default 60)")
    p4.add_argument("--ext", nargs="*", metavar=".EXT",
                    help="restrict to these extensions")
    p4.set_defaults(func=cmd_metadata_changed)

    p5 = sub.add_parser("si-vs-fn",
                        help="$SI (0x10) timestamps against $FN (0x30), needs --mft")
    p5.add_argument("--mft", required=True, metavar="MFT.raw", help="raw $MFT")
    p5.add_argument("--only", choices=["any", "si-lt-fn", "usec-zeros", "both", "all"],
                    default="any",
                    help="which records to report (default any: at least one flag set)")
    p5.add_argument("--min-delta", type=float, metavar="SECONDS",
                    help="only where |$SI.Created - $FN.Created| is at least SECONDS")
    p5.add_argument("--baseline", metavar="FILE",
                    help="extra path patterns to suppress, one per line")
    p5.add_argument("--no-baseline", action="store_true",
                    help="disable the built-in Windows Update / WinSxS suppression")
    p5.add_argument("--limit", type=int, default=50, metavar="N",
                    help="rows to print, 0 for all (default 50)")
    p5.add_argument("--csv", metavar="FILE", help="write full result set to CSV")
    p5.add_argument("--json", metavar="FILE", help="write full result set to JSON")
    p5.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="colourise output")
    p5.add_argument("--quiet", action="store_true", help="suppress parse progress on stderr")
    p5.set_defaults(func=cmd_si_vs_fn)

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    init_color(getattr(args, "color", "auto"))
    credit()
    if getattr(args, "ext", None):
        args.ext = {e.lower() if e.startswith(".") else "." + e.lower() for e in args.ext}
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print("[!] {}".format(exc), file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
