#!/usr/bin/env python3
"""CQEVTXExtractor, a native Windows Event Log (.evtx) reader in pure Python.

Windows event logs are not XML on disk. A .evtx file is a 4 KiB header followed
by 64 KiB chunks, and each chunk holds records encoded in Binary XML: a token
stream with a per chunk template table, so the repeated skeleton of an event is
stored once and every record after it carries only the values that differ.
Reading the file therefore means implementing the format, not parsing text.

This tool does that with nothing but the standard library, which matters on an
evidence machine where installing packages is not an option, and on a live
response box where one more .NET dependency is one more thing to justify. It
reads the file, verifies the three CRC32 checksums the format carries,
reconstructs the XML, and writes what an analyst actually wants: a timeline, a
histogram, or a CSV the rest of the CQURE toolkit already consumes.

Author:  Paula Januszkiewicz | CQURE
License: Apache License 2.0
"""

import argparse
import binascii
import csv
import datetime as dt
import glob
import json
import os
import re
import struct
import sys
import unicodedata
from collections import Counter, OrderedDict


def _use_utf8_streams():
    """Force UTF-8 on stdout and stderr where the runtime allows it.

    Event logs carry usernames, computer names and command lines in UTF-16, so
    they can hold anything. Without this, a console still running cp1252 turns
    non-ASCII evidence into '?' or aborts the run outright.
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


__tool__ = "CQEVTXExtractor"
__version__ = "1.0"
__author__ = "Paula Januszkiewicz | CQURE"
__license__ = "Apache License 2.0"

_CREDIT = "{} v{}  -  {}  -  {}".format(__tool__, __version__, __author__, __license__)


# --------------------------------------------------------------------- colour

_TONE = {
    "accent": "38;5;202",   # brand orange
    "pink":   "38;5;198",   # brand pink, used for the worst findings
    "ok":     "38;5;78",    # healthy / verified
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


def credit():
    """Announce the tool on every run. stderr, so piped output stays clean."""
    print(paint(_CREDIT, "accent"), file=sys.stderr)


# ------------------------------------------------------------- display widths

def _cells(text):
    """Display width of text in terminal cells.

    CJK and other East Asian glyphs occupy two cells but one code point, so
    len() under counts them and the columns drift. Event log payloads are
    UTF-16 and routinely carry such characters, so the table has to measure
    what the terminal will actually draw. Combining marks take no cell at all.
    """
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _fit(text, cells):
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


def render_table(rows, columns, limit=50, tone_for=None, max_width=64):
    """Render rows as an aligned table. columns is a list of (key, header)."""
    if not rows:
        return [paint("  (nothing matched)", "dim")]
    shown = rows if not limit else rows[:limit]
    widths = []
    for key, header in columns:
        w = _cells(header)
        for r in shown:
            w = max(w, _cells(str(r.get(key, ""))))
        widths.append(min(w, max_width))

    out = ["  " + "  ".join(paint(_fit(h.upper(), w), "dim", "bold")
                            for (_, h), w in zip(columns, widths)),
           "  " + "  ".join(paint("-" * w, "faint") for w in widths)]
    for r in shown:
        cells = []
        for (key, _h), w in zip(columns, widths):
            padded = _fit(str(r.get(key, "")), w)
            tone = tone_for(r, key) if tone_for else None
            cells.append(paint(padded, tone) if tone else padded)
        out.append("  " + "  ".join(cells))
    if limit and len(rows) > len(shown):
        out.append(paint("  ... {:,} more, use --limit 0 for all".format(
            len(rows) - len(shown)), "dim"))
    return out


def heading(text):
    print()
    print(paint("  " + text, "accent", "bold"))
    print(paint("  " + "=" * _cells(text), "faint"))


# ====================================================================
#  EVTX container format
# ====================================================================

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"

FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_DATA_OFFSET = 512        # 128 byte header, then string and template tables
RECORD_HEADER_SIZE = 24

FLAG_DIRTY = 0x0001
FLAG_FULL = 0x0002

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)


class EvtxError(Exception):
    """Raised when a structure cannot be read as EVTX."""


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


class FileHeader(object):
    """The 4 KiB header at the front of every .evtx file."""

    __slots__ = ("first_chunk", "last_chunk", "next_record_id", "header_size",
                 "minor_version", "major_version", "header_block_size",
                 "chunk_count", "flags", "checksum", "checksum_ok")

    def __init__(self, data):
        if len(data) < 128 or data[:8] != FILE_MAGIC:
            raise EvtxError("not an EVTX file: bad ElfFile signature")
        (self.first_chunk, self.last_chunk, self.next_record_id,
         self.header_size, self.minor_version, self.major_version,
         self.header_block_size, self.chunk_count) = struct.unpack_from(
            "<QQQIHHHH", data, 8)
        self.flags = _u32(data, 120)
        self.checksum = _u32(data, 124)
        self.checksum_ok = (_crc32(data[:120]) == self.checksum)

    @property
    def dirty(self):
        """Set when the log was not closed cleanly, so chunk metadata may lag."""
        return bool(self.flags & FLAG_DIRTY)

    @property
    def full(self):
        return bool(self.flags & FLAG_FULL)

    @property
    def version(self):
        return "{}.{}".format(self.major_version, self.minor_version)


class ChunkHeader(object):
    """The 512 byte chunk preamble: record ranges, checksums, lookup tables."""

    __slots__ = ("index", "file_offset", "first_record_number", "last_record_number",
                 "first_record_id", "last_record_id", "header_size",
                 "last_record_offset", "free_space_offset", "records_checksum",
                 "checksum", "header_ok", "records_ok", "size")

    def __init__(self, buf, index, file_offset):
        if len(buf) < CHUNK_DATA_OFFSET or buf[:8] != CHUNK_MAGIC:
            raise EvtxError("bad ElfChnk signature at offset {}".format(file_offset))
        self.index = index
        self.file_offset = file_offset
        self.size = len(buf)
        (self.first_record_number, self.last_record_number,
         self.first_record_id, self.last_record_id, self.header_size,
         self.last_record_offset, self.free_space_offset,
         self.records_checksum) = struct.unpack_from("<QQQQIIII", buf, 8)
        self.checksum = _u32(buf, 124)

        # The header checksum deliberately skips bytes 120..128, which hold the
        # flags and the checksum itself, and covers the string and template
        # tables that follow.
        self.header_ok = (_crc32(buf[:120] + buf[128:512]) == self.checksum)

        end = self.free_space_offset
        if CHUNK_DATA_OFFSET <= end <= len(buf):
            self.records_ok = (_crc32(buf[CHUNK_DATA_OFFSET:end]) == self.records_checksum)
        else:
            self.records_ok = False


def iter_chunks(data):
    """Yield (index, file_offset, chunk_bytes) for every ElfChnk in the file.

    The header's chunk count is not trusted. A log that was not closed cleanly
    routinely carries more chunks on disk than the header admits to, and those
    trailing chunks hold the most recent events, which are usually the ones the
    investigation is about.
    """
    offset = FILE_HEADER_SIZE
    index = 0
    total = len(data)
    while offset + 8 <= total:
        if data[offset:offset + 8] != CHUNK_MAGIC:
            break
        buf = data[offset:offset + CHUNK_SIZE]
        yield index, offset, buf
        offset += CHUNK_SIZE
        index += 1


def iter_chunk_records(buf):
    """Yield (offset_in_chunk, size) for each record framed in this chunk."""
    limit = len(buf)
    free = _u32(buf, 48)
    if CHUNK_DATA_OFFSET < free <= limit:
        limit = free
    offset = CHUNK_DATA_OFFSET
    while offset + RECORD_HEADER_SIZE <= limit:
        if buf[offset:offset + 4] != RECORD_MAGIC:
            break
        size = _u32(buf, offset + 4)
        if size < RECORD_HEADER_SIZE + 4 or offset + size > limit:
            break
        yield offset, size
        offset += size


# ====================================================================
#  Binary XML
# ====================================================================

TOK_EOF = 0x00
TOK_OPEN_START = 0x01
TOK_CLOSE_START = 0x02
TOK_CLOSE_EMPTY = 0x03
TOK_END_ELEMENT = 0x04
TOK_VALUE = 0x05
TOK_ATTRIBUTE = 0x06
TOK_CDATA = 0x07
TOK_CHAR_REF = 0x08
TOK_ENTITY_REF = 0x09
TOK_PI_TARGET = 0x0A
TOK_PI_DATA = 0x0B
TOK_TEMPLATE = 0x0C
TOK_NORMAL_SUB = 0x0D
TOK_OPTIONAL_SUB = 0x0E
TOK_FRAGMENT = 0x0F

_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}

_MAX_SUBSTITUTIONS = 4096       # sanity bound, real templates use tens


class BinXmlContext(object):
    """Per chunk parse state.

    Name strings and template definitions live once per chunk and are
    referenced by offset from every record that uses them. That indirection is
    what makes the format compact, and caching it here is what makes reading it
    fast: a chunk with 400 records typically defines under 30 templates.
    """

    __slots__ = ("buf", "names", "name_sizes", "templates")

    def __init__(self, buf):
        self.buf = buf
        self.names = {}
        self.name_sizes = {}
        self.templates = {}

    def name(self, offset):
        cached = self.names.get(offset)
        if cached is not None:
            return cached
        count = _u16(self.buf, offset + 6)
        text = self.buf[offset + 8: offset + 8 + 2 * count].decode("utf-16-le", "replace")
        self.names[offset] = text
        self.name_sizes[offset] = 8 + 2 * count + 2      # trailing UTF-16 null
        return text

    def name_size(self, offset):
        if offset not in self.name_sizes:
            self.name(offset)
        return self.name_sizes[offset]

    def template(self, offset):
        """Parse and cache the binary XML of a template definition.

        The definition header is next-offset (4), GUID (16), data size (4), so
        the token stream starts 24 bytes in. Only the skeleton is cached: the
        substitution values belong to the record, not the template.
        """
        cached = self.templates.get(offset)
        if cached is None:
            cached, _ = _parse_fragment(self, offset + 24)
            self.templates[offset] = cached
        return cached


# AST node shapes, kept as plain tuples because a busy log builds millions:
#   ("e",   name, attrs, children)   attrs: [(name, [value nodes])]
#   ("t",   text)
#   ("s",   index, value_type, optional)
#   ("tpl", skeleton, values)

def _parse_fragment(ctx, offset):
    """Parse a fragment header followed by one element or template instance."""
    buf = ctx.buf
    if offset < len(buf) and (buf[offset] & 0x3F) == TOK_FRAGMENT:
        offset += 4                                  # token, major, minor, flags
    token = buf[offset] & 0x3F
    if token == TOK_TEMPLATE:
        return _parse_template_instance(ctx, offset)
    if token == TOK_OPEN_START:
        return _parse_element(ctx, offset)
    if token == TOK_EOF:
        return ("t", ""), offset + 1
    raise EvtxError("unexpected token 0x{:02x} at chunk offset {}".format(token, offset))


def _parse_template_instance(ctx, offset):
    """Token 0x0C: bind a template skeleton to this record's values."""
    buf = ctx.buf
    template_offset = _u32(buf, offset + 6)
    cursor = offset + 10

    # A resident instance carries the definition inline, immediately after this
    # header. Anything pointing backwards is a reference to a definition an
    # earlier record in the same chunk already laid down.
    if template_offset >= cursor:
        data_size = _u32(buf, template_offset + 20)
        cursor = template_offset + 24 + data_size

    skeleton = ctx.template(template_offset)
    values, cursor = _parse_substitutions(ctx, cursor)
    return ("tpl", skeleton, values), cursor


def _parse_substitutions(ctx, offset):
    """Read the value array that follows a template instance."""
    buf = ctx.buf
    count = _u32(buf, offset)
    if count > _MAX_SUBSTITUTIONS:
        raise EvtxError("implausible substitution count {}".format(count))
    cursor = offset + 4

    descriptors = []
    for _ in range(count):
        size, value_type = struct.unpack_from("<HB", buf, cursor)
        cursor += 4                                  # size, type, one reserved byte
        descriptors.append((size, value_type))

    values = []
    for size, value_type in descriptors:
        values.append(_read_value(ctx, cursor, size, value_type))
        cursor += size
    return values, cursor


def _parse_element(ctx, offset):
    """Token 0x01 / 0x41: an element, its attributes and everything inside it."""
    buf = ctx.buf
    has_attributes = bool(buf[offset] & 0x40)
    name_offset = _u32(buf, offset + 7)
    cursor = offset + 11

    # An inline name sits directly after the eleven byte header. A name offset
    # pointing anywhere else refers to a string already written in this chunk.
    if name_offset >= cursor:
        cursor = name_offset + ctx.name_size(name_offset)
    name = ctx.name(name_offset)

    attributes = []
    if has_attributes:
        cursor += 4                                  # attribute list size, unused
        while (buf[cursor] & 0x3F) == TOK_ATTRIBUTE:
            attr_name, attr_value, cursor = _parse_attribute(ctx, cursor)
            attributes.append((attr_name, attr_value))

    token = buf[cursor] & 0x3F
    if token == TOK_CLOSE_EMPTY:
        return ("e", name, attributes, []), cursor + 1
    if token != TOK_CLOSE_START:
        raise EvtxError("expected element close, got 0x{:02x}".format(token))

    children, cursor = _parse_children(ctx, cursor + 1)
    return ("e", name, attributes, children), cursor


def _parse_attribute(ctx, offset):
    """Token 0x06 / 0x46: one attribute and its value nodes."""
    buf = ctx.buf
    more = bool(buf[offset] & 0x40)
    name_offset = _u32(buf, offset + 1)
    cursor = offset + 5
    if name_offset >= cursor:
        cursor = name_offset + ctx.name_size(name_offset)
    name = ctx.name(name_offset)

    value, cursor = _parse_value_nodes(ctx, cursor)
    # The more flag belongs to the attribute list, not the value, and the loop
    # in _parse_element already stops on the first non attribute token.
    del more
    return name, value, cursor


def _parse_value_nodes(ctx, offset):
    """Read the node or nodes that make up one attribute value."""
    buf = ctx.buf
    nodes = []
    while True:
        token = buf[offset] & 0x3F
        more = bool(buf[offset] & 0x40)
        if token == TOK_VALUE:
            text, offset = _parse_inline_value(ctx, offset)
            nodes.append(("t", text))
        elif token in (TOK_NORMAL_SUB, TOK_OPTIONAL_SUB):
            nodes.append(("s", _u16(buf, offset + 1), buf[offset + 3],
                          token == TOK_OPTIONAL_SUB))
            offset += 4
        elif token == TOK_CHAR_REF:
            nodes.append(("t", chr(_u16(buf, offset + 1))))
            offset += 3
        elif token == TOK_ENTITY_REF:
            name_offset = _u32(buf, offset + 1)
            offset += 5
            if name_offset >= offset:
                offset = name_offset + ctx.name_size(name_offset)
            entity = ctx.name(name_offset)
            nodes.append(("t", _ENTITIES.get(entity, "&{};".format(entity))))
        else:
            break
        if not more:
            break
    return nodes, offset


def _parse_inline_value(ctx, offset):
    """Token 0x05 / 0x45: a literal value stored in the token stream."""
    buf = ctx.buf
    value_type = buf[offset + 1]
    if value_type == 0x00:
        return "", offset + 2
    if value_type != 0x01:
        raise EvtxError("unsupported inline value type 0x{:02x}".format(value_type))
    count = _u16(buf, offset + 2)
    text = buf[offset + 4: offset + 4 + 2 * count].decode("utf-16-le", "replace")
    return text, offset + 4 + 2 * count


def _parse_children(ctx, offset):
    """Read element content up to and including the matching end element."""
    buf = ctx.buf
    children = []
    while True:
        raw = buf[offset]
        token = raw & 0x3F
        if token == TOK_END_ELEMENT:
            return children, offset + 1
        if token == TOK_EOF:
            return children, offset + 1
        if token == TOK_OPEN_START:
            node, offset = _parse_element(ctx, offset)
            children.append(node)
        elif token == TOK_TEMPLATE:
            node, offset = _parse_template_instance(ctx, offset)
            children.append(node)
        elif token == TOK_VALUE:
            text, offset = _parse_inline_value(ctx, offset)
            children.append(("t", text))
        elif token in (TOK_NORMAL_SUB, TOK_OPTIONAL_SUB):
            children.append(("s", _u16(buf, offset + 1), buf[offset + 3],
                             token == TOK_OPTIONAL_SUB))
            offset += 4
        elif token == TOK_CDATA:
            count = _u16(buf, offset + 1)
            children.append(("t", buf[offset + 3: offset + 3 + 2 * count]
                             .decode("utf-16-le", "replace")))
            offset += 3 + 2 * count
        elif token == TOK_CHAR_REF:
            children.append(("t", chr(_u16(buf, offset + 1))))
            offset += 3
        elif token == TOK_ENTITY_REF:
            name_offset = _u32(buf, offset + 1)
            offset += 5
            if name_offset >= offset:
                offset = name_offset + ctx.name_size(name_offset)
            entity = ctx.name(name_offset)
            children.append(("t", _ENTITIES.get(entity, "&{};".format(entity))))
        elif token in (TOK_PI_TARGET, TOK_PI_DATA):
            # Processing instructions carry no evidential value, so they are
            # stepped over rather than represented.
            if token == TOK_PI_TARGET:
                name_offset = _u32(buf, offset + 1)
                offset += 5
                if name_offset >= offset:
                    offset = name_offset + ctx.name_size(name_offset)
            else:
                count = _u16(buf, offset + 1)
                offset += 3 + 2 * count
        elif token == TOK_FRAGMENT:
            offset += 4
        else:
            raise EvtxError("unexpected token 0x{:02x} in element content".format(token))


# ------------------------------------------------------------- value decoding

def _sid(raw):
    """S-1-5-21-... from the binary SID layout."""
    if len(raw) < 8:
        return ""
    revision = raw[0]
    count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    if len(raw) < 8 + 4 * count:
        count = max(0, (len(raw) - 8) // 4)
    parts = struct.unpack_from("<{}I".format(count), raw, 8) if count else ()
    return "S-{}-{}".format(revision, authority) + "".join("-{}".format(p) for p in parts)


def _guid(raw):
    if len(raw) < 16:
        return ""
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    return "{{{:08x}-{:04x}-{:04x}-{}-{}}}".format(
        d1, d2, d3, raw[8:10].hex(), raw[10:16].hex())


def filetime_to_datetime(value):
    """FILETIME, 100 nanosecond ticks since 1601, to an aware datetime."""
    if not value:
        return None
    try:
        return FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def filetime_to_iso(value):
    """Render a FILETIME at its full 100 nanosecond resolution.

    This deliberately does not go through datetime. A FILETIME carries seven
    fractional digits and datetime holds six, so converting first and
    formatting afterwards silently drops the last digit of every timestamp in
    the log. On a Security log that is tens of thousands of values that no
    longer match what Windows itself reports, which is exactly the kind of
    quiet discrepancy that loses an argument about evidence.
    """
    # Zero is a real rendered value, the 1601 epoch itself, and Windows prints
    # it. Suppressing it would turn "this wake timer was never programmed" into
    # "this field is missing", which are different statements about the host.
    seconds, ticks = divmod(int(value), 10_000_000)
    try:
        moment = FILETIME_EPOCH + dt.timedelta(seconds=seconds)
    except OverflowError:
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "{:07d}".format(ticks) + "Z"


def _iso(moment):
    return moment.isoformat() if moment is not None else ""


def _systemtime(raw):
    if len(raw) < 16:
        return ""
    year, month, _dow, day, hour, minute, second, milli = struct.unpack_from("<8H", raw, 0)
    try:
        return dt.datetime(year, month, day, hour, minute, second,
                           milli * 1000, tzinfo=dt.timezone.utc).isoformat()
    except ValueError:
        return ""


_SIMPLE_FORMATS = {
    0x03: ("<b", None), 0x04: ("<B", None),
    0x05: ("<h", None), 0x06: ("<H", None),
    0x07: ("<i", None), 0x08: ("<I", None),
    0x09: ("<q", None), 0x0A: ("<Q", None),
    0x0B: ("<f", None), 0x0C: ("<d", None),
}

_ELEMENT_SIZES = {
    0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4,
    0x09: 8, 0x0A: 8, 0x0B: 4, 0x0C: 8, 0x0D: 4,
    0x0F: 16, 0x11: 8, 0x12: 16, 0x14: 4, 0x15: 8,
}


def _read_scalar(ctx, offset, size, base):
    buf = ctx.buf
    if base == 0x01:
        return buf[offset:offset + size].decode("utf-16-le", "replace").rstrip("\x00")
    if base == 0x02:
        return buf[offset:offset + size].decode("cp1252", "replace").rstrip("\x00")
    if base in _SIMPLE_FORMATS:
        fmt = _SIMPLE_FORMATS[base][0]
        value = struct.unpack_from(fmt, buf, offset)[0]
        if base in (0x0B, 0x0C):
            return repr(value)
        return str(value)
    if base == 0x0D:
        return "true" if _u32(buf, offset) else "false"
    if base == 0x0E:
        return buf[offset:offset + size].hex().upper()
    if base == 0x0F:
        return _guid(buf[offset:offset + 16])
    if base == 0x10:
        return "0x{:x}".format(_u64(buf, offset) if size >= 8 else _u32(buf, offset))
    if base == 0x11:
        return filetime_to_iso(_u64(buf, offset))
    if base == 0x12:
        return _systemtime(buf[offset:offset + 16])
    if base == 0x13:
        return _sid(buf[offset:offset + size])
    if base == 0x14:
        return "0x{:x}".format(_u32(buf, offset))
    if base == 0x15:
        return "0x{:x}".format(_u64(buf, offset))
    if base == 0x20:
        return buf[offset:offset + size].hex().upper()
    return buf[offset:offset + size].hex().upper()


def _read_value(ctx, offset, size, value_type):
    """Decode one substitution value.

    Returns None for a genuinely absent value, which is what lets an optional
    substitution drop its attribute instead of emitting an empty one. Embedded
    binary XML comes back as a parsed fragment, because that is how providers
    nest structured payloads such as Sysmon's EventData.
    """
    if size == 0 or (value_type & 0x7F) == 0x00:
        return None

    base = value_type & 0x7F
    if value_type & 0x80:
        return _read_array(ctx, offset, size, base)

    if base == 0x21:
        node, _ = _parse_fragment(ctx, offset)
        return ("frag", node)
    return _read_scalar(ctx, offset, size, base)


def _read_array(ctx, offset, size, base):
    """Array substitutions pack their elements back to back inside `size`.

    The list is kept as a list rather than joined, because the element that
    holds the substitution has to be repeated once per item. See
    _expand_element for why that matters.
    """
    buf = ctx.buf
    if base in (0x01, 0x02):
        codec = "utf-16-le" if base == 0x01 else "cp1252"
        text = buf[offset:offset + size].decode(codec, "replace")
        parts = text.split("\x00")
        # Every item is null terminated, so the split always leaves one empty
        # string behind the final terminator. Exactly one, though: an array
        # really can end with an empty value, and dropping every trailing
        # empty deletes a field the event actually carries.
        if parts and parts[-1] == "":
            parts.pop()
        return parts
    width = _ELEMENT_SIZES.get(base)
    if not width:
        return [buf[offset:offset + size].hex().upper()]
    return [_read_scalar(ctx, offset + i, width, base)
            for i in range(0, size - width + 1, width)]


# ------------------------------------------------------------------ rendering

class Elem(object):
    """A rendered XML element. Deliberately minimal, built millions of times."""

    __slots__ = ("tag", "attrs", "text", "children")

    def __init__(self, tag):
        self.tag = tag
        self.attrs = OrderedDict()
        self.text = ""
        self.children = []

    def find(self, tag):
        for child in self.children:
            if child.tag == tag:
                return child
        return None

    def findall(self, tag):
        return [c for c in self.children if c.tag == tag]


def _resolve_nodes(nodes, values):
    """Flatten an attribute's value nodes to text, or None if all are absent."""
    parts = []
    saw_value = False
    for node in nodes:
        if node[0] == "t":
            parts.append(node[1])
            saw_value = True
        elif node[0] == "s":
            value = values[node[1]] if node[1] < len(values) else None
            if value is None:
                if node[3]:                       # optional, so contribute nothing
                    continue
                saw_value = True
                continue
            saw_value = True
            if isinstance(value, tuple) and value and value[0] == "frag":
                built = build_tree(value[1])
                parts.append(_flatten_text(built))
            elif isinstance(value, list):
                # An attribute cannot repeat, so an array collapses here.
                parts.append(", ".join(value))
            else:
                parts.append(value)
    if not saw_value and not parts:
        return None
    return "".join(parts)


def _flatten_text(elem):
    out = [elem.text]
    for child in elem.children:
        out.append(_flatten_text(child))
    return "".join(out)


def build_tree(node, values=None):
    """Turn an AST node plus its substitution values into an Elem tree."""
    kind = node[0]
    if kind == "tpl":
        return build_tree(node[1], node[2])
    if kind == "e":
        return _build_element(node, values or [])
    if kind == "s":
        value = (values or [])[node[1]] if values and node[1] < len(values) else None
        if isinstance(value, tuple) and value and value[0] == "frag":
            return build_tree(value[1])
        elem = Elem("Value")
        elem.text = ", ".join(value) if isinstance(value, list) else (value or "")
        return elem
    elem = Elem("Text")
    elem.text = node[1] if kind == "t" else ""
    return elem


def _expand_element(node, values):
    """Build a child element, repeating it once per item if its value is an array.

    A template stores `<Data>` once even when the event carries a list, and the
    substitution then resolves to an array. Windows renders that as one sibling
    element per item, so a PowerShell 600 event shows three separate `<Data>`
    nodes rather than one containing a joined string. Emitting the joined form
    would silently merge three distinct fields into one, which changes what the
    record appears to say.
    """
    _, _name, _attrs, children_ast = node
    if len(children_ast) == 1 and children_ast[0][0] == "s":
        index = children_ast[0][1]
        optional = children_ast[0][3]
        value = values[index] if index < len(values) else None
        if value is None and optional:
            # That is what optional means: the element is not rendered at all.
            # A classic EventData with no binary blob has no <Binary> element,
            # it does not have an empty one, and an analyst counting fields
            # would otherwise see a field the event never carried.
            return []
        if isinstance(value, list):
            out = []
            for item in value:
                copy = _build_element(node, values)
                copy.text = item
                copy.children = []
                out.append(copy)
            return out
    return [_build_element(node, values)]


def _build_element(node, values):
    _, name, attrs_ast, children_ast = node
    elem = Elem(name)

    for attr_name, attr_nodes in attrs_ast:
        text = _resolve_nodes(attr_nodes, values)
        if text is None:
            continue                      # absent optional substitution, attribute dropped
        elem.attrs[attr_name] = text

    for child in children_ast:
        kind = child[0]
        if kind == "e":
            elem.children.extend(_expand_element(child, values))
        elif kind == "t":
            elem.text += child[1]
        elif kind == "tpl":
            elem.children.append(_build_element(child[1], child[2])
                                 if child[1][0] == "e" else build_tree(child))
        elif kind == "s":
            index = child[1]
            value = values[index] if index < len(values) else None
            if value is None:
                continue
            if isinstance(value, tuple) and value and value[0] == "frag":
                built = build_tree(value[1])
                # An embedded fragment that is really a container contributes
                # its children, not a wrapper nobody asked for.
                if built.tag in ("Text", "Value"):
                    elem.text += built.text
                else:
                    elem.children.append(built)
            elif isinstance(value, list):
                # Mixed content around an array, so there is no element to
                # repeat and the items have to be joined.
                elem.text += ", ".join(value)
            else:
                elem.text += value
    return elem


_ILLEGAL_XML = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


def _escape(text, attribute=False):
    text = _ILLEGAL_XML.sub("", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if attribute:
        text = text.replace('"', "&quot;")
    return text


def to_xml(elem, indent=0, pretty=True):
    """Serialise an Elem tree. Matches the shape wevtutil prints."""
    pad = "  " * indent if pretty else ""
    nl = "\n" if pretty else ""
    attrs = "".join(' {}="{}"'.format(k, _escape(v, True)) for k, v in elem.attrs.items())
    text = _escape(elem.text)

    if not elem.children and not text:
        return "{}<{}{} />{}".format(pad, elem.tag, attrs, nl)
    if not elem.children:
        return "{}<{}{}>{}</{}>{}".format(pad, elem.tag, attrs, text, elem.tag, nl)

    parts = ["{}<{}{}>{}".format(pad, elem.tag, attrs, nl)]
    if text.strip():
        parts.append("{}  {}{}".format(pad, text, nl))
    for child in elem.children:
        parts.append(to_xml(child, indent + 1, pretty))
    parts.append("{}</{}>{}".format(pad, elem.tag, nl))
    return "".join(parts)


# ====================================================================
#  Event model
# ====================================================================

_LEVEL_NAMES = {0: "Information", 1: "Critical", 2: "Error",
                3: "Warning", 4: "Information", 5: "Verbose"}

_LEVEL_TONE = {"Critical": "pink", "Error": "pink", "Warning": "warn",
               "Verbose": "faint", "Information": None}


class Event(object):
    """One event record, decoded far enough to answer questions about it."""

    __slots__ = ("record_id", "timestamp", "written", "event_id", "provider",
                 "provider_guid", "channel", "computer", "user_sid", "level",
                 "task", "opcode", "keywords", "process_id", "thread_id",
                 "data", "source", "chunk", "offset", "_elem")

    def __init__(self):
        self.record_id = 0
        self.timestamp = None
        self.written = None
        self.event_id = ""
        self.provider = ""
        self.provider_guid = ""
        self.channel = ""
        self.computer = ""
        self.user_sid = ""
        self.level = ""
        self.task = ""
        self.opcode = ""
        self.keywords = ""
        self.process_id = ""
        self.thread_id = ""
        self.data = OrderedDict()
        self.source = ""
        self.chunk = 0
        self.offset = 0
        self._elem = None

    @property
    def time_iso(self):
        return _iso(self.timestamp)

    @property
    def xml(self):
        return to_xml(self._elem).rstrip("\n") if self._elem is not None else ""

    def summary(self, width=70):
        """A one line gist of the payload, for the console table."""
        interesting = ("TargetUserName", "SubjectUserName", "NewProcessName", "Image",
                       "CommandLine", "ServiceName", "ObjectName", "TaskName",
                       "AccountName", "ScriptBlockText", "param1", "Data1")
        for key in interesting:
            if self.data.get(key):
                return "{}={}".format(key, self.data[key])[:width]
        for key, value in self.data.items():
            if value:
                return "{}={}".format(key, value)[:width]
        return ""


def _collect_data(container, out, prefix=""):
    """Flatten EventData / UserData into a flat name to value mapping."""
    positional = 0
    for child in container.children:
        name = child.attrs.get("Name")
        if child.children:
            _collect_data(child, out, prefix + child.tag + ".")
            continue
        if not name:
            positional += 1
            name = child.tag if child.tag != "Data" else "Data{}".format(positional)
        key = prefix + name
        if key in out and out[key]:
            suffix = 2
            while "{}#{}".format(key, suffix) in out:
                suffix += 1
            key = "{}#{}".format(key, suffix)
        out[key] = child.text


def event_from_elem(elem, record_id, written, source, chunk, offset):
    """Pull the System header fields and the payload out of a rendered event."""
    event = Event()
    event.record_id = record_id
    event.written = written
    event.timestamp = written
    event.source = source
    event.chunk = chunk
    event.offset = offset
    event._elem = elem

    system = elem.find("System")
    if system is not None:
        provider = system.find("Provider")
        if provider is not None:
            event.provider = provider.attrs.get("Name") or provider.attrs.get("EventSourceName", "")
            event.provider_guid = provider.attrs.get("Guid", "")

        for tag, attr in (("EventID", "event_id"), ("Level", "level"),
                          ("Task", "task"), ("Opcode", "opcode"),
                          ("Keywords", "keywords"), ("Channel", "channel"),
                          ("Computer", "computer")):
            node = system.find(tag)
            if node is not None:
                setattr(event, attr, node.text.strip())

        created = system.find("TimeCreated")
        if created is not None and created.attrs.get("SystemTime"):
            parsed = _parse_time(created.attrs["SystemTime"])
            if parsed is not None:
                event.timestamp = parsed

        execution = system.find("Execution")
        if execution is not None:
            event.process_id = execution.attrs.get("ProcessID", "")
            event.thread_id = execution.attrs.get("ThreadID", "")

        security = system.find("Security")
        if security is not None:
            event.user_sid = security.attrs.get("UserID", "")

        record = system.find("EventRecordID")
        if record is not None and record.text.strip().isdigit():
            event.record_id = int(record.text.strip())

    if event.level.isdigit():
        event.level = _LEVEL_NAMES.get(int(event.level), event.level)

    for container_tag in ("EventData", "UserData", "ProcessingErrorData"):
        container = elem.find(container_tag)
        if container is not None:
            _collect_data(container, event.data)

    return event


_TIME_FRACTION = re.compile(r"\.(\d+)")


def _parse_time(text):
    """Accept the ISO shapes Windows and the toolkit both emit."""
    if not text:
        return None
    raw = text.strip().replace("Z", "+00:00")
    # Python accepts at most six fractional digits, Windows writes seven.
    match = _TIME_FRACTION.search(raw)
    if match and len(match.group(1)) > 6:
        raw = raw[:match.start(1) + 6] + raw[match.end(1):]
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


# ====================================================================
#  Reading a file
# ====================================================================

class ParseStats(object):
    __slots__ = ("chunks", "chunks_bad_header", "chunks_bad_records",
                 "records", "failed", "files", "first_error")

    def __init__(self):
        self.chunks = 0
        self.chunks_bad_header = 0
        self.chunks_bad_records = 0
        self.records = 0
        self.failed = 0
        self.files = 0
        self.first_error = ""


def read_evtx(path, stats=None, on_error="skip"):
    """Yield every Event in one .evtx file.

    A record that will not decode is skipped rather than fatal: a single
    malformed record in a 60 MB Sysmon log must not cost the analyst the other
    quarter million events.
    """
    with open(path, "rb") as handle:
        data = handle.read()

    header = FileHeader(data)
    source = os.path.basename(path)
    if stats is not None:
        stats.files += 1

    for index, file_offset, buf in iter_chunks(data):
        try:
            chunk_header = ChunkHeader(buf, index, file_offset)
        except EvtxError:
            continue
        if stats is not None:
            stats.chunks += 1
            if not chunk_header.header_ok:
                stats.chunks_bad_header += 1
            if not chunk_header.records_ok:
                stats.chunks_bad_records += 1

        ctx = BinXmlContext(buf)
        for offset, size in iter_chunk_records(buf):
            record_id = _u64(buf, offset + 8)
            written = filetime_to_datetime(_u64(buf, offset + 16))
            try:
                node, _ = _parse_fragment(ctx, offset + RECORD_HEADER_SIZE)
                elem = build_tree(node)
                event = event_from_elem(elem, record_id, written, source, index, offset)
            except Exception as exc:                # noqa: BLE001, one bad record
                if stats is not None:
                    stats.failed += 1
                    if not stats.first_error:
                        stats.first_error = "{}: chunk {} offset {}: {}".format(
                            source, index, offset, exc)
                if on_error == "raise":
                    raise
                continue
            if stats is not None:
                stats.records += 1
            yield event
    del header


def expand_inputs(paths):
    """Accept files, directories and globs, and return .evtx paths."""
    out = []
    for item in paths:
        if os.path.isdir(item):
            out.extend(sorted(glob.glob(os.path.join(item, "*.evtx"))))
        elif any(ch in item for ch in "*?["):
            out.extend(sorted(glob.glob(item)))
        else:
            out.append(item)
    missing = [p for p in out if not os.path.isfile(p)]
    if missing:
        raise SystemExit("input not found: " + ", ".join(missing[:5]))
    if not out:
        raise SystemExit("no .evtx files matched the input")
    return out


# ====================================================================
#  Filtering
# ====================================================================

class Filters(object):
    """Predicates applied while streaming, so nothing large is held twice."""

    __slots__ = ("event_ids", "providers", "channels", "computers", "levels",
                 "after", "before", "contains", "user", "record_ids", "regex")

    def __init__(self, args):
        self.event_ids = set(str(x) for x in (args.event_id or []))
        self.providers = [p.lower() for p in (args.provider or [])]
        self.channels = [c.lower() for c in (args.channel or [])]
        self.computers = [c.lower() for c in (args.computer or [])]
        self.levels = [l.lower() for l in (args.level or [])]
        self.after = _parse_time(args.after) if args.after else None
        self.before = _parse_time(args.before) if args.before else None
        self.contains = [c.lower() for c in (args.contains or [])]
        self.user = [u.lower() for u in (args.user or [])]
        self.record_ids = set(args.record_id or [])
        self.regex = re.compile(args.regex, re.I | re.S) if args.regex else None

        if args.after and self.after is None:
            raise SystemExit("could not parse --after {!r}, use ISO 8601".format(args.after))
        if args.before and self.before is None:
            raise SystemExit("could not parse --before {!r}, use ISO 8601".format(args.before))

    @property
    def active(self):
        return bool(self.event_ids or self.providers or self.channels or
                    self.computers or self.levels or self.after or self.before or
                    self.contains or self.user or self.record_ids or self.regex)

    def match(self, event):
        if self.event_ids and event.event_id not in self.event_ids:
            return False
        if self.record_ids and event.record_id not in self.record_ids:
            return False
        if self.levels and event.level.lower() not in self.levels:
            return False
        if self.providers and not any(p in event.provider.lower() for p in self.providers):
            return False
        if self.channels and not any(c in event.channel.lower() for c in self.channels):
            return False
        if self.computers and not any(c in event.computer.lower() for c in self.computers):
            return False
        if self.after and (event.timestamp is None or event.timestamp < self.after):
            return False
        if self.before and (event.timestamp is None or event.timestamp > self.before):
            return False
        if self.user:
            haystack = (event.user_sid + " " +
                        " ".join(str(v) for k, v in event.data.items()
                                 if "user" in k.lower() or "account" in k.lower())).lower()
            if not any(u in haystack for u in self.user):
                return False
        if self.contains or self.regex:
            blob = event.xml
            if self.contains and not all(c in blob.lower() for c in self.contains):
                return False
            if self.regex and not self.regex.search(blob):
                return False
        return True


def collect_events(args, stats):
    """Stream every input file through the filters into a list."""
    filters = Filters(args)
    events = []
    cap = getattr(args, "max_records", 0) or 0
    for path in expand_inputs(args.input):
        try:
            for event in read_evtx(path, stats):
                if filters.match(event):
                    events.append(event)
                    if cap and len(events) >= cap:
                        return events, filters
        except EvtxError as exc:
            print(paint("[!] {}: {}".format(os.path.basename(path), exc), "warn"),
                  file=sys.stderr)
        except (IOError, OSError) as exc:
            print(paint("[!] {}: {}".format(os.path.basename(path), exc), "warn"),
                  file=sys.stderr)
    return events, filters


def report_stats(stats, quiet):
    if quiet:
        return
    line = "[*] {:,} file(s), {:,} chunks, {:,} records".format(
        stats.files, stats.chunks, stats.records)
    print(paint(line, "dim"), file=sys.stderr)
    if stats.failed:
        print(paint("[!] {:,} record(s) would not decode. First: {}".format(
            stats.failed, stats.first_error), "warn"), file=sys.stderr)
    if stats.chunks_bad_header or stats.chunks_bad_records:
        print(paint("[!] checksum mismatches: {} chunk header(s), {} record area(s). "
                    "Run `info` for the chunk map.".format(
                        stats.chunks_bad_header, stats.chunks_bad_records), "warn"),
              file=sys.stderr)


# ====================================================================
#  Output writers
# ====================================================================

_CSV_COLUMNS = ["TimeCreated", "RecordId", "EventId", "Level", "Provider", "Channel",
                "Computer", "UserSid", "ProcessId", "ThreadId", "Task", "Opcode",
                "Keywords", "Payload", "SourceFile"]


def event_to_row(event):
    return {
        "TimeCreated": event.time_iso,
        "RecordId": event.record_id,
        "EventId": event.event_id,
        "Level": event.level,
        "Provider": event.provider,
        "Channel": event.channel,
        "Computer": event.computer,
        "UserSid": event.user_sid,
        "ProcessId": event.process_id,
        "ThreadId": event.thread_id,
        "Task": event.task,
        "Opcode": event.opcode,
        "Keywords": event.keywords,
        "Payload": json.dumps(event.data, ensure_ascii=False),
        "SourceFile": event.source,
    }


def write_csv(path, events, columns=None, rows=None):
    columns = columns or _CSV_COLUMNS
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in (rows if rows is not None else (event_to_row(e) for e in events)):
            writer.writerow(row)


def write_json(path, events):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump([{
            "time_created": e.time_iso,
            "record_id": e.record_id,
            "event_id": e.event_id,
            "level": e.level,
            "provider": e.provider,
            "provider_guid": e.provider_guid,
            "channel": e.channel,
            "computer": e.computer,
            "user_sid": e.user_sid,
            "process_id": e.process_id,
            "thread_id": e.thread_id,
            "task": e.task,
            "opcode": e.opcode,
            "keywords": e.keywords,
            "data": e.data,
            "source_file": e.source,
        } for e in events], handle, ensure_ascii=False, indent=2)


def write_xml(path, events):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write('<?xml version="1.0" encoding="utf-8"?>\n<Events>\n')
        for event in events:
            handle.write(event.xml + "\n")
        handle.write("</Events>\n")


# ====================================================================
#  Subcommands
# ====================================================================

def cmd_info(args):
    """File and chunk level facts, including the checksums the format carries."""
    for path in expand_inputs(args.input):
        with open(path, "rb") as handle:
            data = handle.read()
        try:
            header = FileHeader(data)
        except EvtxError as exc:
            print(paint("  {}: {}".format(os.path.basename(path), exc), "pink"))
            continue

        heading(os.path.basename(path))
        size = len(data)
        facts = [
            ("path", path),
            ("size", "{:,} bytes".format(size)),
            ("format version", header.version),
            ("chunks, per header", "{:,}".format(header.chunk_count)),
            ("chunk range, per header", "{} to {}".format(header.first_chunk, header.last_chunk)),
            ("next record id", "{:,}".format(header.next_record_id)),
            ("header checksum", "valid" if header.checksum_ok else "MISMATCH"),
            ("dirty flag", "set, log was not closed cleanly" if header.dirty else "clear"),
            ("full flag", "set, log had wrapped" if header.full else "clear"),
        ]
        width = max(len(k) for k, _ in facts)
        for key, value in facts:
            tone = None
            if value in ("MISMATCH",) or value.startswith("set,"):
                tone = "warn" if value.startswith("set,") else "pink"
            elif value == "valid" or value == "clear":
                tone = "ok"
            print("  {}  {}".format(paint(key.ljust(width), "dim"), paint(value, tone)))

        chunks = []
        on_disk = 0
        first_seen = None
        last_seen = None
        for index, offset, buf in iter_chunks(data):
            on_disk += 1
            try:
                ch = ChunkHeader(buf, index, offset)
            except EvtxError:
                continue
            count = sum(1 for _ in iter_chunk_records(buf))
            times = []
            for rec_off, _size in iter_chunk_records(buf):
                moment = filetime_to_datetime(_u64(buf, rec_off + 16))
                if moment:
                    times.append(moment)
            if times:
                low, high = min(times), max(times)
                first_seen = low if first_seen is None else min(first_seen, low)
                last_seen = high if last_seen is None else max(last_seen, high)
                span = "{}  ..  {}".format(low.strftime("%Y-%m-%d %H:%M:%S"),
                                           high.strftime("%Y-%m-%d %H:%M:%S"))
            else:
                span = ""
            chunks.append({
                "chunk": index,
                "offset": "0x{:x}".format(offset),
                "records": "{:,}".format(count),
                "ids": "{}-{}".format(ch.first_record_id, ch.last_record_id),
                "header": "ok" if ch.header_ok else "BAD",
                "data": "ok" if ch.records_ok else "BAD",
                "span": span,
            })

        print()
        print("  {}  {}".format(paint("chunks on disk".ljust(width), "dim"),
                                paint("{:,}".format(on_disk),
                                      "warn" if on_disk != header.chunk_count else None)))
        if on_disk != header.chunk_count:
            print(paint("  The header understates the chunk count, which is normal for a "
                        "log that was not closed cleanly.", "dim"))
            print(paint("  The extra chunks hold the most recent events, so they are read "
                        "anyway.", "dim"))
        if first_seen and last_seen:
            print("  {}  {} .. {}".format(paint("event time span".ljust(width), "dim"),
                                          first_seen.isoformat(), last_seen.isoformat()))

        def tone_for(row, key):
            if key in ("header", "data"):
                return "pink" if row[key] == "BAD" else "ok"
            return None

        print()
        for line in render_table(chunks, [
                ("chunk", "chunk"), ("offset", "offset"), ("records", "records"),
                ("ids", "record ids"), ("header", "hdr crc"), ("data", "rec crc"),
                ("span", "time span")], limit=args.limit, tone_for=tone_for):
            print(line)

        bad = [c for c in chunks if c["header"] == "BAD" or c["data"] == "BAD"]
        if bad:
            print()
            print(paint("  {} chunk(s) fail a CRC32 check.".format(len(bad)), "warn"))
            print(paint("  In the last chunk of a dirty log this is expected, because the "
                        "checksum is written on close.", "dim"))
            print(paint("  Anywhere else it means the bytes no longer match what the "
                        "service wrote.", "dim"))
    return 0


def cmd_dump(args):
    stats = ParseStats()
    events, filters = collect_events(args, stats)
    report_stats(stats, args.quiet)

    if args.sort == "time":
        events.sort(key=lambda e: (e.timestamp or FILETIME_EPOCH, e.record_id))
    elif args.sort == "record":
        events.sort(key=lambda e: (e.source, e.record_id))

    if args.xml:
        write_xml(args.xml, events)
        print(paint("[+] {:,} event(s) to {}".format(len(events), args.xml), "ok"),
              file=sys.stderr)
    if args.csv:
        write_csv(args.csv, events)
        print(paint("[+] {:,} event(s) to {}".format(len(events), args.csv), "ok"),
              file=sys.stderr)
    if args.json:
        write_json(args.json, events)
        print(paint("[+] {:,} event(s) to {}".format(len(events), args.json), "ok"),
              file=sys.stderr)

    if args.print_xml:
        for event in (events if not args.limit else events[:args.limit]):
            print(event.xml)
            print()
        return 0

    if args.xml or args.csv or args.json:
        if args.quiet:
            return 0

    heading("Events  ({:,} matched{})".format(
        len(events), ", filtered" if filters.active else ""))

    rows = [{
        "time": e.time_iso.replace("+00:00", "Z"),
        "record": e.record_id,
        "eid": e.event_id,
        "level": e.level,
        "provider": e.provider,
        "computer": e.computer,
        "summary": e.summary(),
    } for e in events]

    def tone_for(row, key):
        if key == "level":
            return _LEVEL_TONE.get(row["level"])
        if key == "eid":
            return "accent"
        return None

    for line in render_table(rows, [
            ("time", "time (utc)"), ("record", "record"), ("eid", "eid"),
            ("level", "level"), ("provider", "provider"),
            ("computer", "computer"), ("summary", "summary")],
            limit=args.limit, tone_for=tone_for):
        print(line)
    return 0


def cmd_stats(args):
    """What is in this log, by volume. The first question on any new evidence."""
    stats = ParseStats()
    events, _filters = collect_events(args, stats)
    report_stats(stats, args.quiet)

    if not events:
        print(paint("  (nothing matched)", "dim"))
        return 0

    by_id = Counter((e.provider, e.event_id) for e in events)
    by_provider = Counter(e.provider for e in events)
    by_level = Counter(e.level for e in events)
    by_computer = Counter(e.computer for e in events)

    heading("Top event IDs")
    rows = [{"eid": eid, "provider": provider, "count": "{:,}".format(count),
             "share": "{:.1f}%".format(100.0 * count / len(events))}
            for (provider, eid), count in by_id.most_common(args.top)]
    for line in render_table(rows, [("eid", "eid"), ("provider", "provider"),
                                    ("count", "count"), ("share", "share")],
                             limit=0, tone_for=lambda r, k: "accent" if k == "eid" else None):
        print(line)

    heading("Providers")
    rows = [{"provider": p, "count": "{:,}".format(c)}
            for p, c in by_provider.most_common(args.top)]
    for line in render_table(rows, [("provider", "provider"), ("count", "count")], limit=0):
        print(line)

    heading("Levels")
    rows = [{"level": lvl or "(none)", "count": "{:,}".format(c)}
            for lvl, c in by_level.most_common()]
    for line in render_table(rows, [("level", "level"), ("count", "count")], limit=0,
                             tone_for=lambda r, k: _LEVEL_TONE.get(r["level"])):
        print(line)

    if len(by_computer) > 1:
        heading("Computers")
        rows = [{"computer": c or "(none)", "count": "{:,}".format(n)}
                for c, n in by_computer.most_common(args.top)]
        for line in render_table(rows, [("computer", "computer"), ("count", "count")], limit=0):
            print(line)

    timed = [e.timestamp for e in events if e.timestamp]
    if timed:
        heading("Volume by hour")
        buckets = Counter(t.replace(minute=0, second=0, microsecond=0) for t in timed)
        peak = max(buckets.values())
        blocks = " .:-=+*#%@"
        for hour in sorted(buckets):
            count = buckets[hour]
            level = min(len(blocks) - 1, int(round((count / peak) * (len(blocks) - 1))))
            bar = blocks[level] * max(1, int(round(40.0 * count / peak)))
            print("  {}  {}  {}".format(
                paint(hour.strftime("%Y-%m-%d %H:00"), "dim"),
                paint("{:>7,}".format(count), "accent"),
                paint(bar, "faint")))
        print()
        print(paint("  {:,} events from {} to {}".format(
            len(timed), min(timed).isoformat(), max(timed).isoformat()), "dim"))

    if args.csv:
        rows = [{"Provider": p, "EventId": eid, "Count": c}
                for (p, eid), c in by_id.most_common()]
        write_csv(args.csv, None, columns=["Provider", "EventId", "Count"], rows=rows)
        print(paint("[+] histogram to {}".format(args.csv), "ok"), file=sys.stderr)
    return 0


# ------------------------------------------------------- the toolkit bridge

_EVTXECMD_COLUMNS = ["TimeCreated", "EventId", "Provider", "Channel", "UserName",
                     "ExecutableInfo", "Payload", "SourceFile"]

# Session correlation needs these and nothing else, and CQUSNCorrelate reads
# them straight out of the payload text.
_SESSION_EVENT_IDS = {"4624", "4634", "4647", "4625", "4648", "4672", "4776", "4778", "4779"}


def _username_for(event):
    """Best available account name, in the DOMAIN\\user shape EvtxECmd writes."""
    data = event.data
    user = data.get("TargetUserName") or data.get("SubjectUserName") or data.get("AccountName")
    domain = data.get("TargetDomainName") or data.get("SubjectDomainName")
    if user and domain and domain not in ("-", ""):
        return "{}\\{}".format(domain, user)
    if user:
        return user
    return event.user_sid or ""


def _executable_for(event):
    data = event.data
    return (data.get("NewProcessName") or data.get("Image") or
            data.get("ProcessName") or data.get("ServiceFileName") or "")


def cmd_evtxecmd(args):
    """Emit the CSV shape CQUSNCorrelate's `sessions` subcommand consumes.

    EvtxECmd is an excellent tool, but it is a .NET binary and one more thing
    to carry onto an evidence machine. Producing its CSV contract natively
    means the CQURE forensic set runs end to end on a stock Python install.
    """
    stats = ParseStats()
    if args.sessions_only and not args.event_id:
        args.event_id = sorted(_SESSION_EVENT_IDS)
    events, _filters = collect_events(args, stats)
    report_stats(stats, args.quiet)

    events.sort(key=lambda e: (e.timestamp or FILETIME_EPOCH, e.record_id))

    rows = []
    for event in events:
        # The payload is read downstream with forgiving regexes, so a plain
        # JSON object satisfies both a human reading the CSV and the parser.
        rows.append({
            "TimeCreated": event.time_iso,
            "EventId": event.event_id,
            "Provider": event.provider,
            "Channel": event.channel,
            "UserName": _username_for(event),
            "ExecutableInfo": _executable_for(event),
            "Payload": json.dumps(event.data, ensure_ascii=False),
            "SourceFile": event.source,
        })

    target = args.out or args.csv
    if target:
        write_csv(target, None, columns=_EVTXECMD_COLUMNS, rows=rows)
        print(paint("[+] {:,} row(s) to {}".format(len(rows), target), "ok"), file=sys.stderr)
        if not args.quiet:
            print()
            print(paint("  Feed it straight into the sibling tool:", "dim"))
            print(paint("    py -3 CQUSNCorrelate.py sessions --input J.bin --evtx {}".format(
                target), "accent"))
        return 0

    writer = csv.DictWriter(sys.stdout, fieldnames=_EVTXECMD_COLUMNS,
                            extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return 0


# ====================================================================
#  CLI
# ====================================================================

def add_input_args(parser):
    parser.add_argument("--input", "-i", nargs="+", required=True, metavar="PATH",
                        help="one or more .evtx files, a directory, or a glob")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="colour output. auto is on for a terminal, off when piped")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="suppress progress on stderr")


def add_filter_args(parser):
    group = parser.add_argument_group("filters")
    group.add_argument("--event-id", "-e", nargs="+", metavar="ID",
                       help="keep only these event IDs")
    group.add_argument("--provider", "-p", nargs="+", metavar="SUBSTR",
                       help="provider name contains any of these")
    group.add_argument("--channel", nargs="+", metavar="SUBSTR",
                       help="channel contains any of these")
    group.add_argument("--computer", nargs="+", metavar="SUBSTR",
                       help="computer name contains any of these")
    group.add_argument("--level", nargs="+", metavar="NAME",
                       help="Critical, Error, Warning, Information or Verbose")
    group.add_argument("--user", nargs="+", metavar="SUBSTR",
                       help="any user or account field contains this")
    group.add_argument("--record-id", nargs="+", type=int, metavar="N",
                       help="keep only these record IDs")
    group.add_argument("--after", metavar="ISO", help="events at or after this time")
    group.add_argument("--before", metavar="ISO", help="events at or before this time")
    group.add_argument("--contains", nargs="+", metavar="SUBSTR",
                       help="rendered XML contains ALL of these, case insensitive")
    group.add_argument("--regex", metavar="PATTERN",
                       help="rendered XML matches this regular expression")
    group.add_argument("--max-records", type=int, default=0, metavar="N",
                       help="stop after N matching events, for fast iteration")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="CQEVTXExtractor.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Native Windows Event Log (.evtx) reader. Pure Python, standard "
                    "library only.",
        epilog="Author: {}\nLicense: {}".format(__author__, __license__))
    parser.add_argument("-V", "--version", action="version", version=_CREDIT)
    sub = parser.add_subparsers(dest="cmd", metavar="SUBCOMMAND")

    p_info = sub.add_parser("info", help="file header, chunk map and CRC32 validation")
    add_input_args(p_info)
    p_info.add_argument("--limit", type=int, default=40,
                        help="chunk rows printed, 0 for all (default 40)")
    p_info.set_defaults(func=cmd_info)

    p_dump = sub.add_parser("dump", help="decode records to a table, XML, CSV or JSON")
    add_input_args(p_dump)
    add_filter_args(p_dump)
    p_dump.add_argument("--limit", type=int, default=50,
                        help="rows printed, 0 for all (default 50). Does not affect files")
    p_dump.add_argument("--sort", choices=("time", "record", "none"), default="time",
                        help="row order (default time)")
    p_dump.add_argument("--print-xml", action="store_true",
                        help="print the reconstructed XML instead of a table")
    p_dump.add_argument("--xml", metavar="FILE", help="write all matches as XML")
    p_dump.add_argument("--csv", metavar="FILE", help="write all matches as CSV")
    p_dump.add_argument("--json", metavar="FILE", help="write all matches as JSON")
    p_dump.set_defaults(func=cmd_dump)

    p_stats = sub.add_parser("stats", help="what is in this log, by volume")
    add_input_args(p_stats)
    add_filter_args(p_stats)
    p_stats.add_argument("--top", type=int, default=20, help="rows per table (default 20)")
    p_stats.add_argument("--csv", metavar="FILE", help="write the event ID histogram")
    p_stats.add_argument("--limit", type=int, default=0, help=argparse.SUPPRESS)
    p_stats.set_defaults(func=cmd_stats)

    p_bridge = sub.add_parser(
        "evtxecmd", help="emit an EvtxECmd compatible CSV for CQUSNCorrelate")
    add_input_args(p_bridge)
    add_filter_args(p_bridge)
    p_bridge.add_argument("--out", "-o", metavar="FILE",
                          help="output CSV. Omit to write to stdout")
    p_bridge.add_argument("--csv", metavar="FILE", help=argparse.SUPPRESS)
    p_bridge.add_argument("--sessions-only", action="store_true",
                          help="keep only the logon events session correlation needs")
    p_bridge.add_argument("--limit", type=int, default=0, help=argparse.SUPPRESS)
    p_bridge.set_defaults(func=cmd_evtxecmd)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        credit()
        parser.print_help()
        return 1

    init_color(args.color)
    credit()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(paint("\n[!] interrupted", "warn"), file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
