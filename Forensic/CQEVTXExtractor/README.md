# CQEVTXExtractor

**CQURE | Paula Januszkiewicz | Apache License 2.0**

A native Windows Event Log (`.evtx`) reader in pure Python. Standard library
only, no third party packages, no .NET.

Windows event logs are not XML on disk. A `.evtx` file is a 4 KiB header
followed by 64 KiB chunks, and each chunk holds records encoded in Binary XML:
a token stream with a per chunk template table, so the repeated skeleton of an
event is stored once and every record after it carries only the values that
differ. Reading the file means implementing that format, not parsing text.

That is what this tool does. It reads the file, verifies the three CRC32
checksums the format carries, reconstructs the XML, and writes what an analyst
actually wants: a timeline, a histogram, or a CSV the rest of the CQURE
forensic toolkit already consumes.

## Why native matters

- **Nothing to install on the evidence machine.** Python 3.8 and this one file.
- **No .NET dependency** to justify to whoever owns the box.
- **It reads the file, not the service.** `Get-WinEvent` and `wevtutil` ask the
  Event Log service to render a log. This reads the bytes, so it works on a
  file pulled off a dead disk, and it reports the checksums and the dirty flag
  rather than hiding them.
- **No lossy console hop.** `wevtutil qe ... /f:xml` writes through the console
  codepage, so a log holding `U+00C5 U+00A0` arrives as the bytes `C5 A0` and
  any UTF-8 reader silently merges them into `U+0160`. Polish diacritics
  degrade to ASCII lookalikes the same way. This tool decodes the UTF-16 on
  disk and hands you exactly that.

## Verification

The parser is checked against Windows itself. Every record of every log is
rendered by `Get-WinEvent` (the same `EvtRender` underneath, but taken as .NET
strings and written as UTF-8 so nothing is lost), parsed by the same
ElementTree code as this tool's output, and compared field by field and payload
item by payload item in document order.

| Log | Records | Result |
|---|---|---|
| `Application.evtx` | 35,153 | exact match |
| `System.evtx` | 27,978 | exact match |
| `Security.evtx` | 22,707 | exact match |
| `Windows PowerShell.evtx` | 4,182 | exact match |
| `Microsoft-Windows-WinRM/Operational` | 1,058 | exact match |
| `Microsoft-Windows-PowerShell/Operational` | 471 | exact match |
| `samples/demo_Security.evtx` | 25 | exact match |

Every System field, every `EventData` item, every timestamp to 100 ns.

## Quick start

```bash
run-demo.cmd
```

```bash
# what am I holding, and is it intact
py -3 CQEVTXExtractor.py info -i samples/demo_Security.evtx

# what is in it
py -3 CQEVTXExtractor.py stats -i samples/demo_Security.evtx

# the timeline
py -3 CQEVTXExtractor.py dump -i samples/demo_Security.evtx --limit 0

# one question
py -3 CQEVTXExtractor.py dump -i samples/demo_Security.evtx --event-id 4624 4625

# the full record, as Windows would show it
py -3 CQEVTXExtractor.py dump -i samples/demo_Security.evtx --contains mimi.exe --print-xml

# hand the logons to the sibling tool
py -3 CQEVTXExtractor.py evtxecmd -i samples/demo_Security.evtx --sessions-only -o amber.csv
```

Use `py -3`, not bare `python`. On most Windows machines `python` resolves to
2.7 and dies on the first f-string.

## Subcommands

| Subcommand | Question it answers |
|---|---|
| `info` | What is this file, is it intact, and was it closed cleanly? |
| `dump` | Show me the records, filtered, as a table or XML or CSV or JSON |
| `stats` | What is in this log, by volume, and when was it busy? |
| `evtxecmd` | Give me an EvtxECmd compatible CSV for `CQUSNCorrelate sessions` |

### info

File header, chunk map, and all three CRC32 checksums the format carries: the
file header checksum, each chunk's header checksum, and each chunk's record
area checksum. Also reports the dirty and full flags.

Two things it deliberately does not trust:

- **The header's chunk count.** A log that was not closed cleanly routinely has
  more chunks on disk than the header admits to, and those trailing chunks hold
  the most recent events, which are usually the ones the case is about. Chunks
  are found by scanning, and the discrepancy is reported.
- **A CRC mismatch as proof of tampering.** In the last chunk of a dirty log it
  is expected, because the checksum is written on close. Anywhere else it means
  the bytes no longer match what the service wrote. The tool says which.

### dump

Decodes records and prints a table, or writes them out. `--print-xml` gives the
reconstructed XML, which is what you paste into a report.

### stats

Event ID histogram by provider, provider and level breakdowns, and volume by
hour as a bar chart. The first question on any unfamiliar log.

### evtxecmd

Emits the CSV contract `CQUSNCorrelate sessions` consumes, so the toolkit runs
end to end without EvtxECmd. `--sessions-only` keeps just the logon events that
correlation needs (4624, 4634, 4647, 4625, 4648, 4672, 4776, 4778, 4779).

## CLI flags

### Common
| Flag | Meaning |
|---|---|
| `--input` / `-i` | one or more `.evtx` files, a directory, or a glob |
| `--color auto\|always\|never` | colour output. `auto` is on for a terminal, off when piped. `NO_COLOR` honoured |
| `--quiet` / `-q` | suppress progress on stderr |
| `--version` / `-V` | tool, version, author, license |

### Filters, on `dump`, `stats` and `evtxecmd`
| Flag | Meaning |
|---|---|
| `--event-id` / `-e` | keep only these event IDs |
| `--provider` / `-p` | provider name contains any of these |
| `--channel` | channel contains any of these |
| `--computer` | computer name contains any of these |
| `--level` | Critical, Error, Warning, Information or Verbose |
| `--user` | any user or account field contains this |
| `--record-id` | keep only these record IDs |
| `--after` / `--before` | ISO 8601 time bounds |
| `--contains` | rendered XML contains ALL of these, case insensitive |
| `--regex` | rendered XML matches this regular expression |
| `--max-records` | stop after N matches, for fast iteration |

### dump
| Flag | Meaning |
|---|---|
| `--limit N` | rows printed, `0` for all (default 50). Does not affect files |
| `--sort time\|record\|none` | row order (default time) |
| `--print-xml` | print reconstructed XML instead of a table |
| `--xml` / `--csv` / `--json FILE` | write all matches to a file |

### stats
| Flag | Meaning |
|---|---|
| `--top N` | rows per table (default 20) |
| `--csv FILE` | write the event ID histogram |

### evtxecmd
| Flag | Meaning |
|---|---|
| `--out` / `-o FILE` | output CSV. Omit to write to stdout |
| `--sessions-only` | keep only the logon events session correlation needs |

## Getting a log to read

The live logs under `C:\Windows\System32\winevt\Logs` are held open by the
Event Log service and `Security.evtx` needs elevation, so copy one out first:

```powershell
wevtutil epl Security C:\cases\Security.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\cases\Sysmon.evtx
```

From an image, any tool that reads the raw file works: KAPE, FTK Imager,
RawCopy.

## Demo data

`samples/demo_Security.evtx` is a real `.evtx` file, written by
`make_demo_data.py` in the actual binary format, templates and checksums
included. Windows opens it in Event Viewer. It retells "Operation Amber", the
same intrusion described by the CQUSNCorrelate demo data, on the same host and
the same clock, so the two tools demonstrate together:

```bash
py -3 CQEVTXExtractor.py evtxecmd -i samples/demo_Security.evtx --sessions-only -o amber.csv
py -3 CQUSNCorrelate.py sessions --input samples/demo_J.bin --evtx amber.csv
```

Everything in the sample is invented. No real account, host or address appears.
The scenario and the expected answers are in `samples/demo_README.md`.

## Requirements

Windows, and Python 3.8 or later. No third party packages.

## Forensic limitations

- **Deleted records are not recovered.** This reads records the chunk framing
  still points at. Records in chunk slack, orphan chunks in unallocated space,
  and chunks whose CRC fails are reported by `info` but not carved.
- **A cleared log is a cleared log.** 1102 tells you it happened. What was in
  it before is not in this file.
- **Message strings are not resolved.** Windows composes the human readable
  message from the provider's resource DLL on the machine that has it
  installed. This reports the structured `EventData`, which is what an analyst
  should be reasoning over anyway, but it is not the Event Viewer sentence.
- **Timestamps are UTC as recorded.** No timezone is applied, and a host with a
  wrong clock produces a log with wrong timestamps that no reader can correct.
- **Trust the checksums, not the absence of one.** Anyone able to edit a record
  can recompute a CRC32. `info` proves damage, not integrity.

## Roadmap

- Carving records from chunk slack and unallocated space
- Provider message resolution from a supplied resource DLL
- `--jsonl` streaming output for very large logs
