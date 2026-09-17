# CQUSNCorrelate

`CQUSNCorrelate` is a single-file forensic CLI written in pure Python (stdlib only) that answers one investigative question at a time over raw NTFS artifacts. Where [`CQUSNDeepAnalyzer`](../CQUSNDeepAnalyzer) builds a full interactive report, this tool runs a single focused correlation and prints a table, which is what an analyst reaches for at the start of a case.

It reuses the parsers from `CQUSNDeepAnalyzer`, so the binary formats, path reconstruction and FRN conventions live in exactly one place.

**CQURE / Paula Januszkiewicz · Apache License 2.0**

## Inputs

| File | Required | What it provides |
|---|---|---|
| Raw `$UsnJrnl:$J` (binary) | YES, except for `si-vs-fn` | File system change stream (who/what/when) |
| Raw `$MFT` (binary) | YES for `si-vs-fn`, optional elsewhere | `$SI` and `$FN` timestamps, and full path reconstruction |
| EVTX CSV from Eric Zimmerman's `EvtxECmd` | YES for `sessions` | Logon sessions (4624 with 4634/4647) |

Acquiring `$J` and `$MFT`: any forensic tool able to read the raw ADS stream (`$Extend\$UsnJrnl:$J`) and NTFS metadata (`$MFT`). Examples: `ntfscat`, KAPE, FTK Imager, RawCopy.

Acquiring EVTX CSV:
```bash
EvtxECmd.exe -f Security.evtx --csv outdir --csvf Security.csv
```

`sessions` needs **4624** plus **4634/4647**. Real `EvtxECmd` payloads carry `TargetLogonId`, which is what separates concurrent sessions for one user. Without it the tool degrades to per-user pairing and says so in the output.

## Outputs

| Flag | Format | Use case |
|---|---|---|
| (default) | Coloured table on stdout | Triage at the console |
| `--csv FILE` | CSV | Excel / Timeline Explorer / pivoting |
| `--json FILE` | JSON array | Further programmatic processing |

The console shows a readable subset of columns. The files carry **every** field, including the precise numerics (`delta_s`, `lifetime_s`, `nearest_write_s`) and the raw USN reason lists.

## Quick start

```bash
# the bundled demo data, all five correlations
run-demo.cmd

# dropped AND executed
py -3 CQUSNCorrelate.py exec-evidence --input samples/demo_J.bin --unpaired

# created and then deleted, shortest-lived first
py -3 CQUSNCorrelate.py lifecycle --input samples/demo_J.bin

# who was logged on while the files appeared
py -3 CQUSNCorrelate.py sessions --input samples/demo_J.bin --evtx samples/demo_evtx.csv

# timestamps touched with no write beside them
py -3 CQUSNCorrelate.py metadata-changed --input samples/demo_J.bin

# $SI against $FN, the timestomp check
py -3 CQUSNCorrelate.py si-vs-fn --mft samples/demo_MFT.raw
```

Use `py -3`, not bare `python`. On most Windows machines `python` resolves to 2.7 and dies on the first f-string.

## Correlations

| Subcommand | Question it answers | Needs |
|---|---|---|
| `exec-evidence` | Which binaries were dropped here and then actually ran? | `$J` |
| `lifecycle` | What was created and then deleted, and how long did it survive? | `$J` |
| `sessions` | Which logon session was open when these files appeared? | `$J` + EVTX CSV |
| `metadata-changed` | Whose timestamps or ACLs changed without the content changing? | `$J` |
| `si-vs-fn` | Which files have `$SI` timestamps inconsistent with `$FN`? | `$MFT` |

### exec-evidence
A Prefetch file proves an executable ran. Pairing its creation with the creation of the binary itself gives the strongest sequence available without EVTX: the binary appeared on disk, then it was executed. Also reports binaries that were dropped and never ran, and Prefetch entries whose binary predates the journal.

### lifecycle
Groups by FRN and reports the first `FILE_CREATE` against the last `FILE_DELETE`. Sorted shortest-lived first, because seconds-long files are staging, drop-and-clean and temp payloads. FRN is formatted `entry-seq`, and the sequence number increments when NTFS reuses an MFT entry, so the key does not collide across two different files.

### sessions
Reconstructs logon sessions by pairing 4624 with 4634/4647 on `TargetLogonId`, then attributes every file creation to the sessions open at that instant. A 4624 with no matching logoff is treated as open indefinitely and will match every later creation, so the tool warns and names the affected sessions rather than over-attributing silently.

### metadata-changed
Reports USN metadata reasons (`BASIC_INFO_CHANGE`, `SECURITY_CHANGE`, `EA_CHANGE` and six more) and, for each, whether the file's **content** was written near that moment. Metadata moving on its own is the footprint `SetFileTime` leaves in the journal. Asking merely whether a file was ever written is useless, because creating a file writes it, so proximity is what is measured, with `--window` controlling how close counts as related.

### si-vs-fn
Compares `$STANDARD_INFORMATION` (0x10) against `$FILE_NAME` (0x30) for every MFT record. Windows updates `$SI` freely, but `$FN` is only rewritten on create, rename, move or hard link. Tools that backdate a file write `$SI` and leave `$FN` alone, so `$SI` earlier than `$FN` is a state NTFS does not reach on its own. Also flags `$SI` values landing exactly on a whole second, which hand-set times do and real file system activity rarely does.

`metadata-changed` and `si-vs-fn` are a pair: the first finds the footprint in the journal, the second confirms it in the MFT.

## CLI flags

### Common to all subcommands
| Flag | Meaning |
|---|---|
| `--input J.bin` | raw `$UsnJrnl:$J` |
| `--mft MFT.raw` | raw `$MFT`, enables full path reconstruction |
| `--max-records N` | stop parsing `$J` after N records, for fast iteration |
| `--include-path SUBSTR` / `--exclude-path SUBSTR` | path filters |
| `--skip-directories` | ignore records whose attributes say DIRECTORY |
| `--limit N` | rows printed, `0` for all (default 50). Does not affect `--csv` |
| `--csv FILE` / `--json FILE` | full result set to file |
| `--color auto\|always\|never` | colour output. `auto` is on for a terminal, off when piped. `NO_COLOR` honoured |
| `--quiet` | suppress parse progress on stderr |
| `--version` | tool, version, author, license |

### exec-evidence
| Flag | Meaning |
|---|---|
| `--max-delta SECONDS` | only pairs where create to prefetch is within SECONDS |
| `--unpaired` | also list created-but-never-run and ran-but-not-created |

### lifecycle
| Flag | Meaning |
|---|---|
| `--min-lifetime` / `--max-lifetime SECONDS` | bound how long the file survived |
| `--ext .exe .dll` | restrict to these extensions |
| `--sort shortest\|longest\|created` | row order, default shortest-lived first |

### sessions
| Flag | Meaning |
|---|---|
| `--evtx CSV` | required, `EvtxECmd` export |
| `--per-file` | one row per created file with its open sessions |
| `--only-active` | hide sessions that created no files |

### metadata-changed
| Flag | Meaning |
|---|---|
| `--kind REASON ...` | restrict to specific USN metadata reasons |
| `--no-data-change` | only changes with no nearby write, the timestomp shape |
| `--window SECONDS` | how close a write must be to count as related, default 60 |

### si-vs-fn
| Flag | Meaning |
|---|---|
| `--mft MFT.raw` | required |
| `--only any\|si-lt-fn\|usec-zeros\|both\|all` | which records to report, default `any` |
| `--min-delta SECONDS` | only where the `$SI` to `$FN` gap is at least SECONDS |
| `--baseline FILE` | extra path patterns to suppress, one per line |
| `--no-baseline` | disable the built-in Windows Update / WinSxS suppression |

## Demo data

`samples/` holds a synthetic but coherent intrusion, "Operation Amber", so every correlation has something to find and the expected answers are known before you run anything. The planted scenario is written out in `samples/demo_README.md`.

Regenerate at any time:
```bash
py -3 make_demo_data.py samples/
```

## Requirements

- Windows, and Python 3.8 or later. No third party packages.
- `CQUSNDeepAnalyzer.py` must be reachable. The tool looks beside itself, then in the parent, then in a sibling `CQUSNDeepAnalyzer/` folder, which is the layout of this repository. Cloning the whole `Forensic` folder is enough. Taking only this folder means copying `CQUSNDeepAnalyzer.py` next to `CQUSNCorrelate.py`.

## Forensic limitations

- **Prefetch matching is by executable name.** The Prefetch filename hash encodes the binary's full path, but it is not recomputed here, so two same-named binaries in different directories are indistinguishable. Read a pair as "a binary by this name ran", not "this exact path ran".
- **Open logon sessions over-attribute.** A 4624 with no logoff in the supplied log matches every later file creation. The tool warns, but the judgement is yours.
- **`--window` is a heuristic.** A timestomp performed immediately after a legitimate write will look related. Lower the window when the timeline is dense.
- **Baseline suppression hides real findings too.** `si-vs-fn` suppresses Windows Update, WinSxS, .NET and Defender paths by default, because they carry benign timestamp anomalies in bulk. Anything planted there is suppressed with them. Run `--no-baseline` when it matters.
- **USN journals wrap.** Absence of a record is not evidence of absence of the event.

## Roadmap

- Prefetch path-hash computation, to turn name matching into path matching
- `$LogFile` corroboration for deleted-file lifecycles
- Session attribution across a `$J` that spans a reboot
