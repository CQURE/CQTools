# CQUSNDeepAnalyzer

`CQUSNDeepAnalyzer` is a single-file forensic CLI tool written in pure Python (stdlib only + Plotly for charts) that parses raw NTFS artifacts and generates a rich, interactive HTML report with behavioral analysis and event attribution.

**CQURE / Paula Januszkiewicz · Apache License 2.0**
**CQURE / Marcin Kozłowski · Apache License 2.0**

## Inputs

| File | Required | What it provides |
|---|---|---|
| Raw `$UsnJrnl:$J` (binary) | YES | File system change stream (who/what/when) |
| Raw `$MFT` (binary) | NO (optional) | Full paths + SI/FN timestamps + timestomping detection + ADS + MOTW |
| EVTX CSV from Eric Zimmerman's `EvtxECmd` | NO (optional) | Correlation with event logs (logon, process create, audit clear, service install, user create) |

Acquiring `$J` and `$MFT`: a forensic tool capable of reading the raw ADS stream (`$Extend\$UsnJrnl:$J`) and NTFS metadata (`$MFT`). Examples: `ntfscat`, KAPE, FTK Imager.

Acquiring EVTX CSV:
```bash
EvtxECmd.exe -f Security.evtx --csv outdir --csvf Security.csv
```

## Outputs

| Flag | Format | Use case |
|---|---|---|
| `--csv FILE` | CSV timeline | Excel / Timeline Explorer |
| `--json FILE` | Full JSON dump (records + findings) | Further programmatic processing |
| `--html FILE` | Interactive HTML report (Plotly inline) | Main deliverable for the analyst |
| `--jsonl FILE` | Plaso/Timesketch JSONL super-timeline | Import into Timesketch / `psort.py` |

At least one output flag is required.

## Quick start

```bash
# Minimal case (USN only, HTML report)
python CQUSNDeepAnalyzer.py \
  --input J.bin \
  --html report.html \
  --plotly-path vendor/plotly.min.js

# Full pipeline (USN + MFT + EVTX, all outputs)
python CQUSNDeepAnalyzer.py \
  --input J.bin \
  --mft MFT.raw \
  --evtx Security_evtxecmd.csv \
  --csv timeline.csv \
  --json report.json \
  --html report.html \
  --jsonl super_timeline.jsonl \
  --plotly-path vendor/plotly.min.js
```

## Detectors

| Category | Findings |
|---|---|
| USN behavioral | burst, mass rename, mass delete, ransomware-extension, suspicious staging |
| MFT timestamps | timestomping `$SI<$FN`, timestomping `usec_zeros` (with `--baseline` noise filter) |
| MFT streams | ADS observed, ADS suspicious (non-benign names) |
| MFT MOTW | MOTW observed, executable from Internet (with download URL) |
| YARA-lite | 12 built-in file-name rules (Mimikatz, LSASS dump, vssadmin, PsExec, Cobalt Strike, miners, ransomware families, recon tools, PowerShell offensive, webshells) |
| Anomaly | new extensions outliers (early-stage ransomware without relying on the family name) |
| Prefetch | executables observed, suspicious executable (cross-match YARA-lite x Prefetch entries) |
| EVTX standalone | 1102 audit clear, 4720 user create, 4732/4756 added to admin group, 7045 service install, 4698 scheduled task, 1100 eventlog shutdown |
| Enrichment | per high/critical finding, attached **EVTX context** (+/-2 min) and **Prefetch context** (+/-5 min) |

## HTML report

- **Anomaly strip** below the hero with clickable findings markers
- **Sparklines** in each finding card (shape of events +/-15 min around the finding)
- **6 Plotly charts:**
  - Activity timeline (brushable, drag -> filters the table)
  - Hour x day heatmap (clickable, click -> filters the table)
  - Reasons stacked area over time
  - Sankey reason -> extension -> path bucket
  - Top file extensions (colored by risk class)
  - Path treemap with drill-down and pathbar
- **Virtualized 323k+ table** with multi-filters (text, reason multi-select, extension multi-select, date range), sorting, per-row quick actions (F=FRN, P=parent, .ext)
- **FRN drill-down modal** - click a row -> mini SVG timeline + list of all events for that file
- **Cross-filter banner** - a chart action sets the table filters
- **Filtered CSV export** from any filter state
- **Light/dark mode** - toggle (sun/moon) in the header, dark by default, choice remembered in `localStorage` per file. Switches the whole UI and re-styles all 6 Plotly charts.
- **Section navigation bar** - a fixed vertical bar near the right edge (dots + labels on hover), click = smooth jump to a section, scrollspy highlights the active section. Built from the sections actually present.
- **Keyboard shortcuts:** `/` focus search, `Esc` clear/blur

## CLI flags

### Inputs
| Flag | Default | Description |
|---|---|---|
| `--input PATH` | required | Raw `$UsnJrnl:$J` |
| `--mft PATH` | none | Raw `$MFT` for full paths and MFT findings |
| `--evtx PATH` | none | EVTX CSV (EvtxECmd format) for EVTX correlation |
| `--rules PATH` | none | JSON with additional YARA-lite rules (combined with built-ins) |
| `--baseline PATH` | none | File with additional path patterns for the timestomping filter |

### Outputs
| Flag | Description |
|---|---|
| `--csv PATH` | USN timeline CSV |
| `--json PATH` | Full JSON dump |
| `--html PATH` | Interactive HTML report |
| `--jsonl PATH` | Plaso/Timesketch JSONL super-timeline |
| `--plotly-path PATH` | Location of `plotly.min.js` (default `vendor/plotly.min.js`) |
| `--html-title STR` | Report title |
| `--max-html-rows N` | Row limit in the HTML table (default 1000, 0 = all) |
| `--no-charts` | HTML without charts (debug) |

### Filters and detector parameters
| Flag | Default | Description |
|---|---|---|
| `--max-records N` | none | Stops parsing after N records (for iteration) |
| `--include-path STR` | none | Substring filter (case-insensitive) |
| `--exclude-path STR` | none | Substring exclude filter |
| `--burst-window N` | 60 | Burst detection window in seconds |
| `--min-severity LVL` | info | Severity filter for the report (info/low/medium/high/critical) |
| `--no-baseline` | off | Disables built-in Windows Update / WinSxS / .NET / Defender patterns |
| `--no-builtin-rules` | off | Disables built-in YARA-lite rules |
| `--new-ext-late-fraction` | 0.3 | How late in the timeline an extension must first appear |
| `--new-ext-min-count` | 10 | Minimum event count for a late-emerging extension |
| `--evtx-window N` | 120 | EVTX context window around a finding (seconds) |
| `--no-prefetch` | off | Disables Prefetch detection |
| `--prefetch-window N` | 300 | Prefetch context window around a finding |
| `--quiet` | off | Do not print findings to the console |

## Configuration file formats

### `--rules FILE` (JSON)

```json
[
  {
    "name": "Internal SOC rule",
    "patterns": ["customtool.exe", "evil.dll"],
    "severity": "high",
    "category": "custom",
    "description": "Internal indicator",
    "references": ["https://internal-wiki/..."]
  }
]
```

### `--baseline FILE` (text)

```
# Custom patterns for $TEAM environment
$recycle.bin\
windows\fonts\
program files\notepad++\
```

One line = one substring matched case-insensitively against the reconstructed path. `#` at the start of a line denotes a comment.

### `--evtx FILE` (CSV)

Eric Zimmerman's EvtxECmd format or compatible. Required columns: `TimeCreated`, `EventId`. Optional: `Provider`, `Channel`, `UserName`, `ExecutableInfo`, `Payload`, `SourceFile`.

Example in `examples/sample_evtx.csv`.

## Requirements

- Python 3.7+
- `vendor/plotly.min.js` (for interactive charts; without it the HTML report shows only the structure, no visualizations)
- No other Python dependencies (pure stdlib)

Optional, for diagnostics / regression:
- Node.js 18+ (scripts in `tools/` use the Chrome DevTools Protocol)
- Microsoft Edge or Google Chrome (headless screenshots)

## Tools (diagnostic)

| File | What it does |
|---|---|
| `tools/probe_report.js` | CDP probe of the HTML report; hooks `Plotly.newPlot`, reports the number of rendered charts, DOM stats, JS errors |
| `tools/test_frn_modal.js` | Simulates a table row click, verifies that the FRN drill-down modal opens |
| `tools/screenshot_records.js` | Headless screenshot of the Records section |
| `tools/screenshot_section.js` | Headless screenshot of any HTML section (by `id`) |
| `tools/validate_report_js.js` | Static validation of the inline JS in `vm` (without Plotly execution) |
| `tools/compare_paths.py` | Cross-check of our CSV against MFTECmd ground truth (on real SDB001 data it reached a 99.7% match) |
| `tools/make_synthetic_J.py` | Generator of a synthetic `$J` for local tests |
| `tools/verify_theme.js` | Headless test of the light/dark toggle: dark screenshot, click toggle, verify DOM + Plotly state, light screenshot, PASS/FAIL verdict |
| `tools/verify_nav.js` | Headless test of the section navigation bar: item count + labels, item click, verify scroll and scrollspy, screenshot, PASS/FAIL verdict |

## Architecture (1-screen overview)

```
parse_usn_records ┐
                  ├─→ reconstruct_paths ─→ analyze (5 USN findings)
parse_mft_records ┘                ↓
       ↓                    detect_*_findings (timestomping, ADS, MOTW)
build_mft_path_map          detect_filename_rule_findings (YARA-lite)
                            detect_new_extensions_findings
                            detect_prefetch_executions
load_evtx_csv ──→ detect_evtx_standalone_findings
                  enrich_findings_with_evtx_context (±2 min)
                  enrich_findings_with_prefetch_context (±5 min)
                            ↓
                         findings → severity_allowed filter
                            ↓
                  write_csv / write_json / write_html / write_jsonl
```

A single module, ~4 kLOC, pure Python stdlib. The HTML report embeds Plotly.min.js inline (self-contained, ~4.5 MB), so it works offline in any browser.

## Forensic limitations

- The USN journal does not contain full paths - only the parent FRN. Without `--mft`, paths are best-effort from the journal (typically ~30-40% of records have a full path from USN alone).
- File identifiers in `USN_RECORD_V3` (128-bit) are truncated to 64 bits for V2 compatibility. This has no practical impact on typical volumes.
- The parser is corruption-tolerant: sparse `$J` streams (typical for acquisition artifacts) resynchronize after 8 bytes. It never aborts parsing.
- The first 16 `$MFT` entries (NTFS-reserved: `$MFT`, `$LogFile`, `.`, etc.) are filtered out of findings so they do not pollute the timestomping/ADS signals.

## Roadmap (still to do)

- Full binary Prefetch parser (`.pf`) with Xpress Huffman decompression for Win10/11 → run timestamps + loaded DLLs
- Amcache parser (`Amcache.hve`) → a third independent route to execution evidence
- Resident data dump from `$MFT` → extracting configs of small files (<700 B)
- Streaming USN parser for journals `>2 GB`
- `$LogFile` parser (NTFS transactional log, finer-grained than USN)
- Sigma rules engine (instead of / alongside YARA-lite)

Full change history: `TODO.md` sections 5.1-5.18.
