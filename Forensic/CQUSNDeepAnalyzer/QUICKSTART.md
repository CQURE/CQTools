# Quickstart - 30 seconds to a report

## Step 0: ready-made sample and example report

The `examples/` directory contains a full set for an instant preview without your own data:

| File | What it is |
|---|---|
| `sample_usn_J.bin` | synthetic, fully anonymized `$UsnJrnl:$J` sample (2376 records) |
| `sample_evtx.csv` | example EVTX (EvtxECmd format, demonstration data) |
| `sample_rules.json` | example YARA-lite rules |
| `sample_baseline.txt` | example path baseline |
| `sample_report.html` | **ready-made HTML report** generated from the above (open in a browser) |
| `sample_super_timeline.jsonl` | ready-made Plaso/Timesketch super-timeline |

The sample is generated procedurally by `tools/make_synthetic_J.py`: zero real file names, hosts, or users. It contains a burst of >1000 events/min, a mass-rename wave, ransomware extensions, and suspicious `.exe` files in `Temp\`, so the report shows the full set of findings.

To regenerate the report yourself:

```bash
python tools/make_synthetic_J.py examples/sample_usn_J.bin
python CQUSNDeepAnalyzer.py \
  --input examples/sample_usn_J.bin \
  --evtx examples/sample_evtx.csv \
  --rules examples/sample_rules.json \
  --html examples/sample_report.html \
  --jsonl examples/sample_super_timeline.jsonl \
  --plotly-path vendor/plotly.min.js
```

## Step 1: unpack and check the environment

```bash
python --version   # 3.7+
```

No `requirements.txt`. No installation. Pure stdlib.

## Step 2: minimal report (USN only)

```bash
python CQUSNDeepAnalyzer.py \
  --input your_copy_J.bin \
  --html report.html \
  --plotly-path vendor/plotly.min.js
```

Open `report.html` in a browser. That's it.

## Step 3: full pipeline (USN + MFT + EVTX)

```bash
# First generate the EVTX CSV (one-off, requires EvtxECmd):
EvtxECmd.exe -f Security.evtx --csv outdir --csvf Security.csv

# Then:
python CQUSNDeepAnalyzer.py \
  --input partition_2_UsnJrnl_J.bin \
  --mft MFT.raw \
  --evtx outdir/Security.csv \
  --html report.html \
  --csv timeline.csv \
  --json full.json \
  --jsonl super_timeline.jsonl \
  --plotly-path vendor/plotly.min.js
```

## Most common flags

| What I want to do | Flag |
|---|---|
| Make the table show all rows (not just 1000) | `--max-html-rows 0` |
| Only HIGH/CRITICAL in the console and report | `--min-severity high` |
| Limit to users / windows | `--include-path "users\\"` |
| Mute Windows Update noise from timestomping | (ON by default, disable with `--no-baseline`) |
| Add your own YARA-lite rules | `--rules examples/sample_rules.json` |
| Mute specific paths | `--baseline examples/sample_baseline.txt` |
| Only the first 10000 records (quick tests) | `--max-records 10000` |

## What you get in the HTML report

1. **Hero** with statistics (records, critical, elevated, max burst, time span)
2. **Anomaly strip** below the hero - findings markers on the timeline
3. **Findings cards** with sparklines, severity badges, EVTX + Prefetch context
4. **6 Plotly charts** (brushable timeline, clickable heatmap, reasons area, sankey, extensions, treemap drill-down)
5. **Records table** with multi-filters (text, reason, extension, date), virtual scrolling, CSV export, drill-down modal on click

## What you get in the JSONL

A Plaso/Timesketch super-timeline. Import:

```bash
# Timesketch CLI
tsctl importer --sketch_id 1 --timeline_name "case-name" \
  --file super_timeline.jsonl

# Or straight into psort (Plaso):
psort.py -o l2tcsv -w timeline.csv super_timeline.jsonl
```

## Artifact acquisition

The most common ways to obtain the raw files from a live system / image:

| Artifact | Tool |
|---|---|
| `\$Extend\$UsnJrnl:$J` | KAPE (target `UsnJournal`), FTK Imager, ntfscat |
| `\$MFT` | KAPE (target `MFT`), FTK Imager, ntfscat |
| `Security.evtx` | live: `C:\Windows\System32\winevt\Logs\Security.evtx`; image: KAPE target `EventLogs` |

KAPE one-liner:
```bash
kape.exe --tsource C: --tdest output --target USNJournal,MFT,EventLogs
EvtxECmd.exe -d output\C\Windows\System32\winevt\Logs --csv output\evtx_csv
```

## Diagnostics

Something not showing up? Headless probe:

```bash
node tools/probe_report.js report.html
# Checks: Plotly.newPlot calls, JS errors, DOM stats, table vt rendered rows
```

Full documentation: `README.md`, change history: `TODO.md`.
