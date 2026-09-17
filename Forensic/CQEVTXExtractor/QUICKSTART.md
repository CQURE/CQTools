# CQEVTXExtractor, quick start

Author: Paula Januszkiewicz | CQURE
License: Apache License 2.0

## 1. Run the demo

```powershell
.\run-demo.cmd
```

That reads `samples\demo_Security.evtx`, a real .evtx file written by
`make_demo_data.py`, and walks all four subcommands.

Use `py -3`, not `python`. On most Windows machines bare `python` is 2.7 and
dies on the first f-string.

## 2. The four questions

```powershell
:: what is this file, and is it intact
py -3 CQEVTXExtractor.py info  -i samples\demo_Security.evtx

:: what is in it, by volume
py -3 CQEVTXExtractor.py stats -i samples\demo_Security.evtx

:: the timeline
py -3 CQEVTXExtractor.py dump  -i samples\demo_Security.evtx --limit 0

:: hand the logons to CQUSNCorrelate
py -3 CQEVTXExtractor.py evtxecmd -i samples\demo_Security.evtx --sessions-only -o amber.csv
```

## 3. Your own logs

The live logs are held open by the Event Log service, and `Security` needs
elevation, so export a copy first:

```powershell
wevtutil epl Security C:\cases\Security.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\cases\Sysmon.evtx
```

Then point the tool at the copy, a whole folder, or a glob:

```powershell
py -3 CQEVTXExtractor.py info  -i C:\cases\Security.evtx
py -3 CQEVTXExtractor.py stats -i C:\cases\
py -3 CQEVTXExtractor.py dump  -i C:\cases\Security.evtx --event-id 4624 4625 4720 4732
```

From a disk image, any tool that reads the raw file works: KAPE, FTK Imager,
RawCopy. Nothing needs the Event Log service to be running.

## 4. Common investigative starts

```powershell
:: who logged on, and who failed
py -3 CQEVTXExtractor.py dump -i Security.evtx --event-id 4624 4625 --csv logons.csv

:: accounts created and added to groups
py -3 CQEVTXExtractor.py dump -i Security.evtx --event-id 4720 4728 4732 4756

:: services installed and scheduled tasks created
py -3 CQEVTXExtractor.py dump -i Security.evtx --event-id 4697 4698 4699 4702

:: anything naming a suspect binary, with the full record
py -3 CQEVTXExtractor.py dump -i C:\cases\ --contains rclone.exe --print-xml

:: what happened in a two hour window
py -3 CQEVTXExtractor.py dump -i C:\cases\ --after 2026-03-17T10:00:00Z --before 2026-03-17T12:00:00Z

:: was the log cleared
py -3 CQEVTXExtractor.py dump -i Security.evtx --event-id 1102 --print-xml
```

## 5. Reading `info` before you trust anything

```powershell
py -3 CQEVTXExtractor.py info -i C:\cases\Security.evtx
```

| What it says | What it means |
|---|---|
| `dirty flag: set` | the log was not closed cleanly, so the header's chunk count lags. The tool scans for chunks anyway and says so |
| `chunks on disk` above the header count | the extra chunks hold the newest events, which are usually the ones the case is about |
| `hdr crc BAD` or `rec crc BAD` | in the last chunk of a dirty log this is expected. Anywhere else the bytes no longer match what the service wrote |

A valid checksum is not proof of integrity. Anyone who can edit a record can
recompute a CRC32. `info` proves damage, not the absence of it.

Requires Windows and Python 3.8 or later. No third party packages.
