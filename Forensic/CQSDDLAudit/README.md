# CQSDDLAudit

A security descriptor report for every service on a Windows system, including
the ones that have hidden themselves. Self contained: everything needed to run
lives in this folder.

Author: Paula Januszkiewicz | CQURE
License: Apache License 2.0

---

## Why services

SDDL is the only way to see service permissions at all. The Security tab has no
page for them, and `sc.exe sdshow` hands you a string with no interpretation.

More to the point, a service can hide from you. Denying `SERVICE_QUERY_STATUS`
(`LC`) removes it from enumeration, so `sc query`, `services.msc` and
`Get-Service` all report a machine that does not have it, while the service
keeps running exactly as before. The usual form is a Deny of `DCLC`, often
`DCLCWPDTSD`, aimed at Interactive, Service and Administrators at once, which
also blocks stopping, reconfiguring and deleting it.

It is a Deny ACE, not a rootkit. It needs no driver and no code.

The answer is not to ask the SCM. Every service is registered under
`HKLM\SYSTEM\CurrentControlSet\Services` regardless of its descriptor, and the
descriptor itself sits in the `Security` value of that key. `Collect-Sddl.ps1`
enumerates the registry and reads those values directly, so a service that
denies its own enumeration still appears, and the difference between the
registry list and the SCM list is itself a finding.

## Run it

```powershell
cd D:\CQTools\CQSDDLAudit
.\run-demo.cmd
```

That analyses the bundled sample collection, which contains a hidden service, a
NULL DACL service and an anti-tamper descriptor, so you can see each finding
without touching a real machine.

Against a real system, elevated:

```powershell
powershell -ExecutionPolicy Bypass -File Collect-Sddl.ps1 -OutFile services.csv
py -3 CQSDDLAudit.py services --input services.csv --html report.html --host $env:COMPUTERNAME
```

Use `py -3`, not `python`: on most machines bare `python` is 2.7 and dies on the
first f-string.

Run the collector elevated. Without administrative read on the Services hive
many `Security` values are unreadable, and a short collection looks like a clean
one. The script warns and counts what it could not read rather than staying
quiet about it.

## The six commands

```powershell
# 1. the service report, hidden services called out with a warning and an explanation
py -3 CQSDDLAudit.py services --input services.csv --html report.html

# 2. just the hidden ones
py -3 CQSDDLAudit.py services --input services.csv --only-hidden

# 3. one descriptor, every ACE in real order, canonical verdict
py -3 CQSDDLAudit.py decode --object-type service --sddl "D:(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)"

# 4. pattern findings with severity, across the whole collection
py -3 CQSDDLAudit.py risk --input services.csv --min-severity medium

# 5. who can actually stop this service, and which ACE decided?
py -3 CQSDDLAudit.py access --sddl "D:(D;;WP;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" `
                            --object-type service --token BA --want WP --explain

# 6. drift against a baseline, order aware
py -3 CQSDDLAudit.py diff --input services.csv --baseline baseline.csv
```

Add `--csv out.csv` or `--json out.json` to any of them. The console shows a
readable subset with long cells clipped; the files carry every field.

## What each one is for

| Command | Question it answers | Needs |
|---|---|---|
| `services` | Which services are hidden, weak or tamper-proofed? | collection CSV |
| `decode` | What does this descriptor actually say, in real ACE order? | one SDDL string |
| `order` | Which descriptors are in non-canonical order? | collection CSV |
| `generic` | Which entries can the Security tab not render at all? | collection CSV |
| `risk` | What should I look at first, and how bad is it? | collection CSV |
| `access` | Could this principal do this, and which ACE decided? | one SDDL string |
| `diff` | What changed since the baseline, including order? | two CSVs |

## Verdicts

| Verdict | Meaning |
|---|---|
| `HIDDEN` | Denies `SERVICE_QUERY_STATUS` to a principal that should be able to list it, or exists in the registry while SCM enumeration did not return it |
| `WEAK` | NULL DACL, or a broad principal holds `SERVICE_CHANGE_CONFIG`, `WRITE_DAC`, `WRITE_OWNER`, or start and stop as Everyone |
| `ANTI-TAMPER` | Denies stop, reconfigure, delete or repair to a principal that legitimately administers services |
| `ok` | Nothing matched |

`HIDDEN` gets its own warning block on the console: the ACE responsible, the
principal it targets, what that principal can no longer do, and what to run
next.

## False positives this deliberately does not raise

A permission tool nobody trusts is a permission tool nobody runs, so these are
excluded by design rather than left for the reader to filter:

- **Drivers.** Not returned by SCM enumeration under their own name, ever.
- **Per-user service templates** (`ServiceType` `0x50`/`0x60`, e.g. `OneSyncSvc`).
  The SCM enumerates their per-user instances, `OneSyncSvc_4a1f2`, never the
  template. On a stock Windows 11 install there are roughly two dozen of these,
  and every one of them would otherwise be reported as hidden.
- **Administrators and SYSTEM holding `WRITE_DAC` or `WRITE_OWNER`.** The default
  on virtually every object Windows ships.
- **A service holding rights over its own descriptor.** The `NT SERVICE\<name>`
  SID is derived from the name, so the tool computes it and recognises the
  self-grant instead of printing an unreadable `S-1-5-80-...` row.
- **Interactive or Authenticated Users holding start and stop.** Ordinary
  configuration on a large number of shipped services. Everyone and Anonymous
  holding it is still reported.
- **Denying Guests.** Hardening, not tampering. Windows ships it on the peer
  networking services.
- **`INHERIT_ONLY` generic rights on a service.** A service has no child objects,
  so the entry is inert. This is the second `TrustedInstaller` entry that the
  Security tab cannot draw, reported at `info` so you can see it without it
  competing with real findings.

## Object types matter

The same two-letter token means different things on different objects. `CC` is
`SERVICE_QUERY_CONFIG` on a service and `DS_CREATE_CHILD` on a directory object.
`FA` is `FILE_ALL_ACCESS` in the rights field and `FAILED_ACCESS` in the flags
field. `WD` is `WRITE_DAC` in rights and Everyone in the SID field.

Nothing is resolved by lookup alone. Every table is applied only to the field it
belongs to, and the rights tables are selected by `--object-type`. Pass it, or
rights are read with the file table and labelled unqualified.

## Other surfaces

Services are the first focus, but the collector and the analyzer both handle
files, directories and registry keys:

```powershell
.\Collect-Sddl.ps1 -SkipServices -Path 'C:\Program Files' -RegistryKey 'HKLM:\SOFTWARE' -Recurse -Depth 2
py -3 CQSDDLAudit.py generic --input services.csv --inherit-only
py -3 CQSDDLAudit.py order   --input services.csv
```

Note that file and registry rows are collected with `Get-Acl`, which reorders
ACEs. Ordering findings from that source are not reliable, and the collector
records the caveat in the `Notes` column of every row it writes that way.

## Contents

```
CQSDDLAudit.py      the analyzer
Collect-Sddl.ps1    the collector, registry first
run-demo.cmd        analyses the bundled sample collection
README.md           this file
QUICKSTART.md       the short version
LICENSE             Apache License 2.0
samples/
  demo_sddl.csv     a crafted collection, one of each finding
  demo_README.md    what is in it and why
```

## Requirements

- Windows for collection. Analysis is pure Python and runs anywhere.
- Python 3.12, invoked as `py -3`. No third-party packages.
- PowerShell 5.1 or later for the collector.
- Administrator rights for a complete collection.
