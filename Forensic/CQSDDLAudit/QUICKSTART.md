# CQSDDLAudit quickstart

## See it work, no admin, no real machine

```powershell
cd D:\CQTools\CQSDDLAudit
.\run-demo.cmd
```

The bundled collection contains nine services: two hidden, one with a NULL DACL,
two granting control to a broad principal, one anti-tamper, plus normal ones and
a driver so you can see what gets excluded.

## Audit this machine

Elevated PowerShell:

```powershell
cd D:\CQTools\CQSDDLAudit
powershell -ExecutionPolicy Bypass -File Collect-Sddl.ps1 -OutFile services.csv
py -3 CQSDDLAudit.py services --input services.csv --html report.html --host $env:COMPUTERNAME
```

Open `report.html`. Anything hidden is at the top of the console output too,
with a `WARNING` block explaining which ACE is responsible.

## The one command that matters

```powershell
py -3 CQSDDLAudit.py services --input services.csv --only-hidden
```

Empty output is the answer you want.

## If something looks wrong

```powershell
# what does this descriptor actually say?
py -3 CQSDDLAudit.py decode --object-type service --source Spooler --sddl "<paste sdshow output>"

# could this principal really stop it, and which entry decided?
py -3 CQSDDLAudit.py access --object-type service --token BA --want WP --explain --sddl "<paste>"
```

## Baseline a fleet

```powershell
# on a known-good build
py -3 CQSDDLAudit.py services --input golden.csv --all --csv baseline.csv

# later, anywhere
py -3 CQSDDLAudit.py diff --input services.csv --baseline golden.csv
```

`diff` is order aware, so it reports a descriptor whose entries were reordered
but not otherwise changed. That is a real finding: on a DACL, order decides
access.

## Gotchas

- Use `py -3`. Bare `python` is 2.7 on most of these machines.
- Collect elevated, or `Security` values are unreadable and a short collection
  looks like a clean one. The script tells you how many it could not read.
- Pass `--object-type service` when you hand a single descriptor to `decode` or
  `access`. Without it, `CC` and friends are read with the file table.
