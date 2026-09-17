# Demo dataset, Operation Amber

`demo_Security.evtx` is a real .evtx file, written by `make_demo_data.py` in the
actual binary format: file header, 64 KiB chunks, string and template tables,
CRC32 checksums, and Binary XML records built from templates with typed
substitution arrays. Windows opens it, and so does Event Viewer.

Everything in it is invented. No real account, host or address appears.

```
"Operation Amber", host WKS-041, 17 March 2026 (UTC)
----------------------------------------------------
    08:40  svc_backup logs on as a service (0x2f1a), runs the nightly job
    09:02  jdoe logs on interactively (0x4c7b)
    09:05  svc_backup logs off
    10:01  WINWORD opens invoice_2026.docm from Downloads
    10:04  svchost32.exe runs from AppData Temp, parented by WINWORD
    10:12  jdoe_adm logs on over RDP from 10.10.7.66, and never logs off
    10:16  encoded PowerShell, parented by the dropper
    10:19  recon: whoami, net group, ipconfig, nltest
    10:31  mimi.exe runs and is granted SeDebugPrivilege
    11:05  local account svc_update created, added to Administrators
    11:05  scheduled task \UpdateHealthCheck created
    11:06  service UpdateHealthCheck installed, pointing at the dropper
    11:14  rclone.exe copies Documents to a remote
    11:22  two failed logons for 'administrator' from KALI-7
    11:31  the Security log is cleared (1102)
    17:30  jdoe logs off
```

## What each command should surface

```
info      1 file, 1 chunk(s), every CRC32 valid, clean dirty flag
stats     4688 is the most common event ID, one provider, one computer
dump      25 events across 17 March 2026
          --event-id 4624       three logons: 0x2f1a, 0x4c7b, 0x6e29
          --event-id 4625       the two failures from 10.10.7.66
          --contains mimi.exe   the credential theft
          --after 2026-03-17T11:00:00Z   the destructive tail of the intrusion
evtxecmd  --sessions-only exports the logon events for CQUSNCorrelate
```

Note the 4624 and 4625 records: they have no Security UserID, so the optional
substitution behind that attribute resolves to nothing and the attribute is
absent rather than empty. Compare `dump --event-id 4624 --print-xml` against
`--event-id 4688`, which does carry one.

## The point of the shared timeline

These events sit on the same host and the same clock as `demo_J.bin` in
CQUSNCorrelate. Render this log and hand it over:

```
py -3 CQEVTXExtractor.py evtxecmd -i samples/demo_Security.evtx --sessions-only -o amber.csv
py -3 CQUSNCorrelate.py sessions --input samples/demo_J.bin --evtx amber.csv
```

The 0x6e29 session opens at 10:12 and never logs off, so the tool should warn
about over-attribution rather than silently claim every later file belongs to
it. That warning is the lesson: an open session is not evidence that the
session did everything after it.
