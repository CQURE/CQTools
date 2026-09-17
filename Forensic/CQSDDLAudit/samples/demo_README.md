# Sample collection

`demo_sddl.csv` is hand written, not captured from a real machine, so nothing in
it is anyone's actual configuration. It exists so every finding can be
demonstrated without needing a compromised host.

The columns are exactly what `Collect-Sddl.ps1` writes.

| Service | What it demonstrates |
|---|---|
| `Spooler` | A normal service descriptor. No finding. |
| `W32Time` | Another normal one, running as LocalService. |
| `CQHiddenService` | **Hidden.** `(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)`, the classic form: denies enumeration, reconfiguration, stopping, pausing and deletion to Interactive, Service and Administrators at once. Also marked `EnumVisible=False`. This is the one to point at when you demonstrate the tool. |
| `TelemetrySink` | **Hidden**, the blunt version: `(D;;GA;;;BA)` denies Administrators everything. |
| `LegacyAgent` | **Weak.** Full control to `BU` (Users), which includes `SERVICE_CHANGE_CONFIG`, so any user can repoint the binary. |
| `NetTap` | **Weak.** The same, to `WD` (Everyone). Collected via `sc sdshow` rather than the registry, to show that column in use. |
| `OpenSvc` | **Weak.** NULL DACL, written as a bare `D:` with no entries. |
| `BackupHelper` | **Anti-tamper.** `(D;;WPSD;;;BA)` stops Administrators stopping or deleting it, without hiding it. |
| `DriverFoo` | A kernel driver, `ServiceType 0x1`. Not returned by SCM enumeration under its own name, and correctly **not** reported as hidden. |

## What the demo should print

`services` reports 2 HIDDEN, 3 WEAK, 1 ANTI-TAMPER and 3 ok, and prints a
`WARNING` block for each hidden service naming the ACE responsible.

`access --token BA --want WP` against the `BackupHelper` style descriptor comes
back DENIED, decided by the Deny entry, even though a later entry grants
Administrators full control. That is the point: order decides, and the GUI would
show you a tidy list sorted for display.
