# CQUSNCorrelate, quick start

Author: Paula Januszkiewicz | CQURE
License: Apache License 2.0

## 1. Get the parsers

CQUSNCorrelate reads `$J` and `$MFT` through the parsers in
`CQUSNDeepAnalyzer.py`, which lives one folder over in this repository. Clone
the whole `Forensic` folder and the tool finds it automatically:

```
Forensic/
  CQUSNDeepAnalyzer/CQUSNDeepAnalyzer.py
  CQUSNCorrelate/CQUSNCorrelate.py      <- finds the sibling above
```

Taking only this folder? Copy `CQUSNDeepAnalyzer.py` next to
`CQUSNCorrelate.py` and it works standalone.

## 2. Run the demo

```powershell
.\run-demo.cmd
```

Use `py -3`, not `python`. On most machines bare `python` is 2.7 and dies on the
first f-string.

## 3. The five correlations

```powershell
py -3 CQUSNCorrelate.py exec-evidence    --input samples\demo_J.bin --unpaired
py -3 CQUSNCorrelate.py lifecycle        --input samples\demo_J.bin
py -3 CQUSNCorrelate.py sessions         --input samples\demo_J.bin --evtx samples\demo_evtx.csv
py -3 CQUSNCorrelate.py metadata-changed --input samples\demo_J.bin
py -3 CQUSNCorrelate.py si-vs-fn         --mft   samples\demo_MFT.raw
```

## 4. Your own evidence

```powershell
py -3 CQUSNCorrelate.py exec-evidence --input J.bin --mft MFT.raw --csv exec.csv
```

| Input | Needed for | How to obtain |
|---|---|---|
| `$J` | all but `si-vs-fn` | `\$Extend\$UsnJrnl:$J` via FTK Imager, KAPE or RawCopy |
| `$MFT` | `si-vs-fn`, and real paths elsewhere | volume root, same tooling |
| EVTX CSV | `sessions` | `EvtxECmd.exe -f Security.evtx --csv out\` |

Requires Windows and Python 3.8 or later. No third party packages.
