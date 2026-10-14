<div align="center">

# RansomwareGuard

**User-mode ransomware detection and response for Windows, in a single C file.**

![Language](https://img.shields.io/badge/language-C-00599C?logo=c&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/status-experimental-orange)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

> [!WARNING]
> **Experimental software (v0.2).** RansomwareGuard adds a defensive layer for your own user account. It is **not** a replacement for antivirus/EDR or for offline, versioned backups. Read [Limitations](#limitations) and test on disposable data first.

## What it does

RansomwareGuard watches your document folders and reacts when file activity looks like ransomware, instead of only logging it:

| Layer | What happens |
|---|---|
| **Detect** | Scores several independent signals (canary files, encrypted-looking content, ransomware extensions, ransom notes, rename/write bursts). An alert fires at a score of 60. |
| **Respond** | Finds the process with the highest recent write volume and **suspends** it (default), terminates it, or just alerts. You are asked whether to terminate or resume. |
| **Recover** | Keeps a last-known-good copy of your documents in a local vault. `--restore` brings back missing or encrypted files. |

## Detection signals

Signals are summed over a 5-second sliding window. No single weak signal triggers a response, which keeps false positives low during normal work.

| Signal | Points |
|---|---|
| Canary (decoy) file modified, renamed or deleted | 100 |
| Rename to a known ransomware extension (`.locked`, `.wcry`, `.lockbit`, ...) | 35 (60 for 3+) |
| Ransom-note-like file created (`HOW_TO_DECRYPT.txt`, ...) | 30 (60 for 3+) |
| File content looks encrypted (magic-number mismatch, or high entropy in text files) | 15 / 40 / 70 for 1 / 3 / 6+ files |
| `name.ext` renamed to `name.ext.xyz` (5+ files) | 30 |
| 15+ renames in the window | 30 |
| 40+ writes in the window | 20 |
| Notification buffer overflow (very high change rate) | 30 |

**Content analysis.** For known file types the first 32 KB is checked: a `.docx` must start with a ZIP header, a `.pdf` with `%PDF`, a `.jpg` with `FF D8 FF`, and so on. Plain-text types (`.txt`, `.csv`, `.json`, ...) are checked by Shannon entropy. This catches in-place encryption even when the file name does not change.

## Quick start

### Build

No dependencies and no special flags.

```bash
# MinGW-w64
x86_64-w64-mingw32-gcc -O2 -Wall -o ransomguard.exe guard.c
```

```bat
:: MSVC (Developer Command Prompt)
cl /O2 /W4 guard.c /link /out:ransomguard.exe
```

### Run

```bat
ransomguard.exe
```

With no arguments it protects **Documents, Desktop and Pictures**. To choose folders and behavior:

```bat
ransomguard.exe --mode suspend "D:\Work" "C:\Users\me\Documents"
```

Run it as the same user that owns the files. Press `Ctrl+C` to stop; canary files are removed on exit.

### Options

| Option | Description |
|---|---|
| `folder ...` | Folders to protect (default: Documents, Desktop, Pictures) |
| `--mode alert` | Log and notify only |
| `--mode suspend` | **Default.** Suspend the suspect process, then ask: terminate or resume |
| `--mode kill` | Terminate the suspect process immediately |
| `--allow EXE` | Never act on this process, e.g. a backup tool (repeatable) |
| `--no-canary` | Do not create decoy files |
| `--no-vault` | Do not keep last-known-good copies |
| `--restore` | Restore missing/encrypted files from the vault and exit |
| `--yes` | With `--restore`: skip the confirmation prompt |

## How the response works

1. **Attribution.** A background sampler reads each process's write counters once per second (`GetProcessIoCounters`). At alert time the process with the highest write volume over the last 10 seconds is the suspect. Allow-listed processes and RansomwareGuard itself are excluded.
2. **Safety rails.** Core Windows processes (`svchost.exe`, `explorer.exe`, `lsass.exe`, ...) are reported but never suspended or terminated.
3. **Suspend first.** The default mode freezes the process with `NtSuspendProcess`, so nothing is lost if it was a false alarm. Choosing "No" resumes it and allow-lists it for the session.

## Canary files

At startup, decoy files named `00_ransomguard_canary.*` and `zz_ransomguard_canary.*` are created in each protected folder and its first-level subfolders (they sort first and last, where ransomware tends to start and end). Any change to them is a near-certain sign of mass file tampering. They are deleted when the program exits normally; if it crashes, they are refreshed on the next start. Disable with `--no-canary`.

## Vault and restore

Verifiable documents (Office files, PDFs, images, archives, text) up to 20 MB each are copied to `%LOCALAPPDATA%\RansomwareGuard\vault`, capped at 2 GB. Files that already look encrypted are never copied, so the vault keeps the last clean version.

```bat
ransomguard.exe --restore "C:\Users\me\Documents"
```

Lists what would be restored, asks for confirmation, then restores missing files and replaces encrypted ones. Encrypted originals are kept next to the restored file as `*.rg-encrypted`. Files you deleted on purpose will also be restored, so review the list.

## Logs

Events are written to the console and to `%LOCALAPPDATA%\RansomwareGuard\ransomguard.log`.

## Limitations

- **User-mode only.** There is no kernel minifilter, so a fast process can encrypt some files before the alert fires. The vault exists to cover that gap.
- **Best-effort attribution.** Per-process write volume is a heuristic. Elevated processes cannot be inspected unless RansomwareGuard also runs elevated, and ransomware that injects into a protected system process will be reported but not stopped.
- **Heuristics can be wrong.** Backup tools, sync clients and archivers can resemble ransomware. Use `--allow` for tools you trust.
- **The vault is local.** Ransomware running as your user can reach it. Keep offline, versioned backups.
- **Tested environment.** Detection, scoring, canaries, vault and restore were exercised under Wine with simulated activity on test files. Process suspension and termination have **not** yet been verified on real Windows; try `--mode alert` first on your machine.

## Roadmap

- [x] Canary files, content analysis, scoring, process response, vault and restore
- [ ] Runtime configuration file for thresholds and extensions
- [ ] Automated test suite with a safe activity simulator
- [ ] ETW-based file-event attribution (exact process per file)
- [ ] Tray icon / GUI (see concept below)
- [ ] Structured (JSON) log export

### Concept: planned GUI

> Design mockup only. The current version is a console application.

<img src="assets/RansomwareGuard.png" alt="Concept mockup of a future RansomwareGuard GUI" width="640">

## Contributing

Issues and pull requests are welcome. Please include reproduction steps and test only against disposable data.

## License

Released under the [MIT License](LICENSE).

## Author

**Oğuz Kağan Akar** · [GitHub](https://github.com/oguz-kagan-akar) · [LinkedIn](https://www.linkedin.com/in/oguz-kagan-akar/)
