<div align="center">

# RansomwareGuard

**Behavior-based ransomware detection prototype for Windows, written in C.**

![Language](https://img.shields.io/badge/language-C-00599C?logo=c&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/status-experimental-orange)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

<img src="assets/RansomwareGuard.png" alt="RansomwareGuard dashboard" width="720">

</div>

> [!WARNING]
> **Experimental prototype.** RansomwareGuard is a detection research project. It is **not** a replacement for antivirus/EDR, offline backups, or a production endpoint protection product.

## Overview

RansomwareGuard watches a directory tree in real time and raises an alert when file-system activity looks like ransomware: sudden bursts of renames or writes, or files renamed to extensions commonly dropped by encryptors. It uses only the Windows API, so there are no external dependencies and it builds as a single C file.

## Features

- **Real-time, recursive monitoring** via the Windows `ReadDirectoryChangesW` API
- **Burst detection** over a sliding time window for renames and modifications
- **Suspicious extension matching** against a built-in, case-insensitive list (`.locked`, `.encrypted`, `.crypt`, `.enc`, `.wcry`, `.cerber`, and more)
- **Overflow handling:** a notification buffer overflow is treated as a high-change-rate warning
- **Logging** to the console and to `ransomguard.log`
- **Pluggable response hook:** `ResponseAction()` is the extension point for future, carefully tested actions

## How detection works

| Heuristic | Default trigger |
|---|---|
| Rename burst | 15 or more rename events within 5 seconds |
| Write burst | 40 or more modification events within 5 seconds |
| Suspicious extension | A file is renamed to an extension in the built-in list |
| Notification overflow | A zero-byte notification result (very high change rate) |

These are indicators, not proof. Legitimate software (backup tools, build systems, sync clients) can trigger false positives, and ransomware can evade simple rules.

## Getting started

### Requirements

- Windows
- A C compiler with Windows API support: **MinGW-w64** or **MSVC**

### Build

**MinGW-w64**

```bash
x86_64-w64-mingw32-gcc -O2 -Wall -o ransomguard.exe guard.c
```

**MSVC** (Developer Command Prompt)

```bat
cl /O2 /W4 guard.c /link /out:ransomguard.exe
```

### Run

```bat
ransomguard.exe "C:\Path\To\Monitor"
```

If no path is given, the current user's profile directory (`%USERPROFILE%`) is monitored.

> [!IMPORTANT]
> Only monitor systems and directories you are authorized to monitor. Test first against a disposable folder that contains no important files.

## Configuration

Thresholds and the extension list are compile-time settings at the top of [`guard.c`](guard.c):

| Setting | Default | Purpose |
|---|---|---|
| `TIME_WINDOW_SECONDS` | `5.0` | Sliding window for burst detection |
| `RENAME_BURST_THRESHOLD` | `15` | Renames per window that trigger an alert |
| `WRITE_BURST_THRESHOLD` | `40` | Modifications per window that trigger an alert |
| `MAX_TRACKED_EVENTS` | `4096` | Event ring buffer capacity |
| `EVENT_BUFFER_SIZE` | `64 KB` | `ReadDirectoryChangesW` buffer size |
| `LOG_FILE_NAME` | `ransomguard.log` | Log file in the working directory |
| `SUSPICIOUS_EXTENSIONS[]` | built-in list | Extensions flagged on rename |

## Logs

Events are printed to the console and appended to `ransomguard.log` in the working directory. Log files are excluded from version control via `.gitignore`.

## Limitations

- **Detection only.** On alert, `ResponseAction()` logs the event and plays a system beep. It does not stop processes, quarantine files, or restore data.
- **No process attribution.** Directory change notifications do not identify the responsible process. Reliable attribution requires ETW or a kernel minifilter driver.
- **User-mode only.** A fast process can still modify some files before an alert fires.
- **Heuristic-based.** Thresholds and extensions can produce false positives or miss other ransomware behavior.

## Roadmap

- [ ] Runtime configuration for thresholds and extensions
- [ ] Alert aggregation and deduplication
- [ ] Automated tests using safe, simulated file activity
- [ ] Process attribution (ETW) and optional response actions
- [ ] Settings UI and structured log export (JSON)

## Contributing

Issues and pull requests are welcome. Please include reproduction steps, and run any tests in an isolated environment with disposable data.

## License

No license has been specified yet. Until one is added, standard copyright restrictions apply.

## Author

**Oğuz Kağan Akar** · [@oguz-kagan-akar](https://github.com/oguz-kagan-akar)
