/*
 * RansomwareGuard v0.2 - user-mode ransomware detection and response
 * ------------------------------------------------------------------
 * Watches your document folders in real time and reacts when file activity
 * looks like ransomware.
 *
 * Detection signals (each adds points; an alert fires at ALERT_SCORE):
 *   - Canary (decoy) files being modified, renamed or deleted
 *   - Files whose CONTENT looks encrypted (magic-number mismatch, or
 *     high Shannon entropy in text-like files)
 *   - Renames to known ransomware extensions, or "name.ext" -> "name.ext.xyz"
 *   - Ransom-note-like files being dropped
 *   - Bursts of renames / writes, and notification buffer overflows
 *
 * Response:
 *   - Attributes the activity to the process with the most recent write
 *     volume (user-mode sampling of per-process I/O counters)
 *   - Suspends it (default) and asks you whether to terminate or resume it,
 *     terminates it (--mode kill), or only alerts (--mode alert)
 *   - Keeps a "last known good" vault of your documents so files can be
 *     restored with --restore
 *
 * LIMITATIONS (see README.md): user-mode only, no kernel minifilter, a fast
 * process can damage some files before an alert fires, and heuristics can
 * produce false positives. This is not a replacement for AV/EDR or backups.
 *
 * Build (MinGW):  x86_64-w64-mingw32-gcc -O2 -Wall -o ransomguard.exe guard.c
 * Build (MSVC):   cl /O2 /W4 guard.c /link /out:ransomguard.exe
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <math.h>

#ifdef _MSC_VER
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#endif

/* ---------------------------------------------------------------- */
/* Configuration                                                     */
/* ---------------------------------------------------------------- */

#define EVENT_BUFFER_SIZE        (256 * 1024)
#define TIME_WINDOW_MS           5000      /* sliding window                    */
#define ALERT_SCORE              60        /* points needed to raise an alert   */
#define ALERT_COOLDOWN_MS        30000     /* minimum time between alerts       */
#define RENAME_BURST_THRESHOLD   15
#define WRITE_BURST_THRESHOLD    40
#define APPENDEXT_THRESHOLD      5         /* "a.docx" -> "a.docx.xyz" count    */
#define MAX_TRACKED_EVENTS       8192
#define SAMPLE_BYTES             32768     /* bytes read for content analysis   */
#define ENTROPY_TEXT_LIMIT       7.0       /* bits/byte; text is normally < 6   */
#define MIN_ENTROPY_FILE_BYTES   512
#define MAX_ROOTS                8
#define MAX_CANARIES             64
#define MAX_SUBDIR_CANARIES      16
#define MAX_VAULT_FILE_BYTES     (20ULL * 1024 * 1024)
#define MAX_VAULT_TOTAL_BYTES    (2048ULL * 1024 * 1024)
#define PROC_HISTORY             10        /* seconds of per-process I/O history */
#define MAX_PROCS                1024
#define MAX_ALLOW                32
#define PATH_BUF                 1024
#define CANARY_PREFIX            L"00_ransomguard_canary"
#define CANARY_SUFFIX_PREFIX     L"zz_ransomguard_canary"
#define LOG_FILE_NAME            L"ransomguard.log"
#define DATA_DIR_NAME            L"RansomwareGuard"

/* Extensions commonly dropped by ransomware families (case-insensitive). */
static const char *SUSPICIOUS_EXTENSIONS[] = {
    ".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".locky",
    ".cerber", ".zepto", ".cryptolocker", ".ransom", ".wcry", ".wncry",
    ".odin", ".thor", ".aesir", ".zzz", ".micro", ".xxx", ".ttt",
    ".lockbit", ".conti", ".ryk", ".akira", ".blackcat", ".royal",
    NULL
};

/* Substrings used to recognise ransom-note file names (.txt/.html/.hta only). */
static const char *NOTE_PATTERNS[] = {
    "decrypt", "ransom", "restore_my_files", "restore-my-files",
    "recover_your", "your_files", "files_encrypted", "encrypted_files",
    "how_to_recover", "readme_to_restore", "_readme.", "!!!readme",
    NULL
};

/* Processes that are reported but never suspended or terminated. */
static const wchar_t *PROTECTED_PROCS[] = {
    L"system", L"registry", L"smss.exe", L"csrss.exe", L"wininit.exe",
    L"winlogon.exe", L"services.exe", L"lsass.exe", L"svchost.exe",
    L"explorer.exe", L"dwm.exe", L"fontdrvhost.exe", L"sihost.exe",
    L"taskhostw.exe", L"ctfmon.exe", L"msmpeng.exe", L"searchindexer.exe",
    L"conhost.exe", L"ransomguard.exe", NULL
};

/* ---------------------------------------------------------------- */
/* Types and globals                                                 */
/* ---------------------------------------------------------------- */

typedef enum {
    EVT_MODIFIED, EVT_RENAMED, EVT_CREATED, EVT_DELETED,
    EVT_SUSPECT_EXT, EVT_APPEND_EXT, EVT_BAD_CONTENT, EVT_RANSOM_NOTE,
    EVT_CANARY, EVT_OVERFLOW, EVT_KIND_COUNT
} EventKind;

typedef enum { MODE_ALERT, MODE_SUSPEND, MODE_KILL } ResponseMode;

typedef struct {
    ULONGLONG when;
    int       kind;
} TrackedEvent;

typedef struct {
    wchar_t path[MAX_PATH];
    wchar_t vault[PATH_BUF];
} Root;

typedef struct {
    DWORD     pid;
    wchar_t   name[64];
    ULONGLONG lastBytes, lastOps;
    ULONGLONG dBytes[PROC_HISTORY], dOps[PROC_HISTORY];
    int       idx, seen;
} ProcEntry;

static TrackedEvent g_events[MAX_TRACKED_EVENTS];
static int          g_event_head = 0, g_event_count = 0;
static CRITICAL_SECTION g_lock, g_log_lock, g_proc_lock;

static Root   g_roots[MAX_ROOTS];
static int    g_nroots = 0;
static wchar_t g_data_dir[PATH_BUF];
static wchar_t g_canaries[MAX_CANARIES][PATH_BUF];
static int    g_ncanaries = 0;

static ProcEntry g_procs[MAX_PROCS];
static int       g_nprocs = 0;
static wchar_t   g_allow[MAX_ALLOW][64];
static int       g_nallow = 0;

static FILE        *g_log_file = NULL;
static ResponseMode g_mode = MODE_SUSPEND;
static int          g_use_canary = 1, g_use_vault = 1;
static ULONGLONG    g_vault_bytes = 0;
static ULONGLONG    g_last_alert = 0;
static volatile LONG g_response_active = 0;
static int          g_vault_full_logged = 0;

static const char CANARY_TEXT[] =
    "RansomwareGuard canary file.\r\n"
    "This is a decoy used to detect ransomware. Do not modify, rename or delete it.\r\n"
    "It is removed automatically when RansomwareGuard exits.\r\n";

typedef LONG (NTAPI *NtProcFn)(HANDLE);

/* ---------------------------------------------------------------- */
/* Helpers                                                           */
/* ---------------------------------------------------------------- */

static void W2U(const wchar_t *w, char *out, int cap) {
    if (cap <= 0) return;
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap, NULL, NULL)) out[0] = '\0';
    out[cap - 1] = '\0';
}

static void LogMessage(const char *level, const char *fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char msg[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    EnterCriticalSection(&g_log_lock);
    fprintf(stdout, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, level, msg);
    fflush(stdout);
    if (g_log_file) {
        fprintf(g_log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, level, msg);
        fflush(g_log_file);
    }
    LeaveCriticalSection(&g_log_lock);
}

static void AddReason(char *buf, size_t cap, const char *fmt, ...) {
    size_t used = strlen(buf);
    if (used >= cap - 1) return;
    va_list args;
    va_start(args, fmt);
    if (used) { buf[used++] = ';'; buf[used++] = ' '; buf[used] = '\0'; }
    vsnprintf(buf + used, cap - used, fmt, args);
    va_end(args);
}

/* Lower-case ASCII extension of a file name ("" if none / non-ASCII). */
static void GetExtLower(const wchar_t *name, char *out, size_t cap) {
    out[0] = '\0';
    const wchar_t *slash = wcsrchr(name, L'\\');
    const wchar_t *base = slash ? slash + 1 : name;
    const wchar_t *dot = wcsrchr(base, L'.');
    if (!dot || dot == base) return;
    size_t n = wcslen(dot);
    if (n + 1 > cap || n > 15) return;
    for (size_t i = 0; i < n; i++) {
        if (dot[i] > 127) { out[0] = '\0'; return; }
        out[i] = (char)tolower((unsigned char)dot[i]);
    }
    out[n] = '\0';
}

static int PathUnder(const wchar_t *path, const wchar_t *dir) {
    size_t n = wcslen(dir);
    if (n == 0 || _wcsnicmp(path, dir, n) != 0) return 0;
    return path[n] == L'\\' || path[n] == L'\0';
}

static int IsDirectoryPath(const wchar_t *path) {
    DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static void EnsureParentDirs(const wchar_t *filePath) {
    wchar_t tmp[PATH_BUF];
    wcsncpy(tmp, filePath, PATH_BUF - 1);
    tmp[PATH_BUF - 1] = L'\0';
    for (wchar_t *p = tmp + 3; *p; ++p) {
        if (*p == L'\\') {
            *p = L'\0';
            CreateDirectoryW(tmp, NULL);
            *p = L'\\';
        }
    }
}

static unsigned FnvHash(const wchar_t *s) {
    unsigned h = 2166136261u;
    for (; *s; ++s) {
        wchar_t c = (wchar_t)towlower(*s);
        h ^= (unsigned)(c & 0xFF); h *= 16777619u;
        h ^= (unsigned)((c >> 8) & 0xFF); h *= 16777619u;
    }
    return h;
}

/* ---------------------------------------------------------------- */
/* Event tracking and scoring                                        */
/* ---------------------------------------------------------------- */

static void TrackEvent(EventKind kind) {
    EnterCriticalSection(&g_lock);
    g_events[g_event_head].when = GetTickCount64();
    g_events[g_event_head].kind = (int)kind;
    g_event_head = (g_event_head + 1) % MAX_TRACKED_EVENTS;
    if (g_event_count < MAX_TRACKED_EVENTS) g_event_count++;
    LeaveCriticalSection(&g_lock);
}

static void CountRecent(int counts[EVT_KIND_COUNT]) {
    ULONGLONG now = GetTickCount64();
    memset(counts, 0, sizeof(int) * EVT_KIND_COUNT);
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < g_event_count; i++) {
        int idx = (g_event_head - 1 - i + MAX_TRACKED_EVENTS) % MAX_TRACKED_EVENTS;
        if (now - g_events[idx].when > TIME_WINDOW_MS) break;
        counts[g_events[idx].kind]++;
    }
    LeaveCriticalSection(&g_lock);
}

static int ComputeScore(char *why, size_t cap) {
    int c[EVT_KIND_COUNT], score = 0;
    why[0] = '\0';
    CountRecent(c);

    if (c[EVT_CANARY] > 0) {
        score += 100; AddReason(why, cap, "canary file tampered (%d)", c[EVT_CANARY]);
    }
    if (c[EVT_SUSPECT_EXT] >= 3)      { score += 60; AddReason(why, cap, "%d renames to ransomware extensions", c[EVT_SUSPECT_EXT]); }
    else if (c[EVT_SUSPECT_EXT] >= 1) { score += 35; AddReason(why, cap, "rename to ransomware extension"); }
    if (c[EVT_RANSOM_NOTE] >= 3)      { score += 60; AddReason(why, cap, "%d ransom-note-like files", c[EVT_RANSOM_NOTE]); }
    else if (c[EVT_RANSOM_NOTE] >= 1) { score += 30; AddReason(why, cap, "ransom-note-like file created"); }
    if (c[EVT_BAD_CONTENT] >= 6)      { score += 70; AddReason(why, cap, "%d files with encrypted-looking content", c[EVT_BAD_CONTENT]); }
    else if (c[EVT_BAD_CONTENT] >= 3) { score += 40; AddReason(why, cap, "%d files with encrypted-looking content", c[EVT_BAD_CONTENT]); }
    else if (c[EVT_BAD_CONTENT] >= 1) { score += 15; AddReason(why, cap, "file with encrypted-looking content"); }
    if (c[EVT_APPEND_EXT] >= APPENDEXT_THRESHOLD) {
        score += 30; AddReason(why, cap, "%d files renamed by appending an extension", c[EVT_APPEND_EXT]);
    }
    if (c[EVT_RENAMED] >= RENAME_BURST_THRESHOLD) {
        score += 30; AddReason(why, cap, "%d renames in %d s", c[EVT_RENAMED], TIME_WINDOW_MS / 1000);
    }
    if (c[EVT_MODIFIED] >= WRITE_BURST_THRESHOLD) {
        score += 20; AddReason(why, cap, "%d writes in %d s", c[EVT_MODIFIED], TIME_WINDOW_MS / 1000);
    }
    if (c[EVT_OVERFLOW] >= 1) {
        score += 30; AddReason(why, cap, "event buffer overflow (very high change rate)");
    }
    return score;
}

/* ---------------------------------------------------------------- */
/* Content analysis                                                   */
/* ---------------------------------------------------------------- */

typedef struct { const char *ext; int offset; int len; const unsigned char *magic; } MagicEntry;

static const unsigned char M_ZIP[]  = { 'P', 'K', 3, 4 };
static const unsigned char M_PDF[]  = { '%', 'P', 'D', 'F' };
static const unsigned char M_JPG[]  = { 0xFF, 0xD8, 0xFF };
static const unsigned char M_PNG[]  = { 0x89, 'P', 'N', 'G' };
static const unsigned char M_GIF[]  = { 'G', 'I', 'F', '8' };
static const unsigned char M_BMP[]  = { 'B', 'M' };
static const unsigned char M_OLE[]  = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
static const unsigned char M_7Z[]   = { '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };
static const unsigned char M_RAR[]  = { 'R', 'a', 'r', '!' };
static const unsigned char M_FTYP[] = { 'f', 't', 'y', 'p' };

static const MagicEntry MAGICS[] = {
    { ".docx", 0, 4, M_ZIP }, { ".xlsx", 0, 4, M_ZIP }, { ".pptx", 0, 4, M_ZIP },
    { ".zip", 0, 4, M_ZIP },  { ".odt", 0, 4, M_ZIP },  { ".ods", 0, 4, M_ZIP },
    { ".odp", 0, 4, M_ZIP },  { ".pdf", 0, 4, M_PDF },
    { ".jpg", 0, 3, M_JPG },  { ".jpeg", 0, 3, M_JPG }, { ".png", 0, 4, M_PNG },
    { ".gif", 0, 4, M_GIF },  { ".bmp", 0, 2, M_BMP },
    { ".doc", 0, 8, M_OLE },  { ".xls", 0, 8, M_OLE },  { ".ppt", 0, 8, M_OLE },
    { ".7z", 0, 6, M_7Z },    { ".rar", 0, 4, M_RAR },  { ".mp4", 4, 4, M_FTYP },
    { NULL, 0, 0, NULL }
};

static const char *TEXT_EXTS[] = {
    ".txt", ".csv", ".log", ".md", ".rtf", ".json", ".xml", ".html", ".htm",
    ".css", ".js", ".py", ".c", ".h", ".cpp", ".java", ".ini", ".cfg",
    ".yaml", ".yml", ".sql", ".tex", NULL
};

static const MagicEntry *FindMagic(const char *ext) {
    for (int i = 0; MAGICS[i].ext; i++)
        if (strcmp(ext, MAGICS[i].ext) == 0) return &MAGICS[i];
    return NULL;
}

static int IsTextExt(const char *ext) {
    for (int i = 0; TEXT_EXTS[i]; i++)
        if (strcmp(ext, TEXT_EXTS[i]) == 0) return 1;
    return 0;
}

/* A file type we know how to verify (and therefore worth keeping in the vault). */
static int IsVerifiableExt(const char *ext) {
    return ext[0] && (FindMagic(ext) != NULL || IsTextExt(ext));
}

static double ShannonEntropy(const unsigned char *buf, DWORD n) {
    DWORD freq[256] = { 0 };
    for (DWORD i = 0; i < n; i++) freq[buf[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)n;
        h -= p * (log(p) / log(2.0));
    }
    return h;
}

/* Returns 1 if the file content looks encrypted/corrupted for its type,
 * 0 if it looks fine or the type is unknown / unreadable / in use. */
static int LooksEncrypted(const wchar_t *path, const char *ext) {
    const MagicEntry *me = FindMagic(ext);
    int text = IsTextExt(ext);
    if (!me && !text) return 0;

    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    unsigned char *buf = (unsigned char *)malloc(SAMPLE_BYTES);
    DWORD got = 0;
    int result = 0;
    if (buf && ReadFile(h, buf, SAMPLE_BYTES, &got, NULL)) {
        if (me) {
            if (got >= (DWORD)(me->offset + me->len) &&
                memcmp(buf + me->offset, me->magic, (size_t)me->len) != 0)
                result = 1;
        } else if (got >= MIN_ENTROPY_FILE_BYTES) {
            if (ShannonEntropy(buf, got) > ENTROPY_TEXT_LIMIT) result = 1;
        }
    }
    free(buf);
    CloseHandle(h);
    return result;
}

static int IsRansomNoteName(const wchar_t *name) {
    char ext[16];
    GetExtLower(name, ext, sizeof(ext));
    if (strcmp(ext, ".txt") && strcmp(ext, ".html") && strcmp(ext, ".htm") &&
        strcmp(ext, ".hta") && strcmp(ext, ".url")) return 0;

    const wchar_t *slash = wcsrchr(name, L'\\');
    const wchar_t *base = slash ? slash + 1 : name;
    char narrow[MAX_PATH];
    W2U(base, narrow, sizeof(narrow));
    for (char *p = narrow; *p; ++p) *p = (char)tolower((unsigned char)*p);
    for (int i = 0; NOTE_PATTERNS[i]; i++)
        if (strstr(narrow, NOTE_PATTERNS[i])) return 1;
    return 0;
}

static int HasSuspiciousExtension(const wchar_t *name) {
    char ext[16];
    GetExtLower(name, ext, sizeof(ext));
    if (!ext[0]) return 0;
    for (int i = 0; SUSPICIOUS_EXTENSIONS[i]; i++)
        if (strcmp(ext, SUSPICIOUS_EXTENSIONS[i]) == 0) return 1;
    return 0;
}

/* Small cache so a file being written continuously is not re-read constantly. */
#define CHECK_CACHE 512
static struct { unsigned h; ULONGLONG t; } g_check_cache[CHECK_CACHE];

static int RecentlyChecked(const wchar_t *path) {
    unsigned h = FnvHash(path);
    ULONGLONG now = GetTickCount64();
    int slot = (int)(h % CHECK_CACHE), skip = 0;
    EnterCriticalSection(&g_lock);
    if (g_check_cache[slot].h == h && now - g_check_cache[slot].t < 1500) skip = 1;
    else { g_check_cache[slot].h = h; g_check_cache[slot].t = now; }
    LeaveCriticalSection(&g_lock);
    return skip;
}

/* ---------------------------------------------------------------- */
/* Vault: last-known-good copies of verifiable documents             */
/* ---------------------------------------------------------------- */

static void VaultPathFor(const Root *r, const wchar_t *rel, wchar_t *out, size_t cap) {
    _snwprintf(out, cap, L"%ls\\%ls", r->vault, rel);
    out[cap - 1] = L'\0';
}

static void VaultStore(const Root *r, const wchar_t *full, const wchar_t *rel) {
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(full, GetFileExInfoStandard, &fa)) return;
    if (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return;
    ULONGLONG size = ((ULONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    if (size == 0 || size > MAX_VAULT_FILE_BYTES) return;

    wchar_t dest[PATH_BUF];
    VaultPathFor(r, rel, dest, PATH_BUF);

    ULONGLONG old = 0;
    WIN32_FILE_ATTRIBUTE_DATA da;
    if (GetFileAttributesExW(dest, GetFileExInfoStandard, &da))
        old = ((ULONGLONG)da.nFileSizeHigh << 32) | da.nFileSizeLow;

    EnterCriticalSection(&g_lock);
    int full_now = (g_vault_bytes - old + size) > MAX_VAULT_TOTAL_BYTES;
    LeaveCriticalSection(&g_lock);
    if (full_now) {
        if (!g_vault_full_logged) {
            g_vault_full_logged = 1;
            LogMessage("WARN", "Vault size limit reached; new files are no longer backed up");
        }
        return;
    }

    EnsureParentDirs(dest);
    if (CopyFileW(full, dest, FALSE)) {
        EnterCriticalSection(&g_lock);
        g_vault_bytes = g_vault_bytes - old + size;
        LeaveCriticalSection(&g_lock);
    }
}

typedef void (*FileCb)(const wchar_t *full, const WIN32_FIND_DATAW *fd, void *ctx);

static void WalkDir(const wchar_t *dir, int skipHidden, FileCb cb, void *ctx) {
    wchar_t pattern[PATH_BUF];
    _snwprintf(pattern, PATH_BUF, L"%ls\\*", dir);
    pattern[PATH_BUF - 1] = L'\0';
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        wchar_t full[PATH_BUF];
        _snwprintf(full, PATH_BUF, L"%ls\\%ls", dir, fd.cFileName);
        full[PATH_BUF - 1] = L'\0';
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (skipHidden && (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) continue;
            if (PathUnder(full, g_data_dir)) continue;
            WalkDir(full, skipHidden, cb, ctx);
        } else {
            cb(full, &fd, ctx);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void SizeCb(const wchar_t *full, const WIN32_FIND_DATAW *fd, void *ctx) {
    (void)full;
    *(ULONGLONG *)ctx += ((ULONGLONG)fd->nFileSizeHigh << 32) | fd->nFileSizeLow;
}

static void SeedCb(const wchar_t *full, const WIN32_FIND_DATAW *fd, void *ctx) {
    const Root *r = (const Root *)ctx;
    char ext[16];
    GetExtLower(fd->cFileName, ext, sizeof(ext));
    if (!IsVerifiableExt(ext)) return;
    ULONGLONG size = ((ULONGLONG)fd->nFileSizeHigh << 32) | fd->nFileSizeLow;
    if (size == 0 || size > MAX_VAULT_FILE_BYTES) return;

    const wchar_t *rel = full + wcslen(r->path) + 1;
    wchar_t dest[PATH_BUF];
    VaultPathFor(r, rel, dest, PATH_BUF);
    WIN32_FILE_ATTRIBUTE_DATA da;
    if (GetFileAttributesExW(dest, GetFileExInfoStandard, &da) &&
        da.nFileSizeLow == fd->nFileSizeLow && da.nFileSizeHigh == fd->nFileSizeHigh &&
        CompareFileTime(&da.ftLastWriteTime, &fd->ftLastWriteTime) >= 0)
        return; /* already up to date */

    if (LooksEncrypted(full, ext)) return;
    VaultStore(r, full, rel);
}

static DWORD WINAPI VaultSeedThread(LPVOID unused) {
    (void)unused;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    LogMessage("INFO", "Vault: backing up documents in the background ...");
    for (int i = 0; i < g_nroots; i++) WalkDir(g_roots[i].path, 1, SeedCb, &g_roots[i]);
    LogMessage("INFO", "Vault: initial backup finished (%llu MB stored)",
               (unsigned long long)(g_vault_bytes / (1024 * 1024)));
    return 0;
}

typedef struct { const Root *root; int dry; int restored, quarantined; } RestoreCtx;

static void RestoreCb(const wchar_t *vfull, const WIN32_FIND_DATAW *fd, void *ctx) {
    RestoreCtx *rc = (RestoreCtx *)ctx;
    const Root *r = rc->root;
    const wchar_t *rel = vfull + wcslen(r->vault) + 1;
    wchar_t orig[PATH_BUF];
    _snwprintf(orig, PATH_BUF, L"%ls\\%ls", r->path, rel);
    orig[PATH_BUF - 1] = L'\0';
    (void)fd;

    char ext[16], narrow[PATH_BUF];
    GetExtLower(rel, ext, sizeof(ext));
    W2U(orig, narrow, sizeof(narrow));

    int missing = GetFileAttributesW(orig) == INVALID_FILE_ATTRIBUTES;
    int bad = !missing && LooksEncrypted(orig, ext);
    if (!missing && !bad) return;

    if (rc->dry) { printf("  would restore: %s%s\n", narrow, bad ? "  (current file looks encrypted)" : ""); return; }

    if (bad) {
        wchar_t q[PATH_BUF];
        _snwprintf(q, PATH_BUF, L"%ls.rg-encrypted", orig);
        q[PATH_BUF - 1] = L'\0';
        if (MoveFileExW(orig, q, MOVEFILE_REPLACE_EXISTING)) rc->quarantined++;
        else return;
    }
    EnsureParentDirs(orig);
    if (CopyFileW(vfull, orig, TRUE)) { rc->restored++; printf("  restored: %s\n", narrow); }
}

static int RunRestore(int assumeYes) {
    int total = 0;
    for (int i = 0; i < g_nroots; i++) {
        RestoreCtx dry = { &g_roots[i], 1, 0, 0 };
        printf("Checking vault for %ls ...\n", g_roots[i].path);
        WalkDir(g_roots[i].vault, 0, RestoreCb, &dry);
    }
    if (!assumeYes) {
        printf("\nRestore the files listed above? Intentionally deleted files will also come back. [y/N] ");
        fflush(stdout);
        int c = getchar();
        if (c != 'y' && c != 'Y') { printf("Aborted.\n"); return 0; }
    }
    for (int i = 0; i < g_nroots; i++) {
        RestoreCtx rc = { &g_roots[i], 0, 0, 0 };
        WalkDir(g_roots[i].vault, 0, RestoreCb, &rc);
        total += rc.restored;
        if (rc.quarantined)
            printf("%d encrypted files were kept next to the originals as *.rg-encrypted\n", rc.quarantined);
    }
    printf("Restored %d files.\n", total);
    return 0;
}

/* ---------------------------------------------------------------- */
/* Canary files                                                       */
/* ---------------------------------------------------------------- */

static int IsCanaryName(const wchar_t *rel) {
    const wchar_t *slash = wcsrchr(rel, L'\\');
    const wchar_t *base = slash ? slash + 1 : rel;
    return _wcsnicmp(base, CANARY_PREFIX, wcslen(CANARY_PREFIX)) == 0 ||
           _wcsnicmp(base, CANARY_SUFFIX_PREFIX, wcslen(CANARY_SUFFIX_PREFIX)) == 0;
}

static void CreateOneCanary(const wchar_t *dir, const wchar_t *name) {
    if (g_ncanaries >= MAX_CANARIES) return;
    wchar_t path[PATH_BUF];
    _snwprintf(path, PATH_BUF, L"%ls\\%ls", dir, name);
    path[PATH_BUF - 1] = L'\0';
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w;
    WriteFile(h, CANARY_TEXT, (DWORD)(sizeof(CANARY_TEXT) - 1), &w, NULL);
    CloseHandle(h);
    wcscpy(g_canaries[g_ncanaries++], path);
}

static void CreateCanaries(const Root *r) {
    CreateOneCanary(r->path, CANARY_PREFIX L".docx");
    CreateOneCanary(r->path, CANARY_PREFIX L".xlsx");
    CreateOneCanary(r->path, CANARY_SUFFIX_PREFIX L".pdf");

    wchar_t pattern[PATH_BUF];
    _snwprintf(pattern, PATH_BUF, L"%ls\\*", r->path);
    pattern[PATH_BUF - 1] = L'\0';
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    int n = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        wchar_t sub[PATH_BUF];
        _snwprintf(sub, PATH_BUF, L"%ls\\%ls", r->path, fd.cFileName);
        sub[PATH_BUF - 1] = L'\0';
        if (PathUnder(sub, g_data_dir)) continue;
        CreateOneCanary(sub, CANARY_PREFIX L".docx");
    } while (FindNextFileW(h, &fd) && ++n < MAX_SUBDIR_CANARIES);
    FindClose(h);
}

static void CleanupCanaries(void) {
    for (int i = 0; i < g_ncanaries; i++) DeleteFileW(g_canaries[i]);
    g_ncanaries = 0;
}

/* Returns 1 if the canary is missing or its content changed. */
static int CanaryTampered(const wchar_t *full) {
    HANDLE h = CreateFileW(full, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND ||
                                          GetLastError() == ERROR_PATH_NOT_FOUND;
    char buf[sizeof(CANARY_TEXT) + 16];
    DWORD got = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf), &got, NULL);
    CloseHandle(h);
    if (!ok) return 0;
    return !(got == sizeof(CANARY_TEXT) - 1 && memcmp(buf, CANARY_TEXT, got) == 0);
}

/* ---------------------------------------------------------------- */
/* Process attribution (per-process I/O sampling)                    */
/* ---------------------------------------------------------------- */

static int IsProtectedName(const wchar_t *name) {
    for (int i = 0; PROTECTED_PROCS[i]; i++)
        if (!_wcsicmp(name, PROTECTED_PROCS[i])) return 1;
    return 0;
}

static int IsAllowedName(const wchar_t *name) {
    for (int i = 0; i < g_nallow; i++)
        if (!_wcsicmp(name, g_allow[i])) return 1;
    return 0;
}

static void AddAllow(const wchar_t *name) {
    if (g_nallow >= MAX_ALLOW) return;
    wcsncpy(g_allow[g_nallow], name, 63);
    g_allow[g_nallow][63] = L'\0';
    g_nallow++;
}

/* Takes one sample of every process's cumulative write counters. */
static void SampleProcesses(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    EnterCriticalSection(&g_proc_lock);
    for (int i = 0; i < g_nprocs; i++) g_procs[i].seen = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4) continue;
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hp) continue;
            IO_COUNTERS io;
            if (GetProcessIoCounters(hp, &io)) {
                ProcEntry *e = NULL;
                for (int i = 0; i < g_nprocs; i++)
                    if (g_procs[i].pid == pe.th32ProcessID) { e = &g_procs[i]; break; }
                if (!e && g_nprocs < MAX_PROCS) {
                    e = &g_procs[g_nprocs++];
                    memset(e, 0, sizeof(*e));
                    e->pid = pe.th32ProcessID;
                    wcsncpy(e->name, pe.szExeFile, 63);
                    /* A process started within the history window has done all of its
                     * I/O inside it, so count from zero instead of from "now". */
                    FILETIME ct, xt, kt, ut, nowft;
                    int recent = 0;
                    if (GetProcessTimes(hp, &ct, &xt, &kt, &ut)) {
                        GetSystemTimeAsFileTime(&nowft);
                        ULONGLONG c = ((ULONGLONG)ct.dwHighDateTime << 32) | ct.dwLowDateTime;
                        ULONGLONG n = ((ULONGLONG)nowft.dwHighDateTime << 32) | nowft.dwLowDateTime;
                        recent = n > c && (n - c) < (ULONGLONG)PROC_HISTORY * 10000000ULL;
                    }
                    e->lastBytes = recent ? 0 : io.WriteTransferCount;
                    e->lastOps   = recent ? 0 : io.WriteOperationCount;
                }
                if (e) {
                    e->dBytes[e->idx] = io.WriteTransferCount - e->lastBytes;
                    e->dOps[e->idx]   = io.WriteOperationCount - e->lastOps;
                    e->idx = (e->idx + 1) % PROC_HISTORY;
                    e->lastBytes = io.WriteTransferCount;
                    e->lastOps = io.WriteOperationCount;
                    e->seen = 1;
                }
            }
            CloseHandle(hp);
        } while (Process32NextW(snap, &pe));
    }
    for (int i = 0; i < g_nprocs; ) {
        if (!g_procs[i].seen) g_procs[i] = g_procs[--g_nprocs];
        else i++;
    }
    LeaveCriticalSection(&g_proc_lock);
    CloseHandle(snap);
}

static DWORD WINAPI SamplerThread(LPVOID unused) {
    (void)unused;
    for (;;) { SampleProcesses(); Sleep(1000); }
    return 0;
}

/* Picks the process (not allow-listed, not ourselves) with the largest recent write volume. */
static int PickSuspect(DWORD *pid, wchar_t *name, ULONGLONG *bytes, ULONGLONG *ops) {
    int found = 0;
    ULONGLONG bestB = 0, bestO = 0;
    SampleProcesses();   /* fresh data: the alert may fire within a second of the process starting */
    DWORD self = GetCurrentProcessId();
    EnterCriticalSection(&g_proc_lock);
    for (int i = 0; i < g_nprocs; i++) {
        ProcEntry *e = &g_procs[i];
        if (e->pid == self || IsAllowedName(e->name)) continue;
        ULONGLONG sb = 0, so = 0;
        for (int k = 0; k < PROC_HISTORY; k++) { sb += e->dBytes[k]; so += e->dOps[k]; }
        if (so < 30 && sb < 512 * 1024) continue;
        if (!found || sb > bestB) {
            found = 1; bestB = sb; bestO = so;
            *pid = e->pid;
            wcsncpy(name, e->name, 63); name[63] = L'\0';
        }
    }
    LeaveCriticalSection(&g_proc_lock);
    *bytes = bestB; *ops = bestO;
    return found;
}

/* ---------------------------------------------------------------- */
/* Response                                                           */
/* ---------------------------------------------------------------- */

typedef struct { char why[1024]; int score; } AlertCtx;

static void ShowBox(UINT flags, int *answer, const wchar_t *fmt, ...) {
    wchar_t text[2048];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf(text, 2048, fmt, args);
    va_end(args);
    text[2047] = L'\0';
    int r = MessageBoxW(NULL, text, L"RansomwareGuard - possible ransomware",
                        flags | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
    if (answer) *answer = r;
}

static DWORD WINAPI ResponseThread(LPVOID param) {
    AlertCtx *ctx = (AlertCtx *)param;
    wchar_t wwhy[1024];
    MultiByteToWideChar(CP_UTF8, 0, ctx->why, -1, wwhy, 1024);
    LogMessage("ALERT", "Possible ransomware activity (score %d): %s", ctx->score, ctx->why);
    MessageBeep(MB_ICONEXCLAMATION);

    DWORD pid = 0;
    wchar_t name[64] = L"";
    ULONGLONG sb = 0, so = 0;
    int have = PickSuspect(&pid, name, &sb, &so);

    if (!have) {
        LogMessage("WARN", "No process could be attributed (it may be elevated or too short-lived)");
        ShowBox(MB_OK, NULL,
                L"Suspicious file activity detected.\n\n%ls\n\nNo responsible process could be identified. "
                L"Disconnect from the network, stop what you are doing and check your files.", wwhy);
        goto done;
    }

    char nameU[200];
    W2U(name, nameU, sizeof(nameU));
    LogMessage("ALERT", "Top writer: %s (pid %lu), %llu KB / %llu writes in last %d s",
               nameU, (unsigned long)pid, (unsigned long long)(sb / 1024),
               (unsigned long long)so, PROC_HISTORY);

    if (IsProtectedName(name)) {
        LogMessage("WARN", "%s is a protected system process; not taking action", nameU);
        ShowBox(MB_OK, NULL,
                L"Suspicious file activity detected.\n\n%ls\n\nMost active writer: %ls (pid %lu), a protected "
                L"system process, so no action was taken.", wwhy, name, (unsigned long)pid);
        goto done;
    }

    if (g_mode == MODE_ALERT) {
        ShowBox(MB_OK, NULL,
                L"Suspicious file activity detected.\n\n%ls\n\nMost active writer: %ls (pid %lu). "
                L"Alert-only mode: no action taken.", wwhy, name, (unsigned long)pid);
        goto done;
    }

    wchar_t exe[PATH_BUF] = L"(unknown path)";
    HANDLE hq = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hq) { DWORD n = PATH_BUF; QueryFullProcessImageNameW(hq, 0, exe, &n); CloseHandle(hq); }

    if (g_mode == MODE_KILL) {
        HANDLE hk = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        int ok = hk && TerminateProcess(hk, 1);
        if (hk) CloseHandle(hk);
        LogMessage(ok ? "ACTION" : "ERROR", "%s pid %lu (%s)", ok ? "Terminated" : "Failed to terminate",
                   (unsigned long)pid, nameU);
        ShowBox(MB_OK, NULL, L"Suspicious file activity detected.\n\n%ls\n\n%ls pid %lu (%ls) was %ls.",
                wwhy, name, (unsigned long)pid, exe, ok ? L"terminated" : L"NOT terminated (access denied)");
        goto done;
    }

    /* MODE_SUSPEND */
    NtProcFn suspend = (NtProcFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
    NtProcFn resume  = (NtProcFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess");
    HANDLE hs = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE, FALSE, pid);
    if (!hs || !suspend || suspend(hs) != 0) {
        LogMessage("ERROR", "Could not suspend %s pid %lu (access denied? try running as the same user)",
                   nameU, (unsigned long)pid);
        ShowBox(MB_OK, NULL,
                L"Suspicious file activity detected.\n\n%ls\n\nMost active writer: %ls (pid %lu), but it could not be "
                L"suspended. Stop it manually (Task Manager).", wwhy, name, (unsigned long)pid);
        if (hs) CloseHandle(hs);
        goto done;
    }
    LogMessage("ACTION", "Suspended %s (pid %lu): %s", nameU, (unsigned long)pid, nameU);

    int answer = IDNO;
    ShowBox(MB_YESNO, &answer,
            L"Suspicious file activity detected.\n\n%ls\n\nThe process %ls (pid %lu) was SUSPENDED:\n%ls\n\n"
            L"Yes = terminate it (recommended if you did not start it)\n"
            L"No = resume it (false alarm)", wwhy, name, (unsigned long)pid, exe);
    if (answer == IDYES) {
        TerminateProcess(hs, 1);
        LogMessage("ACTION", "Terminated %s (pid %lu) at user request", nameU, (unsigned long)pid);
    } else {
        if (resume) resume(hs);
        AddAllow(name);
        LogMessage("ACTION", "Resumed %s (pid %lu); it is now allow-listed for this session",
                   nameU, (unsigned long)pid);
    }
    CloseHandle(hs);

done:
    free(ctx);
    InterlockedExchange(&g_response_active, 0);
    return 0;
}

static void EvaluateHeuristics(void) {
    ULONGLONG now = GetTickCount64();
    if (g_last_alert && now - g_last_alert < ALERT_COOLDOWN_MS) return;

    AlertCtx *ctx = (AlertCtx *)calloc(1, sizeof(AlertCtx));
    if (!ctx) return;
    ctx->score = ComputeScore(ctx->why, sizeof(ctx->why));
    if (ctx->score < ALERT_SCORE) { free(ctx); return; }

    if (InterlockedCompareExchange(&g_response_active, 1, 0) != 0) { free(ctx); return; }
    g_last_alert = now;
    HANDLE t = CreateThread(NULL, 0, ResponseThread, ctx, 0, NULL);
    if (t) CloseHandle(t);
    else { free(ctx); InterlockedExchange(&g_response_active, 0); }
}

/* ---------------------------------------------------------------- */
/* Directory watcher                                                  */
/* ---------------------------------------------------------------- */

static void CheckFile(const Root *r, const wchar_t *full, const wchar_t *rel,
                      const wchar_t *extName, int allowVault) {
    if (IsDirectoryPath(full)) return;
    if (RecentlyChecked(full)) return;
    char ext[16];
    GetExtLower(extName, ext, sizeof(ext));
    if (!ext[0]) return;
    if (LooksEncrypted(full, ext)) {
        char narrow[PATH_BUF];
        W2U(rel, narrow, sizeof(narrow));
        LogMessage("WARN", "Encrypted-looking content: %s", narrow);
        TrackEvent(EVT_BAD_CONTENT);
    } else if (allowVault && g_use_vault && IsVerifiableExt(ext)) {
        VaultStore(r, full, rel);
    }
}

static void HandleNotification(const Root *r, FILE_NOTIFY_INFORMATION *fni, wchar_t *oldName) {
    wchar_t rel[MAX_PATH], full[PATH_BUF];
    int len = (int)(fni->FileNameLength / sizeof(WCHAR));
    if (len >= MAX_PATH) len = MAX_PATH - 1;
    wcsncpy(rel, fni->FileName, (size_t)len);
    rel[len] = L'\0';
    _snwprintf(full, PATH_BUF, L"%ls\\%ls", r->path, rel);
    full[PATH_BUF - 1] = L'\0';

    if (PathUnder(full, g_data_dir)) return;     /* our own vault / log */
    int canary = IsCanaryName(rel);

    switch (fni->Action) {
    case FILE_ACTION_MODIFIED:
        if (canary) {
            if (CanaryTampered(full)) { LogMessage("WARN", "Canary modified: %ls", full); TrackEvent(EVT_CANARY); }
            break;
        }
        if (IsDirectoryPath(full)) break;
        TrackEvent(EVT_MODIFIED);
        CheckFile(r, full, rel, rel, 1);
        break;

    case FILE_ACTION_ADDED:
        if (canary) break;
        TrackEvent(EVT_CREATED);
        if (IsRansomNoteName(rel)) { LogMessage("WARN", "Ransom-note-like file: %ls", full); TrackEvent(EVT_RANSOM_NOTE); }
        CheckFile(r, full, rel, rel, 1);
        break;

    case FILE_ACTION_REMOVED:
        if (canary) { LogMessage("WARN", "Canary deleted: %ls", full); TrackEvent(EVT_CANARY); break; }
        TrackEvent(EVT_DELETED);
        break;

    case FILE_ACTION_RENAMED_OLD_NAME:
        if (canary) { LogMessage("WARN", "Canary renamed: %ls", full); TrackEvent(EVT_CANARY); }
        wcsncpy(oldName, rel, MAX_PATH - 1);
        oldName[MAX_PATH - 1] = L'\0';
        return;

    case FILE_ACTION_RENAMED_NEW_NAME:
        if (canary) break;
        TrackEvent(EVT_RENAMED);
        if (HasSuspiciousExtension(rel)) {
            LogMessage("WARN", "Renamed to suspicious extension: %ls", full);
            TrackEvent(EVT_SUSPECT_EXT);
        }
        {
            /* Classify content by the ORIGINAL extension when a ransomware-style
             * "name.ext" -> "name.ext.xyz" rename was used. */
            const wchar_t *extName = rel;
            if (oldName[0]) {
                size_t ol = wcslen(oldName);
                const wchar_t *base = wcsrchr(oldName, L'\\');
                base = base ? base + 1 : oldName;
                if (wcschr(base, L'.') && wcslen(rel) > ol + 1 &&
                    _wcsnicmp(rel, oldName, ol) == 0 && rel[ol] == L'.') {
                    TrackEvent(EVT_APPEND_EXT);
                    extName = oldName;
                }
            }
            if (IsRansomNoteName(rel)) TrackEvent(EVT_RANSOM_NOTE);
            CheckFile(r, full, rel, extName, 0);
        }
        break;

    default:
        break;
    }
    oldName[0] = L'\0';
}

static DWORD WINAPI WatcherThread(LPVOID param) {
    const Root *r = (const Root *)param;
    HANDLE hDir = CreateFileW(r->path, FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        LogMessage("ERROR", "Cannot watch %ls (error %lu)", r->path, GetLastError());
        return 1;
    }
    BYTE *buffer = (BYTE *)malloc(EVENT_BUFFER_SIZE);
    if (!buffer) { CloseHandle(hDir); return 1; }
    wchar_t oldName[MAX_PATH] = L"";

    for (;;) {
        DWORD bytes = 0;
        BOOL ok = ReadDirectoryChangesW(hDir, buffer, EVENT_BUFFER_SIZE, TRUE,
                                        FILE_NOTIFY_CHANGE_FILE_NAME |
                                        FILE_NOTIFY_CHANGE_LAST_WRITE |
                                        FILE_NOTIFY_CHANGE_SIZE,
                                        &bytes, NULL, NULL);
        if (!ok) {
            if (GetLastError() == ERROR_NOTIFY_ENUM_DIR) { TrackEvent(EVT_OVERFLOW); EvaluateHeuristics(); continue; }
            LogMessage("ERROR", "ReadDirectoryChangesW failed for %ls (error %lu)", r->path, GetLastError());
            break;
        }
        if (bytes == 0) { TrackEvent(EVT_OVERFLOW); EvaluateHeuristics(); continue; }

        BYTE *p = buffer;
        for (;;) {
            FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)p;
            HandleNotification(r, fni, oldName);
            if (fni->NextEntryOffset == 0) break;
            p += fni->NextEntryOffset;
        }
        EvaluateHeuristics();
    }
    free(buffer);
    CloseHandle(hDir);
    return 1;
}

/* ---------------------------------------------------------------- */
/* Setup                                                              */
/* ---------------------------------------------------------------- */

static BOOL WINAPI CtrlHandler(DWORD type) {
    (void)type;
    LogMessage("INFO", "Shutting down, removing canary files");
    CleanupCanaries();
    if (g_log_file) fflush(g_log_file);
    ExitProcess(0);
    return TRUE;
}

static void InitDataDir(void) {
    wchar_t base[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) wcscpy(base, L".");
    _snwprintf(g_data_dir, PATH_BUF, L"%ls\\%ls", base, DATA_DIR_NAME);
    g_data_dir[PATH_BUF - 1] = L'\0';
    CreateDirectoryW(g_data_dir, NULL);
}

static void AddRoot(const wchar_t *path) {
    if (g_nroots >= MAX_ROOTS) return;
    wchar_t full[MAX_PATH];
    DWORD n = GetFullPathNameW(path, MAX_PATH, full, NULL);
    if (n == 0 || n >= MAX_PATH) return;
    while (n > 3 && full[n - 1] == L'\\') full[--n] = L'\0';
    if (!IsDirectoryPath(full)) { fwprintf(stderr, L"Not a directory, skipped: %ls\n", full); return; }
    for (int i = 0; i < g_nroots; i++) if (!_wcsicmp(g_roots[i].path, full)) return;
    Root *r = &g_roots[g_nroots++];
    wcscpy(r->path, full);
    _snwprintf(r->vault, PATH_BUF, L"%ls\\vault\\%08x", g_data_dir, FnvHash(full));
    r->vault[PATH_BUF - 1] = L'\0';
}

static void AddDefaultRoots(void) {
    static const int ids[] = { CSIDL_PERSONAL, CSIDL_DESKTOPDIRECTORY, CSIDL_MYPICTURES };
    for (int i = 0; i < 3; i++) {
        wchar_t p[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, ids[i], NULL, 0, p))) AddRoot(p);
    }
}

static void PrintUsage(void) {
    printf(
        "RansomwareGuard v0.2\n\n"
        "Usage: ransomguard.exe [options] [folder ...]\n\n"
        "  folder          Folders to protect (default: Documents, Desktop, Pictures)\n"
        "  --mode M        alert | suspend (default) | kill\n"
        "  --allow EXE     Never suspend/terminate this process (repeatable)\n"
        "  --no-canary     Do not create decoy canary files\n"
        "  --no-vault      Do not keep last-known-good copies of documents\n"
        "  --restore       Restore missing/encrypted files from the vault and exit\n"
        "  --yes           With --restore: do not ask for confirmation\n"
        "  --help          Show this help\n");
}

int main(void) {
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;

    int restore = 0, yes = 0;
    SetConsoleOutputCP(CP_UTF8);
    InitializeCriticalSection(&g_lock);
    InitializeCriticalSection(&g_log_lock);
    InitializeCriticalSection(&g_proc_lock);
    InitDataDir();

    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--help") || !wcscmp(argv[i], L"-h")) { PrintUsage(); return 0; }
        else if (!wcscmp(argv[i], L"--mode") && i + 1 < argc) {
            i++;
            if (!wcscmp(argv[i], L"alert")) g_mode = MODE_ALERT;
            else if (!wcscmp(argv[i], L"suspend")) g_mode = MODE_SUSPEND;
            else if (!wcscmp(argv[i], L"kill")) g_mode = MODE_KILL;
            else { PrintUsage(); return 1; }
        }
        else if (!wcscmp(argv[i], L"--allow") && i + 1 < argc) AddAllow(argv[++i]);
        else if (!wcscmp(argv[i], L"--no-canary")) g_use_canary = 0;
        else if (!wcscmp(argv[i], L"--no-vault")) g_use_vault = 0;
        else if (!wcscmp(argv[i], L"--restore")) restore = 1;
        else if (!wcscmp(argv[i], L"--yes")) yes = 1;
        else if (!wcsncmp(argv[i], L"--", 2)) { PrintUsage(); return 1; }
        else AddRoot(argv[i]);
    }
    if (g_nroots == 0) AddDefaultRoots();
    if (g_nroots == 0) { fprintf(stderr, "No valid folders to protect.\n"); return 1; }

    if (restore) return RunRestore(yes);

    wchar_t logPath[PATH_BUF];
    _snwprintf(logPath, PATH_BUF, L"%ls\\%ls", g_data_dir, LOG_FILE_NAME);
    logPath[PATH_BUF - 1] = L'\0';
    g_log_file = _wfopen(logPath, L"a");

    static const char *modeNames[] = { "alert", "suspend", "kill" };
    LogMessage("INFO", "RansomwareGuard v0.2 starting (mode: %s, alert score >= %d)",
               modeNames[g_mode], ALERT_SCORE);
    for (int i = 0; i < g_nroots; i++) {
        char p[PATH_BUF];
        W2U(g_roots[i].path, p, sizeof(p));
        LogMessage("INFO", "Protecting: %s", p);
    }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    if (g_use_canary) {
        for (int i = 0; i < g_nroots; i++) CreateCanaries(&g_roots[i]);
        LogMessage("INFO", "Created %d canary files (removed on exit)", g_ncanaries);
    }

    if (g_use_vault) {
        for (int i = 0; i < g_nroots; i++) WalkDir(g_roots[i].vault, 0, SizeCb, &g_vault_bytes);
        HANDLE t = CreateThread(NULL, 0, VaultSeedThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }

    HANDLE ts = CreateThread(NULL, 0, SamplerThread, NULL, 0, NULL);
    if (ts) CloseHandle(ts);

    HANDLE watchers[MAX_ROOTS];
    int nw = 0;
    for (int i = 0; i < g_nroots; i++) {
        HANDLE t = CreateThread(NULL, 0, WatcherThread, &g_roots[i], 0, NULL);
        if (t) watchers[nw++] = t;
    }
    LogMessage("INFO", "Monitoring. Press Ctrl+C to stop.");
    if (nw > 0) WaitForMultipleObjects((DWORD)nw, watchers, TRUE, INFINITE);

    CleanupCanaries();
    if (g_log_file) fclose(g_log_file);
    return 0;
}
