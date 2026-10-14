/*
 * RansomGuard - Behavioral Ransomware Detection Prototype
 * ---------------------------------------------------------
 * Watches a target directory tree in real time (ReadDirectoryChangesW)
 * and flags ransomware-like behavior using heuristics:
 *
 *   1. Burst of file renames/modifications in a short time window
 *      (ransomware typically touches hundreds of files per second)
 *   2. Renames that land on a known "suspicious" extension
 *      (.locked, .encrypted, .crypt, .locky, .cerber, .enc, ...)
 *   3. A high ratio of distinct files changed vs. time elapsed
 *
 * On alert: logs to console + file, beeps, and calls a pluggable
 * ResponseAction() hook (currently: log only — see README for how to
 * extend it toward process suspension / quarantine).
 *
 * LIMITATIONS (see README.md):
 *   - User-mode only. Cannot see *which* process made the change
 *     (that needs an ETW consumer or a kernel minifilter driver).
 *   - A single rogue process can still out-race user-mode detection
 *     for a few files before the alert fires.
 *   - This is a detection PROTOTYPE, not a production AV engine.
 *
 * Build (MinGW):   x86_64-w64-mingw32-gcc -O2 -Wall -o ransomguard.exe guard.c
 * Build (MSVC):    cl /O2 /W4 guard.c /link /out:ransomguard.exe
 * Run:             ransomguard.exe "C:\Users\me\Documents"
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------------------------------------------------------------- */
/* Configuration                                                     */
/* ---------------------------------------------------------------- */

#define EVENT_BUFFER_SIZE      (64 * 1024)
#define TIME_WINDOW_SECONDS    5.0     /* sliding window for burst detection   */
#define RENAME_BURST_THRESHOLD 15      /* renames within window -> suspicious  */
#define WRITE_BURST_THRESHOLD  40      /* writes within window  -> suspicious  */
#define MAX_TRACKED_EVENTS     4096    /* ring buffer capacity                 */
#define LOG_FILE_NAME          "ransomguard.log"

/* Extensions commonly dropped by ransomware families after encrypting files.
 * Not exhaustive — easy to extend. Matching is case-insensitive. */
static const char *SUSPICIOUS_EXTENSIONS[] = {
    ".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".locky",
    ".cerber", ".zepto", ".cryptolocker", ".ransom", ".wcry", ".wncry",
    ".odin", ".thor", ".aesir", ".zzz", ".micro", ".xxx", ".ttt",
    NULL
};

/* ---------------------------------------------------------------- */
/* Event tracking (sliding window ring buffer)                       */
/* ---------------------------------------------------------------- */

typedef enum { EVT_MODIFIED, EVT_RENAMED, EVT_CREATED, EVT_DELETED } EventKind;

typedef struct {
    time_t    when;
    EventKind kind;
} TrackedEvent;

static TrackedEvent g_events[MAX_TRACKED_EVENTS];
static int          g_event_head = 0;
static int          g_event_count = 0;
static CRITICAL_SECTION g_lock;

static FILE *g_log_file = NULL;

/* ---------------------------------------------------------------- */
/* Logging                                                            */
/* ---------------------------------------------------------------- */

static void LogMessage(const char *level, const char *fmt, ...) {
    char timebuf[32];
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", lt);

    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    fprintf(stdout, "[%s] [%s] %s\n", timebuf, level, msg);
    fflush(stdout);

    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%s] %s\n", timebuf, level, msg);
        fflush(g_log_file);
    }
}

/* ---------------------------------------------------------------- */
/* Heuristics                                                         */
/* ---------------------------------------------------------------- */

static int HasSuspiciousExtension(const wchar_t *filename) {
    const wchar_t *dot = wcsrchr(filename, L'.');
    if (!dot) return 0;

    char ext[64];
    WideCharToMultiByte(CP_UTF8, 0, dot, -1, ext, sizeof(ext), NULL, NULL);
    for (char *p = ext; *p; ++p) *p = (char)tolower((unsigned char)*p);

    for (int i = 0; SUSPICIOUS_EXTENSIONS[i] != NULL; i++) {
        if (strcmp(ext, SUSPICIOUS_EXTENSIONS[i]) == 0) return 1;
    }
    return 0;
}

/* Records an event into the sliding-window ring buffer. */
static void TrackEvent(EventKind kind) {
    EnterCriticalSection(&g_lock);
    g_events[g_event_head].when = time(NULL);
    g_events[g_event_head].kind = kind;
    g_event_head = (g_event_head + 1) % MAX_TRACKED_EVENTS;
    if (g_event_count < MAX_TRACKED_EVENTS) g_event_count++;
    LeaveCriticalSection(&g_lock);
}

/* Counts events of a given kind within TIME_WINDOW_SECONDS of now. */
static int CountRecentEvents(EventKind kind) {
    time_t now = time(NULL);
    int count = 0;

    EnterCriticalSection(&g_lock);
    for (int i = 0; i < g_event_count; i++) {
        int idx = (g_event_head - 1 - i + MAX_TRACKED_EVENTS) % MAX_TRACKED_EVENTS;
        if (difftime(now, g_events[idx].when) > TIME_WINDOW_SECONDS) break;
        if (g_events[idx].kind == kind) count++;
    }
    LeaveCriticalSection(&g_lock);
    return count;
}

/* ---------------------------------------------------------------- */
/* Response hook — extend this for real mitigation                   */
/* ---------------------------------------------------------------- */

static void ResponseAction(const char *reason) {
    LogMessage("ALERT", "Suspicious behavior detected: %s", reason);
    MessageBeep(MB_ICONEXCLAMATION);

    /*
     * Extension point for a real product:
     *  - Enumerate processes with open handles to the watched volume
     *    (requires NtQuerySystemInformation / restart manager APIs)
     *    and suspend the top offender with NtSuspendProcess / DebugActiveProcess.
     *  - Trigger a Volume Shadow Copy snapshot or restore point.
     *  - Quarantine newly created files matching suspicious extensions.
     *  - Push an alert to a central console (e.g., via HTTPS webhook).
     *
     * Each of those is a meaningful chunk of additional Windows API work
     * (and, for reliable process attribution, really wants a kernel-mode
     * minifilter driver instead of ReadDirectoryChangesW). Left as a
     * clearly marked hook so the detection core above stays testable
     * on its own.
     */
}

static void EvaluateHeuristics(void) {
    int renames = CountRecentEvents(EVT_RENAMED);
    int writes  = CountRecentEvents(EVT_MODIFIED);

    if (renames >= RENAME_BURST_THRESHOLD) {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "%d file renames within %.0fs window (threshold %d)",
                 renames, TIME_WINDOW_SECONDS, RENAME_BURST_THRESHOLD);
        ResponseAction(reason);
    }
    if (writes >= WRITE_BURST_THRESHOLD) {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "%d file writes within %.0fs window (threshold %d)",
                 writes, TIME_WINDOW_SECONDS, WRITE_BURST_THRESHOLD);
        ResponseAction(reason);
    }
}

/* ---------------------------------------------------------------- */
/* Directory watcher                                                  */
/* ---------------------------------------------------------------- */

static void HandleNotification(FILE_NOTIFY_INFORMATION *fni) {
    wchar_t filename[MAX_PATH];
    int len = fni->FileNameLength / sizeof(WCHAR);
    if (len >= MAX_PATH) len = MAX_PATH - 1;
    wcsncpy(filename, fni->FileName, len);
    filename[len] = L'\0';

    switch (fni->Action) {
        case FILE_ACTION_MODIFIED:
            TrackEvent(EVT_MODIFIED);
            break;

        case FILE_ACTION_RENAMED_NEW_NAME:
            TrackEvent(EVT_RENAMED);
            if (HasSuspiciousExtension(filename)) {
                char narrow[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, filename, -1, narrow, sizeof(narrow), NULL, NULL);
                char reason[MAX_PATH + 64];
                snprintf(reason, sizeof(reason),
                         "file renamed to suspicious extension: %s", narrow);
                ResponseAction(reason);
            }
            break;

        case FILE_ACTION_ADDED:
            TrackEvent(EVT_CREATED);
            break;

        case FILE_ACTION_REMOVED:
            TrackEvent(EVT_DELETED);
            break;

        default:
            break;
    }

    EvaluateHeuristics();
}

static int WatchDirectory(const wchar_t *path) {
    HANDLE hDir = CreateFileW(
        path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        LogMessage("ERROR", "Cannot open directory for watching (error %lu)", GetLastError());
        return 1;
    }

    BYTE *buffer = (BYTE *)malloc(EVENT_BUFFER_SIZE);
    if (!buffer) {
        LogMessage("ERROR", "Out of memory allocating event buffer");
        CloseHandle(hDir);
        return 1;
    }

    LogMessage("INFO", "Watching directory tree (recursive) ...");

    for (;;) {
        DWORD bytesReturned = 0;
        BOOL ok = ReadDirectoryChangesW(
            hDir,
            buffer,
            EVENT_BUFFER_SIZE,
            TRUE, /* watch subtree */
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_ATTRIBUTES,
            &bytesReturned,
            NULL,
            NULL);

        if (!ok) {
            LogMessage("ERROR", "ReadDirectoryChangesW failed (error %lu)", GetLastError());
            break;
        }
        if (bytesReturned == 0) {
            /* Buffer overflowed — too many changes at once. That, by
             * itself, is a strong signal worth flagging. */
            ResponseAction("notification buffer overflow (extremely high change rate)");
            continue;
        }

        BYTE *p = buffer;
        for (;;) {
            FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)p;
            HandleNotification(fni);
            if (fni->NextEntryOffset == 0) break;
            p += fni->NextEntryOffset;
        }
    }

    free(buffer);
    CloseHandle(hDir);
    return 1;
}

/* ---------------------------------------------------------------- */
/* Entry point                                                        */
/* ---------------------------------------------------------------- */

int wmain(int argc, wchar_t *argv[]) {
    wchar_t targetPath[MAX_PATH];

    if (argc >= 2) {
        wcsncpy(targetPath, argv[1], MAX_PATH - 1);
        targetPath[MAX_PATH - 1] = L'\0';
    } else {
        /* Default: current user's profile directory */
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", targetPath, MAX_PATH);
        if (n == 0 || n > MAX_PATH) wcscpy(targetPath, L".");
    }

    InitializeCriticalSection(&g_lock);
    g_log_file = fopen(LOG_FILE_NAME, "a");

    LogMessage("INFO", "RansomGuard starting up");
    LogMessage("INFO", "Burst thresholds: %d renames / %d writes per %.0fs",
               RENAME_BURST_THRESHOLD, WRITE_BURST_THRESHOLD, TIME_WINDOW_SECONDS);

    int rc = WatchDirectory(targetPath);

    if (g_log_file) fclose(g_log_file);
    DeleteCriticalSection(&g_lock);
    return rc;
}
