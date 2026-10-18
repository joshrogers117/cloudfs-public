// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit macOS/Unix locking API probe, suitable for a signed arm64 VM helper.
// Build: clang -std=c11 -Wall -Wextra -Werror -O2 scripts/validate-mac-locks.c -o /tmp/validate-mac-locks
// The file must already exist under a cloudfs-editor-validation-* directory.
// Hold:  helper hold FILE exclusive 0 4096 --seconds 120 --ready READY --release RELEASE
// Probe: helper probe FILE shared 0 4096 --expect blocked
// Disjoint probe: helper probe FILE exclusive 8192 4096 --expect acquired
// Native SMB range: add --api smbfs --open read (exclusive ranges only).
// Whole-file BSD flock: use OFFSET=0 LENGTH=0 --api flock --open read.
// POSIX fcntl is the default; macOS SMB rejects it with ENOTSUP. There is no
// silent fallback: --expect unsupported records that client limitation.
// Outputs JSON lines; hold also writes an atomic JSON readiness marker after acquiring the selected lock API.
// Exit 0: expected lock result / clean release. Exit 1: wrong lock result.
// Exit 2: configuration, open, unexpected lock errno, marker, or unlock failure.
// An open failure NEVER counts as a blocked-lock pass. O_RDWR can encounter a
// whole-inode SMB writer lease before the kernel issues a byte-range lock.
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/mount.h>
// Apple SMBClient kernel/smbfs/smbfs.h, ByteRangeLockPB2 / ioctl z:23.
// This ABI accepts exclusive byte ranges only; shared cannot be emulated by it.
struct CloudFSByteRangeLockPB2 {
    int64_t offset, length;
    uint64_t retRangeStart;
    uint8_t unLockFlag, startEndFlag;
    int32_t fd;
};
_Static_assert(sizeof(struct CloudFSByteRangeLockPB2) == 32, "Apple BRL ABI size");
_Static_assert(offsetof(struct CloudFSByteRangeLockPB2, fd) == 28, "Apple BRL ABI fd offset");
#define CLOUDFS_SMB_BRL _IOWR('z', 23, struct CloudFSByteRangeLockPB2)
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static volatile sig_atomic_t stopped;
static const char *lock_api = "fcntl";
static void stop_handler(int signo) { stopped = signo; }
static uint64_t millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static void json_string(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32) fprintf(out, "\\u%04x", (unsigned)*p);
        else fputc(*p, out);
    }
    fputc('"', out);
}
static void result(FILE *out, const char *phase, const char *file, const char *mode,
                   const char *open_mode, int64_t start, int64_t length,
                   bool acquired, bool matched, int error_number, uint64_t held_ms) {
    fprintf(out, "{\"phase\":"); json_string(out, phase);
    fprintf(out, ",\"file\":"); json_string(out, file);
    fprintf(out, ",\"mode\":"); json_string(out, mode);
    fprintf(out, ",\"api\":"); json_string(out, lock_api);
    fprintf(out, ",\"openMode\":"); json_string(out, open_mode);
    fprintf(out, ",\"pid\":%ld,\"offset\":%" PRId64 ",\"length\":%" PRId64,
            (long)getpid(), start, length);
    fprintf(out, ",\"acquired\":%s,\"expectationMatched\":%s,\"errno\":%d,\"error\":",
            acquired ? "true" : "false", matched ? "true" : "false", error_number);
    json_string(out, error_number ? strerror(error_number) : "");
    fprintf(out, ",\"heldMs\":%" PRIu64 ",\"signal\":%d}\n", held_ms, (int)stopped);
    fflush(out);
}
static bool number(const char *text, int64_t *value) {
    if (!*text || *text == '-') return false;
    errno = 0; char *end = NULL;
    intmax_t parsed = strtoimax(text, &end, 10);
    if (errno || !end || *end || parsed < 0 || parsed > INT64_MAX) return false;
    *value = (int64_t)parsed; return true;
}
static bool under_fixture(const char *path) {
    const char prefix[] = "cloudfs-editor-validation-";
    for (const char *p = path; *p; ++p) {
        if (*p == '/' && strncmp(p + 1, prefix, sizeof(prefix) - 1) == 0) {
            const char *end = strchr(p + 1, '/');
            if (end && end > p + sizeof(prefix)) return true;
        }
    }
    return false;
}
static bool resolve_fixture_file(const char *input, char *output) {
    struct stat info;
    return lstat(input, &info) == 0 && S_ISREG(info.st_mode) &&
           realpath(input, output) != NULL && under_fixture(output);
}
static bool resolve_marker(const char *input, char *output) {
    char copy[PATH_MAX], parent[PATH_MAX];
    if (!input || strlen(input) >= sizeof(copy)) return false;
    strcpy(copy, input);
    char *slash = strrchr(copy, '/');
    if (!slash || !slash[1] || !strcmp(slash + 1, ".") || !strcmp(slash + 1, "..")) return false;
    char name[PATH_MAX]; strcpy(name, slash + 1);
    if (slash == copy) slash[1] = 0; else *slash = 0;
    if (!realpath(copy, parent)) return false;
    int count = snprintf(output, PATH_MAX, "%s/%s", parent, name);
    return count > 0 && count < PATH_MAX && under_fixture(output);
}
static bool absent(const char *path) {
    struct stat info;
    return lstat(path, &info) != 0 && errno == ENOENT;
}
static int ready_marker(const char *path, const char *file, const char *mode,
                        const char *open_mode, int64_t start, int64_t length) {
    char temporary[PATH_MAX];
    int count = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid());
    if (count < 0 || (size_t)count >= sizeof(temporary)) return ENAMETOOLONG;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return errno;
    FILE *out = fdopen(fd, "w");
    if (!out) { int error_number = errno; close(fd); unlink(temporary); return error_number; }
    result(out, "held", file, mode, open_mode, start, length, true, true, 0, 0);
    int error_number = ferror(out) ? EIO : 0;
    if (fsync(fd) != 0 && !error_number) error_number = errno;
    if (fclose(out) != 0 && !error_number) error_number = errno;
    if (!error_number && rename(temporary, path) != 0) error_number = errno;
    if (error_number) unlink(temporary);
    return error_number;
}
static void usage(void) {
    fprintf(stderr, "Usage: validate-mac-locks hold|probe FILE shared|exclusive OFFSET LENGTH [--api fcntl|smbfs|flock] [--expect acquired|blocked|unsupported] [--seconds 1..3600] [--ready PATH] [--release PATH] [--open read|readwrite]\n");
}
static int lock_operation(int fd, bool exclusive, int64_t start, int64_t length, bool unlock) {
    if (!strcmp(lock_api, "flock")) return flock(fd, unlock ? LOCK_UN : (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB);
    if (!strcmp(lock_api, "smbfs")) {
#ifdef __APPLE__
        struct CloudFSByteRangeLockPB2 request = {0};
        request.offset = start; request.length = length; request.unLockFlag = unlock; request.fd = fd;
        return ffsctl(fd, CLOUDFS_SMB_BRL, &request, 0);
#else
        errno = ENOTSUP; return -1;
#endif
    }
    struct flock request; memset(&request, 0, sizeof(request));
    request.l_type = unlock ? F_UNLCK : exclusive ? F_WRLCK : F_RDLCK;
    request.l_whence = SEEK_SET; request.l_start = (off_t)start; request.l_len = (off_t)length;
    return fcntl(fd, F_SETLK, &request);
}
int main(int argc, char **argv) {
    if (argc < 6) { usage(); return 2; }
    bool hold = strcmp(argv[1], "hold") == 0;
    if (!hold && strcmp(argv[1], "probe")) { usage(); return 2; }
    bool exclusive = strcmp(argv[3], "exclusive") == 0;
    if (!exclusive && strcmp(argv[3], "shared")) { usage(); return 2; }
    int64_t start, length, seconds = 120;
    if (!number(argv[4], &start) || !number(argv[5], &length) ||
        (length && start > INT64_MAX - length)) { usage(); return 2; }
    const char *expected = hold ? "acquired" : NULL;
    const char *ready_input = NULL, *release_input = NULL;
    const char *open_mode = exclusive ? "readwrite" : "read";
    for (int i = 6; i < argc; i += 2) {
        if (i + 1 >= argc) { usage(); return 2; }
        if (!strcmp(argv[i], "--expect")) expected = argv[i + 1];
        else if (!strcmp(argv[i], "--api")) lock_api = argv[i + 1];
        else if (!strcmp(argv[i], "--seconds")) {
            if (!number(argv[i + 1], &seconds) || seconds < 1 || seconds > 3600) { usage(); return 2; }
        } else if (!strcmp(argv[i], "--ready")) ready_input = argv[i + 1];
        else if (!strcmp(argv[i], "--release")) release_input = argv[i + 1];
        else if (!strcmp(argv[i], "--open")) open_mode = argv[i + 1];
        else { usage(); return 2; }
    }
    if (!expected || (strcmp(expected, "acquired") && strcmp(expected, "blocked") && strcmp(expected, "unsupported")) ||
        (hold && strcmp(expected, "acquired")) ||
        (!hold && (ready_input || release_input)) ||
        (strcmp(open_mode, "read") && strcmp(open_mode, "readwrite")) ||
        (strcmp(lock_api, "fcntl") && strcmp(lock_api, "flock") && strcmp(lock_api, "smbfs")) ||
        (!strcmp(lock_api, "smbfs") && (!exclusive || !length)) ||
        (!strcmp(lock_api, "flock") && (start || length)) ||
        (!strcmp(lock_api, "fcntl") && exclusive && !strcmp(open_mode, "read"))) { usage(); return 2; }
    char file[PATH_MAX], ready[PATH_MAX] = "", release[PATH_MAX] = "";
    if (!resolve_fixture_file(argv[2], file) ||
        (ready_input && (!resolve_marker(ready_input, ready) || !absent(ready))) ||
        (release_input && (!resolve_marker(release_input, release) || !absent(release))) ||
        (*ready && *release && !strcmp(ready, release))) {
        fprintf(stderr, "File/markers must be isolated under cloudfs-editor-validation-*; file must exist and markers must be absent.\n"); return 2;
    }
    struct sigaction action; memset(&action, 0, sizeof(action)); action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask); sigaction(SIGINT, &action, NULL); sigaction(SIGTERM, &action, NULL);
    int fd = open(file, (!strcmp(open_mode, "read") ? O_RDONLY : O_RDWR) | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { result(stdout, "open_failed", file, argv[3], open_mode, start, length, false, false, errno, 0); return 2; }
    int status = lock_operation(fd, exclusive, start, length, false), error_number = status == 0 ? 0 : errno;
    bool acquired = status == 0, blocked = error_number == EAGAIN || error_number == EACCES;
    bool unsupported = error_number == ENOTSUP;
    bool matched = (!strcmp(expected, "acquired") && acquired) || (!strcmp(expected, "blocked") && blocked) ||
        (!strcmp(expected, "unsupported") && unsupported);
    if (!acquired) {
        result(stdout, blocked ? "blocked" : unsupported ? "unsupported" : "lock_failed", file, argv[3], open_mode, start, length, false, matched, error_number, 0);
        close(fd); return matched ? 0 : !blocked && !unsupported ? 2 : 1;
    }
    uint64_t began = millis();
    if (hold) {
        if (*ready) error_number = ready_marker(ready, file, argv[3], open_mode, start, length);
        result(stdout, error_number ? "marker_failed" : "held", file, argv[3], open_mode, start, length, true, !error_number, error_number, 0);
        if (!error_number) {
            while (!stopped && millis() - began < (uint64_t)seconds * 1000) {
                if (*release && access(release, F_OK) == 0) break;
                struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
                nanosleep(&delay, NULL);
            }
        }
    }
    if (lock_operation(fd, exclusive, start, length, true) != 0 && !error_number) error_number = errno;
    if (close(fd) != 0 && !error_number) error_number = errno;
    result(stdout, error_number ? "release_failed" : hold ? "released" : "probed", file, argv[3], open_mode,
           start, length, true, matched && !error_number, error_number, millis() - began);
    return error_number ? 2 : matched ? 0 : 1;
}
