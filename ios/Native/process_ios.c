// SPDX-License-Identifier: GPL-2.0-or-later
// iOS VPN runs in-process. Scripts/subprocesses are deliberately unsupported.
#include <utils/process.h>
#include <errno.h>
process_t *process_start(char *const argv[], char *const envp[], int *in, int *out, int *err, bool close_all) {
    errno = ENOTSUP; return NULL;
}
process_t *process_start_shell(char *const envp[], int *in, int *out, int *err, char *fmt, ...) {
    errno = ENOTSUP; return NULL;
}