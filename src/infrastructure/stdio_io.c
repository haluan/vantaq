// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/stdio_io.h"

#include <stdio.h>

__attribute__((weak)) int vantaq_write_stdout(void *ctx, const char *data) {
    (void)ctx;
    if (data != NULL) {
        if (fputs(data, stdout) == EOF) {
            return -1;
        }
    }
    return 0;
}

__attribute__((weak)) int vantaq_write_stderr(void *ctx, const char *data) {
    (void)ctx;
    if (data != NULL) {
        if (fputs(data, stderr) == EOF) {
            return -1;
        }
    }
    return 0;
}

void vantaq_stdio_io_init(struct vantaq_app_io *io) {
    if (io == NULL) {
        return;
    }
    io->write_out = vantaq_write_stdout;
    io->write_err = vantaq_write_stderr;
    io->ctx       = NULL;
}
