// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/stdio_io.h"

#include <stdio.h>

static void vantaq_write_stdout(void *ctx, const char *data) {
    (void)ctx;
    fputs(data, stdout);
}

static void vantaq_write_stderr(void *ctx, const char *data) {
    (void)ctx;
    fputs(data, stderr);
}

void vantaq_stdio_io_init(struct vantaq_stdio_io *stdio_io) {
    stdio_io->io.write_out = vantaq_write_stdout;
    stdio_io->io.write_err = vantaq_write_stderr;
    stdio_io->io.ctx       = NULL;
}
