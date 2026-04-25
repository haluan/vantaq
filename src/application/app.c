// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"
#include "domain/version.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define VANTAQ_USAGE "Usage: vantaqd [--version]\n"

static void vantaq_write(const vantaq_write_fn writer, void *ctx, const char *text) {
    if (writer != NULL && text != NULL) {
        writer(ctx, text);
    }
}

int vantaq_app_run(int argc, char **argv, const struct vantaq_app_io *io) {
    if (io == NULL) {
        return 64;
    }

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        char output[64];
        const char *version = vantaq_domain_version();
        int n               = snprintf(output, sizeof(output), "vantaqd %s\n", version);

        if (n <= 0 || (size_t)n >= sizeof(output)) {
            vantaq_write(io->write_err, io->ctx, "failed to render version\n");
            return 70;
        }

        vantaq_write(io->write_out, io->ctx, output);
        return 0;
    }

    if (argc == 1) {
        vantaq_write(io->write_out, io->ctx, "vantaqd skeleton started\n");
        return 0;
    }

    vantaq_write(io->write_err, io->ctx, VANTAQ_USAGE);
    return 64;
}
