// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"
#include "domain/version.h"
#include "infrastructure/config_loader.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define VANTAQ_USAGE "Usage: vantaqd [--version] [--config <path>]\n"

static void vantaq_write(const vantaq_write_fn writer, void *ctx, const char *text) {
    if (writer != NULL && text != NULL) {
        writer(ctx, text);
    }
}

int vantaq_app_run(int argc, char **argv, const struct vantaq_app_io *io) {
    const char *config_path = VANTAQ_DEFAULT_CONFIG_PATH;
    int i;

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

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                vantaq_write(io->write_err, io->ctx, VANTAQ_USAGE);
                return 64;
            }
            config_path = argv[++i];
            continue;
        }

        vantaq_write(io->write_err, io->ctx, VANTAQ_USAGE);
        return 64;
    }

    {
        struct vantaq_config_loader *loader = vantaq_config_loader_create();
        enum vantaq_config_status status;
        const struct vantaq_runtime_config *config;
        char output[160];
        int n;

        if (loader == NULL) {
            vantaq_write(io->write_err, io->ctx, "config load failed: out of memory\n");
            return 70;
        }

        status = vantaq_config_loader_load(loader, config_path);
        if (status != VANTAQ_CONFIG_STATUS_OK) {
            n = snprintf(output, sizeof(output), "config load failed: %s\n",
                         vantaq_config_loader_last_error(loader));
            if (n > 0 && (size_t)n < sizeof(output)) {
                vantaq_write(io->write_err, io->ctx, output);
            } else {
                vantaq_write(io->write_err, io->ctx, "config load failed\n");
            }
            vantaq_config_loader_destroy(loader);
            return 78;
        }

        config = vantaq_config_loader_config(loader);
        n      = snprintf(output, sizeof(output), "vantaqd skeleton started (%s:%d)\n",
                          vantaq_runtime_service_listen_host(config),
                          vantaq_runtime_service_listen_port(config));
        if (n > 0 && (size_t)n < sizeof(output)) {
            vantaq_write(io->write_out, io->ctx, output);
        } else {
            vantaq_write(io->write_out, io->ctx, "vantaqd skeleton started\n");
        }
        vantaq_config_loader_destroy(loader);
    }

    return 0;
}
