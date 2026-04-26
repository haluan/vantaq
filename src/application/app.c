// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"
#include "domain/version.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/http_server.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define VANTAQ_USAGE "Usage: vantaqd [--version] [--config <path>]\n"

static void vantaq_write(const vantaq_write_fn writer, void *ctx, const char *text) {
    if (writer != NULL && text != NULL) {
        writer(ctx, text);
    }
}

enum vantaq_capability_status {
    VANTAQ_CAPABILITY_STATUS_OK = 0,
    VANTAQ_CAPABILITY_STATUS_INVALID_ARGUMENT,
    VANTAQ_CAPABILITY_STATUS_CAPACITY_EXCEEDED,
    VANTAQ_CAPABILITY_STATUS_ITEM_NOT_FOUND,
};

static const char *vantaq_capability_status_text(enum vantaq_capability_status status) {
    switch (status) {
    case VANTAQ_CAPABILITY_STATUS_OK:
        return "ok";
    case VANTAQ_CAPABILITY_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case VANTAQ_CAPABILITY_STATUS_CAPACITY_EXCEEDED:
        return "capacity exceeded";
    case VANTAQ_CAPABILITY_STATUS_ITEM_NOT_FOUND:
        return "item not found";
    default:
        return "unknown";
    }
}

static const char *vantaq_capability_list_name(enum vantaq_capability_list list) {
    switch (list) {
    case VANTAQ_CAPABILITY_SUPPORTED_CLAIMS:
        return "supported_claims";
    case VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS:
        return "signature_algorithms";
    case VANTAQ_CAPABILITY_EVIDENCE_FORMATS:
        return "evidence_formats";
    case VANTAQ_CAPABILITY_CHALLENGE_MODES:
        return "challenge_modes";
    case VANTAQ_CAPABILITY_STORAGE_MODES:
        return "storage_modes";
    default:
        return "unknown";
    }
}

static enum vantaq_capability_status
collect_capability_items(const struct vantaq_runtime_config *config,
                         enum vantaq_capability_list list, const char **items,
                         size_t items_capacity, size_t *count_out) {
    size_t i;
    size_t count;

    if (config == NULL || items == NULL || count_out == NULL) {
        return VANTAQ_CAPABILITY_STATUS_INVALID_ARGUMENT;
    }

    count = vantaq_runtime_capability_count(config, list);
    if (count > items_capacity) {
        return VANTAQ_CAPABILITY_STATUS_CAPACITY_EXCEEDED;
    }

    for (i = 0; i < count; i++) {
        const char *item = vantaq_runtime_capability_item(config, list, i);
        if (item == NULL) {
            return VANTAQ_CAPABILITY_STATUS_ITEM_NOT_FOUND;
        }
        items[i] = item;
    }

    *count_out = count;
    return VANTAQ_CAPABILITY_STATUS_OK;
}

int vantaq_app_run(int argc, char **argv, const struct vantaq_app_io *io) {
    const char *config_path             = VANTAQ_DEFAULT_CONFIG_PATH;
    struct vantaq_config_loader *loader = NULL;
    int i;
    int exit_code = 0;

    if (io == NULL) {
        return 70;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            char output[64];
            const char *version = vantaq_domain_version();
            int n               = snprintf(output, sizeof(output), "vantaqd %s\n", version);

            if (n <= 0 || (size_t)n >= sizeof(output)) {
                vantaq_write(io->write_err, io->ctx, "failed to render version\n");
                exit_code = 70;
                goto cleanup;
            }

            vantaq_write(io->write_out, io->ctx, output);
            exit_code = 0;
            goto cleanup;
        }

        if (strcmp(argv[i], "--config") == 0) {
            if (strcmp(config_path, VANTAQ_DEFAULT_CONFIG_PATH) != 0) {
                vantaq_write(io->write_err, io->ctx, "error: duplicate --config flag\n");
                exit_code = 64;
                goto cleanup;
            }
            if (i + 1 >= argc) {
                vantaq_write(io->write_err, io->ctx, VANTAQ_USAGE);
                exit_code = 64;
                goto cleanup;
            }
            config_path = argv[++i];
            continue;
        }

        vantaq_write(io->write_err, io->ctx, VANTAQ_USAGE);
        exit_code = 64;
        goto cleanup;
    }

    {
        enum vantaq_config_status status;
        const struct vantaq_runtime_config *config;
        struct vantaq_http_server_options server_options = {0};
        enum vantaq_http_server_status server_status;
        char output[192];
        const char *supported_claims[VANTAQ_MAX_LIST_ITEMS]     = {0};
        const char *signature_algorithms[VANTAQ_MAX_LIST_ITEMS] = {0};
        const char *evidence_formats[VANTAQ_MAX_LIST_ITEMS]     = {0};
        const char *challenge_modes[VANTAQ_MAX_LIST_ITEMS]      = {0};
        const char *storage_modes[VANTAQ_MAX_LIST_ITEMS]        = {0};
        size_t supported_claims_count                           = 0;
        size_t signature_algorithms_count                       = 0;
        size_t evidence_formats_count                           = 0;
        size_t challenge_modes_count                            = 0;
        size_t storage_modes_count                              = 0;
        int n;

        loader = vantaq_config_loader_create();
        if (loader == NULL) {
            vantaq_write(io->write_err, io->ctx, "config load failed: out of memory\n");
            exit_code = 70;
            goto cleanup;
        }

        status = vantaq_config_loader_load(loader, config_path);
        if (status != VANTAQ_CONFIG_STATUS_OK) {
            const char *err = vantaq_config_loader_last_error(loader);
            n               = snprintf(output, sizeof(output), "config load failed: %s\n",
                                       err != NULL ? err : "unknown error");
            if (n > 0 && (size_t)n < sizeof(output)) {
                vantaq_write(io->write_err, io->ctx, output);
            } else {
                vantaq_write(io->write_err, io->ctx, "config load failed\n");
            }
            exit_code = 78;
            goto cleanup;
        }

        config = vantaq_config_loader_config(loader);
        {
            struct {
                enum vantaq_capability_list list;
                const char **items;
                size_t *count;
            } lists[] = {
                {VANTAQ_CAPABILITY_SUPPORTED_CLAIMS, supported_claims, &supported_claims_count},
                {VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS, signature_algorithms,
                 &signature_algorithms_count},
                {VANTAQ_CAPABILITY_EVIDENCE_FORMATS, evidence_formats, &evidence_formats_count},
                {VANTAQ_CAPABILITY_CHALLENGE_MODES, challenge_modes, &challenge_modes_count},
                {VANTAQ_CAPABILITY_STORAGE_MODES, storage_modes, &storage_modes_count},
            };
            size_t list_idx;
            enum vantaq_capability_status cap_status;

            for (list_idx = 0; list_idx < sizeof(lists) / sizeof(lists[0]); list_idx++) {
                cap_status =
                    collect_capability_items(config, lists[list_idx].list, lists[list_idx].items,
                                             VANTAQ_MAX_LIST_ITEMS, lists[list_idx].count);
                if (cap_status != VANTAQ_CAPABILITY_STATUS_OK) {
                    n = snprintf(output, sizeof(output),
                                 "config load failed: list '%s' error: %s\n",
                                 vantaq_capability_list_name(lists[list_idx].list),
                                 vantaq_capability_status_text(cap_status));
                    if (n > 0 && (size_t)n < sizeof(output)) {
                        vantaq_write(io->write_err, io->ctx, output);
                    } else {
                        vantaq_write(io->write_err, io->ctx,
                                     "config load failed: invalid capabilities data\n");
                    }
                    exit_code = 78;
                    goto cleanup;
                }
            }
        }

        n = snprintf(output, sizeof(output), "vantaqd startup on %s:%d\n",
                     vantaq_runtime_service_listen_host(config),
                     vantaq_runtime_service_listen_port(config));
        if (n <= 0 || (size_t)n >= sizeof(output)) {
            vantaq_write(io->write_err, io->ctx, "failed to render startup message\n");
            exit_code = 70;
            goto cleanup;
        }

        vantaq_write(io->write_out, io->ctx, output);

        server_options.cbSize                     = sizeof(server_options);
        server_options.listen_host                = vantaq_runtime_service_listen_host(config);
        server_options.listen_port                = vantaq_runtime_service_listen_port(config);
        server_options.service_name               = "vantaqd";
        server_options.service_version            = vantaq_runtime_service_version(config);
        server_options.device_id                  = vantaq_runtime_device_id(config);
        server_options.device_model               = vantaq_runtime_device_model(config);
        server_options.device_serial_number       = vantaq_runtime_device_serial_number(config);
        server_options.device_manufacturer        = vantaq_runtime_device_manufacturer(config);
        server_options.device_firmware_version    = vantaq_runtime_device_firmware_version(config);
        server_options.supported_claims           = supported_claims;
        server_options.supported_claims_count     = supported_claims_count;
        server_options.signature_algorithms       = signature_algorithms;
        server_options.signature_algorithms_count = signature_algorithms_count;
        server_options.evidence_formats           = evidence_formats;
        server_options.evidence_formats_count     = evidence_formats_count;
        server_options.challenge_modes            = challenge_modes;
        server_options.challenge_modes_count      = challenge_modes_count;
        server_options.storage_modes              = storage_modes;
        server_options.storage_modes_count        = storage_modes_count;
        server_options.write_out                  = io->write_out;
        server_options.write_err                  = io->write_err;
        server_options.io_ctx                     = io->ctx;

        server_status = vantaq_http_server_run(&server_options);
        if (server_status != VANTAQ_HTTP_SERVER_STATUS_OK) {
            const char *err = vantaq_http_server_status_text(server_status);
            n               = snprintf(output, sizeof(output), "http server failed: %s\n",
                                       err != NULL ? err : "unknown error");
            if (n > 0 && (size_t)n < sizeof(output)) {
                vantaq_write(io->write_err, io->ctx, output);
            } else {
                vantaq_write(io->write_err, io->ctx, "http server failed\n");
            }
            exit_code = 78;
            goto cleanup;
        }
    }

cleanup:
    vantaq_config_loader_destroy(loader);
    return exit_code;
}
