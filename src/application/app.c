// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"

#include "application/evidence/latest_evidence_store.h"
#include "domain/ring_buffer/ring_buffer.h"
#include "domain/version.h"
#include "evidence_ring_buffer.h"
#include "infrastructure/audit_log.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/crypto/device_key_loader.h"
#include "infrastructure/http_server.h"
#include "infrastructure/memory/challenge_store_memory.h"
#include "infrastructure/memory/zero_struct.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define VANTAQ_USAGE "Usage: vantaqd [--version] [--config <path>]\n"
#define VANTAQ_DEFAULT_AUDIT_LOG_PATH "/var/lib/vantaqd/audit.log"
#define VANTAQ_DEFAULT_AUDIT_LOG_MAX_BYTES (10U * 1024U * 1024U)
#define VANTAQ_AUDIT_LOG_MAX_BYTES_CAP (1024U * 1024U * 1024U)

/**
 * Internal enumeration for list collection status.
 */
enum vantaq_app_list_status {
    VANTAQ_APP_LIST_OK = 0,
    VANTAQ_APP_LIST_OVERFLOW,
    VANTAQ_APP_LIST_ERROR,
};

/**
 * Internal application context used to group state during startup and refactor
 * the monolithic run function (D-6). This also addresses D-3 by moving large
 * pointer arrays off the stack and into a managed structure.
 */
struct vantaq_app_context {
    const struct vantaq_app_io *io;
    struct vantaq_config_loader *loader;
    struct vantaq_challenge_store *store;
    struct vantaq_latest_evidence_store *latest_store;
    struct vantaq_ring_buffer_config *ring_config;
    struct vantaq_evidence_ring_buffer *ring_buffer;
    vantaq_device_key_t *device_key;
    const char *config_path;
    bool config_path_set;
    const char *audit_log_path;
    bool audit_log_path_owned;
    size_t audit_log_max_bytes;
    bool audit_log_max_bytes_env_set;

    /* Capability and access control lists */
    const char *supported_claims[VANTAQ_MAX_LIST_ITEMS];
    size_t supported_claims_count;
    const char *signature_algorithms[VANTAQ_MAX_LIST_ITEMS];
    size_t signature_algorithms_count;
    const char *evidence_formats[VANTAQ_MAX_LIST_ITEMS];
    size_t evidence_formats_count;
    const char *challenge_modes[VANTAQ_MAX_LIST_ITEMS];
    size_t challenge_modes_count;
    const char *storage_modes[VANTAQ_MAX_LIST_ITEMS];
    size_t storage_modes_count;
    const char *allowed_subnets[VANTAQ_MAX_LIST_ITEMS];
    size_t allowed_subnets_count;

    int exit_code;
};

static int vantaq_write(const vantaq_io_write_fn writer, void *ctx, const char *text) {
    if (writer != NULL && text != NULL) {
        return writer(ctx, text);
    }
    return -1;
}

struct collect_items_ctx {
    const struct vantaq_runtime_config *config;
    enum vantaq_capability_list capability_list;
};
struct collect_subnet_ctx {
    const struct vantaq_runtime_config *config;
};

typedef const char *(*vantaq_app_accessor_fn)(size_t index, void *ctx);

static const char *capability_accessor(size_t index, void *ctx) {
    struct collect_items_ctx *c = (struct collect_items_ctx *)ctx;
    return vantaq_runtime_capability_item(c->config, c->capability_list, index);
}

static const char *subnet_accessor(size_t index, void *ctx) {
    struct collect_subnet_ctx *c = (struct collect_subnet_ctx *)ctx;
    return vantaq_runtime_allowed_subnet_item(c->config, index);
}

static enum vantaq_app_list_status collect_items(const char **items, size_t items_capacity,
                                                 size_t *count_out, size_t count,
                                                 vantaq_app_accessor_fn accessor, void *ctx) {
    size_t i;
    if (count > items_capacity) {
        return VANTAQ_APP_LIST_OVERFLOW;
    }
    for (i = 0; i < count; i++) {
        items[i] = accessor(i, ctx);
        if (items[i] == NULL) {
            return VANTAQ_APP_LIST_ERROR;
        }
    }
    *count_out = count;
    return VANTAQ_APP_LIST_OK;
}

static enum vantaq_app_list_status
collect_capability_items(const struct vantaq_runtime_config *config,
                         enum vantaq_capability_list list_type, const char **items,
                         size_t max_items, size_t *count_out) {
    struct collect_items_ctx ctx = {config, list_type};
    size_t count                 = vantaq_runtime_capability_count(config, list_type);
    return collect_items(items, max_items, count_out, count, capability_accessor, &ctx);
}

static enum vantaq_app_list_status
collect_allowed_subnet_items(const struct vantaq_runtime_config *config, const char **items,
                             size_t items_capacity, size_t *count_out) {
    struct collect_subnet_ctx ctx = {config};
    size_t count                  = vantaq_runtime_allowed_subnet_count(config);
    return collect_items(items, items_capacity, count_out, count, subnet_accessor, &ctx);
}

/**
 * Parses CLI arguments. Addresses E-1, E-2, and E-4.
 */
static bool vantaq_app_parse_cli(struct vantaq_app_context *ctx, int argc, char **argv) {
    int arg_idx;

    for (arg_idx = 1; arg_idx < argc; arg_idx++) {
        if (argv[arg_idx] == NULL) {
            continue;
        }

        if (strcmp(argv[arg_idx], "--version") == 0) {
            char output[64];
            const char *version = vantaq_domain_version();
            int n               = snprintf(output, sizeof(output), "vantaqd %s\n", version);

            if (n <= 0 || (size_t)n >= sizeof(output)) {
                (void)vantaq_write(ctx->io->write_err, ctx->io->ctx, "failed to render version\n");
                ctx->exit_code = 70;
                return false;
            }

            (void)vantaq_write(ctx->io->write_out, ctx->io->ctx, output);
            ctx->exit_code = 0;
            return false;
        }

        if (strcmp(argv[arg_idx], "--config") == 0) {
            if (ctx->config_path_set) {
                (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                                   "error: duplicate --config flag\n");
                ctx->exit_code = 64;
                return false;
            }
            if (arg_idx + 1 >= argc) {
                (void)vantaq_write(ctx->io->write_err, ctx->io->ctx, VANTAQ_USAGE);
                ctx->exit_code = 64;
                return false;
            }
            ctx->config_path     = argv[++arg_idx];
            ctx->config_path_set = true;
            continue;
        }

        (void)vantaq_write(ctx->io->write_err, ctx->io->ctx, VANTAQ_USAGE);
        ctx->exit_code = 64;
        return false;
    }

    return true;
}

/**
 * Resolves audit log configuration from environment.
 * Security policy: audit log path is not overrideable via environment.
 */
static bool vantaq_app_resolve_audit(struct vantaq_app_context *ctx) {
    const char *env_path;
    const char *env_max_bytes;
    int n;

    /* Handle Path */
    env_path = getenv("VANTAQ_AUDIT_LOG_PATH");
    if (env_path != NULL && env_path[0] != '\0') {
        (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                           "error: VANTAQ_AUDIT_LOG_PATH override is not allowed\n");
        ctx->exit_code = 64;
        return false;
    }

    /* Handle Max Bytes */
    env_max_bytes = getenv("VANTAQ_AUDIT_LOG_MAX_BYTES");
    if (env_max_bytes != NULL && env_max_bytes[0] != '\0') {
        char *end;
        unsigned long long val;
        errno = 0;
        val   = strtoull(env_max_bytes, &end, 10);
        if (errno == ERANGE || *end != '\0' || val == 0 || val > VANTAQ_AUDIT_LOG_MAX_BYTES_CAP) {
            (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                               "error: invalid VANTAQ_AUDIT_LOG_MAX_BYTES (must be positive "
                               "integer <= 1GB)\n");
            ctx->exit_code = 64;
            return false;
        }
        ctx->audit_log_max_bytes         = (size_t)val;
        ctx->audit_log_max_bytes_env_set = true;

        {
            char msg[256];
            n = snprintf(msg, sizeof(msg),
                         "SECURITY WARNING: Audit log max size redirected by environment "
                         "variable: %llu\n",
                         val);
            if (n > 0 && (size_t)n < sizeof(msg)) {
                (void)vantaq_write(ctx->io->write_err, ctx->io->ctx, msg);
            }
        }
    }

    return true;
}

/**
 * Loads configuration and populates capabilities. Addresses E-5, D-3.
 */
static bool vantaq_app_load_and_collect(struct vantaq_app_context *ctx) {
    enum vantaq_config_status status;
    const struct vantaq_runtime_config *config;
    char output[512];
    int n;
    int cfg_fd;
    struct stat cfg_st;

    ctx->loader = vantaq_config_loader_create();
    if (ctx->loader == NULL) {
        (void)vantaq_write(ctx->io->write_err, ctx->io->ctx, "config load failed: out of memory\n");
        ctx->exit_code = 70;
        return false;
    }

    cfg_fd = open(ctx->config_path, O_RDONLY
#ifdef O_CLOEXEC
                                        | O_CLOEXEC
#endif
#ifdef O_NOFOLLOW
                                        | O_NOFOLLOW
#endif
    );
    if (cfg_fd < 0) {
        n = snprintf(output, sizeof(output), "config load failed: unable to open config file: %s\n",
                     ctx->config_path);
        (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                           (n > 0 && (size_t)n < sizeof(output)) ? output : "config load failed\n");
        ctx->exit_code = 78;
        return false;
    }
    if (fstat(cfg_fd, &cfg_st) != 0 || !S_ISREG(cfg_st.st_mode)) {
        (void)close(cfg_fd);
        (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                           "config load failed: config path is not a regular file\n");
        ctx->exit_code = 78;
        return false;
    }
    status = vantaq_config_loader_load_fd(ctx->loader, cfg_fd, ctx->config_path);
    (void)close(cfg_fd);
    if (status != VANTAQ_CONFIG_STATUS_OK) {
        const char *err = vantaq_config_loader_last_error(ctx->loader);
        n               = snprintf(output, sizeof(output), "config load failed: %s\n",
                                   err != NULL ? err : "unknown error");
        (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                           (n > 0 && (size_t)n < sizeof(output)) ? output : "config load failed\n");
        ctx->exit_code = 78;
        return false;
    }

    config = vantaq_config_loader_config(ctx->loader);

    /* Finalize Audit Config */
    if (!ctx->audit_log_max_bytes_env_set) {
        size_t config_max_bytes = vantaq_runtime_audit_log_max_bytes(config);
        ctx->audit_log_max_bytes =
            (config_max_bytes > 0) ? config_max_bytes : VANTAQ_DEFAULT_AUDIT_LOG_MAX_BYTES;
    }

    {
        const char *config_path_val = vantaq_runtime_audit_log_path(config);
        const char *resolved_path   = VANTAQ_DEFAULT_AUDIT_LOG_PATH;
        char *owned_path;
        if (config_path_val != NULL && config_path_val[0] != '\0') {
            if (strlen(config_path_val) >= PATH_MAX) {
                (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                                   "error: audit.path exceeds maximum path length\n");
                ctx->exit_code = 78;
                return false;
            }
            resolved_path = config_path_val;
        }
        owned_path = strdup(resolved_path);
        if (owned_path == NULL) {
            (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                               "error: out of memory for audit path\n");
            ctx->exit_code = 70;
            return false;
        }
        ctx->audit_log_path       = owned_path;
        ctx->audit_log_path_owned = true;
    }

    /* Collect capabilities */
    {
        struct {
            enum vantaq_capability_list list;
            const char **items;
            size_t *count;
        } lists[] = {
            {VANTAQ_CAPABILITY_SUPPORTED_CLAIMS, ctx->supported_claims,
             &ctx->supported_claims_count},
            {VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS, ctx->signature_algorithms,
             &ctx->signature_algorithms_count},
            {VANTAQ_CAPABILITY_EVIDENCE_FORMATS, ctx->evidence_formats,
             &ctx->evidence_formats_count},
            {VANTAQ_CAPABILITY_CHALLENGE_MODES, ctx->challenge_modes, &ctx->challenge_modes_count},
            {VANTAQ_CAPABILITY_STORAGE_MODES, ctx->storage_modes, &ctx->storage_modes_count},
        };
        size_t i;

        for (i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
            enum vantaq_app_list_status cap_status = collect_capability_items(
                config, lists[i].list, lists[i].items, VANTAQ_MAX_LIST_ITEMS, lists[i].count);
            if (cap_status != VANTAQ_APP_LIST_OK) {
                (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                                   "config load failed: invalid capabilities data\n");
                ctx->exit_code = 78;
                return false;
            }
        }
    }

    /* Collect subnets */
    if (collect_allowed_subnet_items(config, ctx->allowed_subnets, VANTAQ_MAX_LIST_ITEMS,
                                     &ctx->allowed_subnets_count) != VANTAQ_APP_LIST_OK) {
        (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                           "config load failed: invalid network access data\n");
        ctx->exit_code = 78;
        return false;
    }

    /* Load device key */
    {
        const char *priv_path = vantaq_runtime_device_priv_key_path(config);
        const char *pub_path  = vantaq_runtime_device_pub_key_path(config);
        vantaq_key_err_t kerr = vantaq_device_key_load(NULL, priv_path, pub_path, &ctx->device_key);
        if (kerr != VANTAQ_KEY_OK) {
            (void)vantaq_write(ctx->io->write_err, ctx->io->ctx,
                               "config load failed: failed to load device key\n");
            ctx->exit_code = 70;
            return false;
        }
    }

    return true;
}

/**
 * Main application entry point. Orchestrates the startup sequence.
 */
int vantaq_app_run(int argc, char **argv, const struct vantaq_app_io *io) {
    struct vantaq_app_context ctx;
    VANTAQ_ZERO_STRUCT(ctx);

    if (io == NULL || io->cbSize != sizeof(struct vantaq_app_io)) {
        return 70;
    }
    ctx.io          = io;
    ctx.config_path = VANTAQ_DEFAULT_CONFIG_PATH;

    (void)signal(SIGPIPE, SIG_IGN);

    if (argc > 0 && argv == NULL) {
        (void)vantaq_write(io->write_err, io->ctx, "error: argc > 0 but argv is NULL\n");
        return 64;
    }

    if (!vantaq_app_parse_cli(&ctx, argc, argv)) {
        goto cleanup;
    }

    if (!vantaq_app_resolve_audit(&ctx)) {
        goto cleanup;
    }

    if (!vantaq_app_load_and_collect(&ctx)) {
        goto cleanup;
    }

    {
        const struct vantaq_runtime_config *config = vantaq_config_loader_config(ctx.loader);
        struct vantaq_http_server_options server_options;
        char startup_msg[256];
        int n;

        VANTAQ_ZERO_STRUCT(server_options);
        server_options.cbSize                     = sizeof(server_options);
        server_options.runtime_config             = config;
        server_options.listen_host                = vantaq_runtime_service_listen_host(config);
        server_options.listen_port                = vantaq_runtime_service_listen_port(config);
        server_options.service_name               = "vantaqd";
        server_options.service_version            = vantaq_domain_version();
        server_options.device_id                  = vantaq_runtime_device_id(config);
        server_options.device_model               = vantaq_runtime_device_model(config);
        server_options.device_serial_number       = vantaq_runtime_device_serial_number(config);
        server_options.device_manufacturer        = vantaq_runtime_device_manufacturer(config);
        server_options.device_firmware_version    = vantaq_runtime_device_firmware_version(config);
        server_options.supported_claims           = ctx.supported_claims;
        server_options.supported_claims_count     = ctx.supported_claims_count;
        server_options.signature_algorithms       = ctx.signature_algorithms;
        server_options.signature_algorithms_count = ctx.signature_algorithms_count;
        server_options.evidence_formats           = ctx.evidence_formats;
        server_options.evidence_formats_count     = ctx.evidence_formats_count;
        server_options.challenge_modes            = ctx.challenge_modes;
        server_options.challenge_modes_count      = ctx.challenge_modes_count;
        server_options.storage_modes              = ctx.storage_modes;
        server_options.storage_modes_count        = ctx.storage_modes_count;
        server_options.allowed_subnets            = ctx.allowed_subnets;
        server_options.allowed_subnets_count      = ctx.allowed_subnets_count;
        server_options.dev_allow_all_networks     = vantaq_runtime_dev_allow_all_networks(config);
        server_options.audit_log_path             = ctx.audit_log_path;
        server_options.audit_log_max_bytes        = ctx.audit_log_max_bytes;
        server_options.tls_enabled                = vantaq_runtime_tls_enabled(config);
        server_options.tls_server_cert_path       = vantaq_runtime_tls_server_cert_path(config);
        server_options.tls_server_key_path        = vantaq_runtime_tls_server_key_path(config);
        server_options.tls_trusted_client_ca_path =
            vantaq_runtime_tls_trusted_client_ca_path(config);
        server_options.tls_require_client_cert = vantaq_runtime_tls_require_client_cert(config);

        if (!server_options.tls_enabled) {
            (void)vantaq_write(io->write_err, io->ctx,
                               "SECURITY WARNING: mTLS is DISABLED. Server is operating in "
                               "INSECURE mode.\n");
        }

        ctx.store =
            vantaq_challenge_store_memory_create(vantaq_runtime_challenge_max_global(config),
                                                 vantaq_runtime_challenge_max_per_verifier(config));
        if (ctx.store == NULL) {
            (void)vantaq_write(io->write_err, io->ctx,
                               "startup failed: failed to create challenge store\n");
            ctx.exit_code = 70;
            goto cleanup;
        }
        ctx.latest_store =
            vantaq_latest_evidence_store_create(vantaq_runtime_verifier_count(config));
        if (ctx.latest_store == NULL) {
            (void)vantaq_write(io->write_err, io->ctx,
                               "startup failed: failed to create latest evidence store\n");
            ctx.exit_code = 70;
            goto cleanup;
        }

        if (vantaq_ring_buffer_config_create(vantaq_runtime_evidence_store_file_path(config),
                                             vantaq_runtime_evidence_store_max_records(config),
                                             vantaq_runtime_evidence_store_max_record_bytes(config),
                                             vantaq_runtime_evidence_store_fsync_on_append(config),
                                             &ctx.ring_config) != RING_BUFFER_OK) {
            (void)vantaq_write(io->write_err, io->ctx,
                               "startup failed: invalid evidence ring buffer config\n");
            ctx.exit_code = 78;
            goto cleanup;
        }

        if (vantaq_evidence_ring_buffer_open(ctx.ring_config, &ctx.ring_buffer) !=
            VANTAQ_EVIDENCE_RING_OPEN_OK) {
            (void)vantaq_write(io->write_err, io->ctx,
                               "startup failed: failed to open evidence ring buffer\n");
            ctx.exit_code = 70;
            goto cleanup;
        }

        server_options.challenge_store       = ctx.store;
        server_options.latest_evidence_store = ctx.latest_store;
        server_options.evidence_ring_buffer  = ctx.ring_buffer;
        server_options.device_key            = ctx.device_key;
        server_options.challenge_ttl_seconds = vantaq_runtime_challenge_ttl_seconds(config);
        server_options.write_out             = io->write_out;
        server_options.write_err             = io->write_err;
        server_options.io_ctx                = io->ctx;

        n = snprintf(startup_msg, sizeof(startup_msg), "vantaqd startup on %s:%d\n",
                     server_options.listen_host, server_options.listen_port);
        if (n > 0 && (size_t)n < sizeof(startup_msg)) {
            (void)vantaq_write(io->write_out, io->ctx, startup_msg);
        }

        /*
         * Execution enters the synchronous HTTP server loop. This function only
         * returns after it has stopped accepting requests and closed its listener,
         * ensuring that all pointers into the app context remain valid
         * throughout the server's lifetime (C-1).
         */
        if (vantaq_http_server_run(&server_options) != VANTAQ_HTTP_SERVER_STATUS_OK) {
            (void)vantaq_write(io->write_err, io->ctx, "http server failed: runtime error\n");
            ctx.exit_code = 71;
        }
    }

cleanup:
    if (ctx.audit_log_path_owned) {
        free((void *)ctx.audit_log_path);
    }
    if (ctx.store != NULL) {
        vantaq_challenge_store_destroy(ctx.store);
    }
    if (ctx.latest_store != NULL) {
        vantaq_latest_evidence_store_destroy(ctx.latest_store);
    }
    if (ctx.ring_buffer != NULL) {
        vantaq_evidence_ring_buffer_destroy(ctx.ring_buffer);
    }
    if (ctx.ring_config != NULL) {
        vantaq_ring_buffer_config_destroy(ctx.ring_config);
    }
    if (ctx.device_key != NULL) {
        vantaq_device_key_destroy(ctx.device_key);
    }
    if (ctx.loader != NULL) {
        vantaq_config_loader_destroy(ctx.loader);
    }
    return ctx.exit_code;
}
