// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/memory/challenge_store_memory.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct memory_store_ctx {
    pthread_mutex_t mutex;
    size_t max_global;
    size_t max_per_verifier;
    struct vantaq_challenge **challenges;
};

static enum vantaq_challenge_store_status memory_insert(struct vantaq_challenge_store *store,
                                                        struct vantaq_challenge *challenge) {
    struct memory_store_ctx *ctx = store->ctx;
    pthread_mutex_lock(&ctx->mutex);

    size_t global_count         = 0;
    size_t verifier_count       = 0;
    int first_free              = -1;
    const char *new_verifier_id = vantaq_challenge_get_verifier_id(challenge);

    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            global_count++;
            if (strcmp(vantaq_challenge_get_verifier_id(ctx->challenges[i]), new_verifier_id) ==
                0) {
                verifier_count++;
            }
        } else if (first_free == -1) {
            first_free = (int)i;
        }
    }

    if (global_count >= ctx->max_global || first_free == -1) {
        pthread_mutex_unlock(&ctx->mutex);
        return VANTAQ_CHALLENGE_STORE_ERROR_GLOBAL_CAPACITY_REACHED;
    }

    if (verifier_count >= ctx->max_per_verifier) {
        pthread_mutex_unlock(&ctx->mutex);
        return VANTAQ_CHALLENGE_STORE_ERROR_VERIFIER_CAPACITY_REACHED;
    }

    ctx->challenges[first_free] = challenge;

    pthread_mutex_unlock(&ctx->mutex);
    return VANTAQ_CHALLENGE_STORE_OK;
}

static struct vantaq_challenge *memory_lookup(struct vantaq_challenge_store *store,
                                              const char *challenge_id) {
    struct memory_store_ctx *ctx   = store->ctx;
    struct vantaq_challenge *found = NULL;

    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i] &&
            strcmp(vantaq_challenge_get_id(ctx->challenges[i]), challenge_id) == 0) {
            found = ctx->challenges[i];
            break;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);

    return found;
}

static size_t memory_count_pending_for_verifier(struct vantaq_challenge_store *store,
                                                const char *verifier_id) {
    struct memory_store_ctx *ctx = store->ctx;
    size_t count                 = 0;

    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i] &&
            strcmp(vantaq_challenge_get_verifier_id(ctx->challenges[i]), verifier_id) == 0) {
            count++;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);

    return count;
}

static size_t memory_count_global_pending(struct vantaq_challenge_store *store) {
    struct memory_store_ctx *ctx = store->ctx;
    size_t count                 = 0;

    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            count++;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);

    return count;
}

static void memory_cleanup_expired(struct vantaq_challenge_store *store, long current_time_ms) {
    struct memory_store_ctx *ctx = store->ctx;

    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i] &&
            vantaq_challenge_is_expired(ctx->challenges[i], current_time_ms)) {
            vantaq_challenge_destroy(ctx->challenges[i]);
            ctx->challenges[i] = NULL;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);
}

static void memory_destroy(struct vantaq_challenge_store *store) {
    if (!store)
        return;
    struct memory_store_ctx *ctx = store->ctx;

    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            vantaq_challenge_destroy(ctx->challenges[i]);
        }
    }
    pthread_mutex_unlock(&ctx->mutex);
    pthread_mutex_destroy(&ctx->mutex);

    free(ctx->challenges);
    free(ctx);
    free(store);
}

struct vantaq_challenge_store *vantaq_challenge_store_memory_create(size_t max_global,
                                                                    size_t max_per_verifier) {
    struct vantaq_challenge_store *store = malloc(sizeof(struct vantaq_challenge_store));
    if (!store)
        return NULL;

    struct memory_store_ctx *ctx = malloc(sizeof(struct memory_store_ctx));
    if (!ctx) {
        free(store);
        return NULL;
    }

    ctx->challenges = calloc(max_global, sizeof(struct vantaq_challenge *));
    if (!ctx->challenges) {
        free(ctx);
        free(store);
        return NULL;
    }

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        free(ctx->challenges);
        free(ctx);
        free(store);
        return NULL;
    }

    ctx->max_global       = max_global;
    ctx->max_per_verifier = max_per_verifier;

    store->ctx                        = ctx;
    store->insert                     = memory_insert;
    store->lookup                     = memory_lookup;
    store->count_pending_for_verifier = memory_count_pending_for_verifier;
    store->count_global_pending       = memory_count_global_pending;
    store->cleanup_expired            = memory_cleanup_expired;
    store->destroy                    = memory_destroy;

    return store;
}
