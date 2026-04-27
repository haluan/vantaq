// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/memory/challenge_store_memory.h"
#include "infrastructure/memory/zero_struct.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* D-8: Internal vtable definition for the challenge store. */
struct vantaq_challenge_store_ops {
    enum vantaq_challenge_store_status (*insert)(struct vantaq_challenge_store *store,
                                                 struct vantaq_challenge *challenge);
    enum vantaq_challenge_store_status (*find_and_consume)(struct vantaq_challenge_store *store,
                                                           const char *challenge_id,
                                                           long current_time_ms, bool consume,
                                                           struct vantaq_challenge **out_challenge);
    enum vantaq_challenge_store_status (*remove)(struct vantaq_challenge_store *store,
                                                 const char *challenge_id);
    size_t (*count_pending_for_verifier)(struct vantaq_challenge_store *store,
                                         const char *verifier_id);
    size_t (*count_global_pending)(struct vantaq_challenge_store *store);
    void (*destroy)(struct vantaq_challenge_store *store);
};

struct vantaq_challenge_store {
    const struct vantaq_challenge_store_ops *ops;
    void *ctx;
};

struct memory_store_ctx {
    pthread_mutex_t mutex;
    size_t max_global;
    size_t max_per_verifier;
    struct vantaq_challenge **challenges;
};

/* Internal helper: must be called with mutex held. */
static void cleanup_internal(struct memory_store_ctx *ctx, long current_time_ms) {
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i] &&
            vantaq_challenge_is_expired(ctx->challenges[i], current_time_ms)) {
            vantaq_challenge_destroy(ctx->challenges[i]);
            ctx->challenges[i] = NULL;
        }
    }
}

static enum vantaq_challenge_store_status memory_insert(struct vantaq_challenge_store *store,
                                                        struct vantaq_challenge *challenge) {
    /* C-2: Validate challenge input before use */
    if (!store || !challenge)
        return VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT;
    struct memory_store_ctx *ctx = store->ctx;

    /* S-4, D-5: Robust mutex lock checking */
    if (pthread_mutex_lock(&ctx->mutex) != 0)
        return VANTAQ_CHALLENGE_STORE_ERROR_INTERNAL;

    /* D-2, D-3: Perform internal cleanup to ensure quotas exclude expired entries */
    cleanup_internal(ctx, vantaq_challenge_get_created_at_ms(challenge));

    size_t global_count         = 0;
    size_t verifier_count       = 0;
    ssize_t first_free          = -1;
    const char *new_verifier_id = vantaq_challenge_get_verifier_id(challenge);

    /* S-2: Guard against NULL verifier_id from accessor */
    if (!new_verifier_id) {
        pthread_mutex_unlock(&ctx->mutex);
        return VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            /* C-5: Prevent duplicate insertion of the same pointer */
            if (ctx->challenges[i] == challenge) {
                pthread_mutex_unlock(&ctx->mutex);
                return VANTAQ_CHALLENGE_STORE_OK; /* Already present */
            }

            global_count++;
            const char *v_id = vantaq_challenge_get_verifier_id(ctx->challenges[i]);
            if (v_id && strcmp(v_id, new_verifier_id) == 0) {
                verifier_count++;
            }
        } else if (first_free == -1) {
            first_free = (ssize_t)i;
        }
    }

    /* C-3: Quotas are now accurate as expired entries were cleaned */
    if (global_count >= ctx->max_global || first_free == -1) {
        pthread_mutex_unlock(&ctx->mutex);
        return VANTAQ_CHALLENGE_STORE_ERROR_GLOBAL_CAPACITY_REACHED;
    }

    if (verifier_count >= ctx->max_per_verifier) {
        pthread_mutex_unlock(&ctx->mutex);
        return VANTAQ_CHALLENGE_STORE_ERROR_VERIFIER_CAPACITY_REACHED;
    }

    /* C-4: No overflow risk as i is capped by max_global which was validated in create */
    ctx->challenges[first_free] = challenge;

    pthread_mutex_unlock(&ctx->mutex);
    return VANTAQ_CHALLENGE_STORE_OK;
}

static enum vantaq_challenge_store_status
memory_find_and_consume(struct vantaq_challenge_store *store, const char *challenge_id,
                        long current_time_ms, bool consume,
                        struct vantaq_challenge **out_challenge) {

    /* C-1: Validate ID input */
    if (!store || !challenge_id || !out_challenge)
        return VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT;
    struct memory_store_ctx *ctx = store->ctx;
    *out_challenge               = NULL;

    if (pthread_mutex_lock(&ctx->mutex) != 0)
        return VANTAQ_CHALLENGE_STORE_ERROR_INTERNAL;

    enum vantaq_challenge_store_status status = VANTAQ_CHALLENGE_STORE_ERROR_NOT_FOUND;

    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            const char *id = vantaq_challenge_get_id(ctx->challenges[i]);
            if (id && strcmp(id, challenge_id) == 0) {
                /* E-4: Handle expiry under lock */
                if (vantaq_challenge_is_expired(ctx->challenges[i], current_time_ms)) {
                    vantaq_challenge_destroy(ctx->challenges[i]);
                    ctx->challenges[i] = NULL;
                    status             = VANTAQ_CHALLENGE_STORE_ERROR_EXPIRED;
                } else {
                    /* S-1, D-1: Atomic find-and-consume under the same lock */
                    if (consume) {
                        if (!vantaq_challenge_mark_used(ctx->challenges[i])) {
                            status = VANTAQ_CHALLENGE_STORE_ERROR_INTERNAL; /* Already used? */
                        } else {
                            *out_challenge = ctx->challenges[i];
                            status         = VANTAQ_CHALLENGE_STORE_OK;
                        }
                    } else {
                        *out_challenge = ctx->challenges[i];
                        status         = VANTAQ_CHALLENGE_STORE_OK;
                    }
                }
                break;
            }
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
    return status;
}

static enum vantaq_challenge_store_status memory_remove(struct vantaq_challenge_store *store,
                                                        const char *challenge_id) {
    if (!store || !challenge_id)
        return VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT;
    struct memory_store_ctx *ctx = store->ctx;

    if (pthread_mutex_lock(&ctx->mutex) != 0)
        return VANTAQ_CHALLENGE_STORE_ERROR_INTERNAL;

    enum vantaq_challenge_store_status status = VANTAQ_CHALLENGE_STORE_ERROR_NOT_FOUND;
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            const char *id = vantaq_challenge_get_id(ctx->challenges[i]);
            if (id && strcmp(id, challenge_id) == 0) {
                /* D-4: Explicit removal */
                vantaq_challenge_destroy(ctx->challenges[i]);
                ctx->challenges[i] = NULL;
                status             = VANTAQ_CHALLENGE_STORE_OK;
                break;
            }
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
    return status;
}

static size_t memory_count_pending_for_verifier(struct vantaq_challenge_store *store,
                                                const char *verifier_id) {
    if (!store || !verifier_id)
        return 0;
    struct memory_store_ctx *ctx = store->ctx;
    size_t count                 = 0;

    if (pthread_mutex_lock(&ctx->mutex) != 0)
        return 0;
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            const char *v_id = vantaq_challenge_get_verifier_id(ctx->challenges[i]);
            if (v_id && strcmp(v_id, verifier_id) == 0) {
                count++;
            }
        }
    }
    pthread_mutex_unlock(&ctx->mutex);

    return count;
}

static size_t memory_count_global_pending(struct vantaq_challenge_store *store) {
    if (!store)
        return 0;
    struct memory_store_ctx *ctx = store->ctx;
    size_t count                 = 0;

    if (pthread_mutex_lock(&ctx->mutex) != 0)
        return 0;
    for (size_t i = 0; i < ctx->max_global; i++) {
        if (ctx->challenges[i]) {
            count++;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);

    return count;
}

static void memory_destroy(struct vantaq_challenge_store *store) {
    if (!store)
        return;
    struct memory_store_ctx *ctx = store->ctx;

    /* S-3, D-7: Ensure no concurrent access during destruction */
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

static const struct vantaq_challenge_store_ops memory_ops = {
    .insert                     = memory_insert,
    .find_and_consume           = memory_find_and_consume,
    .remove                     = memory_remove,
    .count_pending_for_verifier = memory_count_pending_for_verifier,
    .count_global_pending       = memory_count_global_pending,
    .destroy                    = memory_destroy,
};

struct vantaq_challenge_store *vantaq_challenge_store_memory_create(size_t max_global,
                                                                    size_t max_per_verifier) {
    /* Validate factory parameters */
    if (max_global == 0 || max_per_verifier == 0 || max_per_verifier > max_global) {
        return NULL;
    }

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

    store->ctx = ctx;
    store->ops = &memory_ops;

    return store;
}

/* API Wrappers to keep the vtable opaque (D-8) */

enum vantaq_challenge_store_status
vantaq_challenge_store_insert(struct vantaq_challenge_store *store,
                              struct vantaq_challenge *challenge) {
    if (!store || !store->ops || !store->ops->insert)
        return VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT;
    return store->ops->insert(store, challenge);
}

enum vantaq_challenge_store_status
vantaq_challenge_store_find_and_consume(struct vantaq_challenge_store *store,
                                        const char *challenge_id, long current_time_ms,
                                        bool consume, struct vantaq_challenge **out_challenge) {
    if (!store || !store->ops || !store->ops->find_and_consume)
        return VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT;
    return store->ops->find_and_consume(store, challenge_id, current_time_ms, consume,
                                        out_challenge);
}

enum vantaq_challenge_store_status
vantaq_challenge_store_remove(struct vantaq_challenge_store *store, const char *challenge_id) {
    if (!store || !store->ops || !store->ops->remove)
        return VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT;
    return store->ops->remove(store, challenge_id);
}

size_t vantaq_challenge_store_count_pending_for_verifier(struct vantaq_challenge_store *store,
                                                         const char *verifier_id) {
    if (!store || !store->ops || !store->ops->count_pending_for_verifier)
        return 0;
    return store->ops->count_pending_for_verifier(store, verifier_id);
}

size_t vantaq_challenge_store_count_global_pending(struct vantaq_challenge_store *store) {
    if (!store || !store->ops || !store->ops->count_global_pending)
        return 0;
    return store->ops->count_global_pending(store);
}

void vantaq_challenge_store_destroy(struct vantaq_challenge_store *store) {
    if (!store || !store->ops || !store->ops->destroy)
        return;
    store->ops->destroy(store);
}
