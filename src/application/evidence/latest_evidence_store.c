// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/latest_evidence_store.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct evidence_entry {
    char verifier_id[VANTAQ_VERIFIER_ID_MAX];
    struct vantaq_evidence *evidence;
    char *signature_b64;
    bool active;
};

struct vantaq_latest_evidence_store {
    pthread_mutex_t mutex;
    size_t max_verifiers;
    struct evidence_entry *entries;
};

static struct vantaq_evidence *clone_evidence(const struct vantaq_evidence *evidence) {
    if (!evidence)
        return NULL;
    struct vantaq_evidence *clone = NULL;
    vantaq_evidence_create(
        vantaq_evidence_get_evidence_id(evidence), vantaq_evidence_get_device_id(evidence),
        vantaq_evidence_get_verifier_id(evidence), vantaq_evidence_get_challenge_id(evidence),
        vantaq_evidence_get_nonce(evidence), vantaq_evidence_get_purpose(evidence),
        vantaq_evidence_get_issued_at_unix(evidence), vantaq_evidence_get_claims(evidence),
        vantaq_evidence_get_signature_alg(evidence), vantaq_evidence_get_signature(evidence),
        &clone);
    return clone;
}

struct vantaq_latest_evidence_store *vantaq_latest_evidence_store_create(size_t max_verifiers) {
    if (max_verifiers == 0)
        return NULL;

    struct vantaq_latest_evidence_store *store =
        malloc(sizeof(struct vantaq_latest_evidence_store));
    if (!store)
        return NULL;

    store->max_verifiers = max_verifiers;
    store->entries       = calloc(max_verifiers, sizeof(struct evidence_entry));
    if (!store->entries) {
        free(store);
        return NULL;
    }

    if (pthread_mutex_init(&store->mutex, NULL) != 0) {
        free(store->entries);
        free(store);
        return NULL;
    }

    return store;
}

void vantaq_latest_evidence_store_destroy(struct vantaq_latest_evidence_store *store) {
    if (!store)
        return;

    for (size_t i = 0; i < store->max_verifiers; i++) {
        if (store->entries[i].active) {
            vantaq_evidence_destroy(store->entries[i].evidence);
            free(store->entries[i].signature_b64);
        }
    }

    pthread_mutex_destroy(&store->mutex);
    free(store->entries);
    free(store);
}

vantaq_latest_evidence_err_t
vantaq_latest_evidence_store_put(struct vantaq_latest_evidence_store *store,
                                 const char *verifier_id, const struct vantaq_evidence *evidence,
                                 const char *signature_b64) {
    if (!store || !verifier_id || !evidence || !signature_b64) {
        return VANTAQ_LATEST_EVIDENCE_ERR_INVALID_ARG;
    }

    if (pthread_mutex_lock(&store->mutex) != 0) {
        return VANTAQ_LATEST_EVIDENCE_ERR_INTERNAL;
    }

    ssize_t slot      = -1;
    ssize_t free_slot = -1;

    for (size_t i = 0; i < store->max_verifiers; i++) {
        if (store->entries[i].active) {
            if (strcmp(store->entries[i].verifier_id, verifier_id) == 0) {
                slot = i;
                break;
            }
        } else if (free_slot == -1) {
            free_slot = i;
        }
    }

    if (slot == -1) {
        if (free_slot == -1) {
            pthread_mutex_unlock(&store->mutex);
            return VANTAQ_LATEST_EVIDENCE_ERR_FULL;
        }
        slot = free_slot;
    }

    struct vantaq_evidence *new_ev = clone_evidence(evidence);
    char *new_sig                  = strdup(signature_b64);

    if (!new_ev || !new_sig) {
        if (new_ev)
            vantaq_evidence_destroy(new_ev);
        if (new_sig)
            free(new_sig);
        pthread_mutex_unlock(&store->mutex);
        return VANTAQ_LATEST_EVIDENCE_ERR_MALLOC_FAILED;
    }

    // Replace
    if (store->entries[slot].active) {
        vantaq_evidence_destroy(store->entries[slot].evidence);
        free(store->entries[slot].signature_b64);
    }

    strncpy(store->entries[slot].verifier_id, verifier_id, VANTAQ_VERIFIER_ID_MAX - 1);
    store->entries[slot].verifier_id[VANTAQ_VERIFIER_ID_MAX - 1] = '\0';
    store->entries[slot].evidence                                = new_ev;
    store->entries[slot].signature_b64                           = new_sig;
    store->entries[slot].active                                  = true;

    pthread_mutex_unlock(&store->mutex);
    return VANTAQ_LATEST_EVIDENCE_OK;
}

vantaq_latest_evidence_err_t
vantaq_latest_evidence_store_get(struct vantaq_latest_evidence_store *store,
                                 const char *verifier_id, struct vantaq_evidence **out_evidence,
                                 char **out_signature_b64) {
    if (!store || !verifier_id || !out_evidence || !out_signature_b64) {
        return VANTAQ_LATEST_EVIDENCE_ERR_INVALID_ARG;
    }

    if (pthread_mutex_lock(&store->mutex) != 0) {
        return VANTAQ_LATEST_EVIDENCE_ERR_INTERNAL;
    }

    vantaq_latest_evidence_err_t status = VANTAQ_LATEST_EVIDENCE_ERR_NOT_FOUND;

    for (size_t i = 0; i < store->max_verifiers; i++) {
        if (store->entries[i].active && strcmp(store->entries[i].verifier_id, verifier_id) == 0) {
            struct vantaq_evidence *clone = clone_evidence(store->entries[i].evidence);
            char *sig                     = strdup(store->entries[i].signature_b64);

            if (!clone || !sig) {
                if (clone)
                    vantaq_evidence_destroy(clone);
                if (sig)
                    free(sig);
                status = VANTAQ_LATEST_EVIDENCE_ERR_MALLOC_FAILED;
            } else {
                *out_evidence      = clone;
                *out_signature_b64 = sig;
                status             = VANTAQ_LATEST_EVIDENCE_OK;
            }
            break;
        }
    }

    pthread_mutex_unlock(&store->mutex);
    return status;
}
