// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/latest_evidence_store.h"
#include "infrastructure/memory/zero_struct.h"
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

static vantaq_evidence_err_t clone_evidence(const struct vantaq_evidence *evidence,
                                            struct vantaq_evidence **out_clone) {
    if (!evidence || !out_clone) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
    }
    *out_clone = NULL;
    return vantaq_evidence_create(
        vantaq_evidence_get_evidence_id(evidence), vantaq_evidence_get_device_id(evidence),
        vantaq_evidence_get_verifier_id(evidence), vantaq_evidence_get_challenge_id(evidence),
        vantaq_evidence_get_nonce(evidence), vantaq_evidence_get_purpose(evidence),
        vantaq_evidence_get_issued_at_unix(evidence), vantaq_evidence_get_claims(evidence),
        vantaq_evidence_get_signature_alg(evidence), vantaq_evidence_get_signature(evidence),
        out_clone);
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
            vantaq_explicit_bzero(store->entries[i].signature_b64,
                                  strlen(store->entries[i].signature_b64));
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
    if (strlen(verifier_id) >= VANTAQ_VERIFIER_ID_MAX) {
        return VANTAQ_LATEST_EVIDENCE_ERR_VERIFIER_ID_TOO_LONG;
    }

    struct vantaq_evidence *new_ev  = NULL;
    vantaq_evidence_err_t clone_err = clone_evidence(evidence, &new_ev);
    if (clone_err != VANTAQ_EVIDENCE_OK) {
        return (clone_err == VANTAQ_EVIDENCE_ERR_MALLOC_FAILED)
                   ? VANTAQ_LATEST_EVIDENCE_ERR_MALLOC_FAILED
                   : VANTAQ_LATEST_EVIDENCE_ERR_INTERNAL;
    }
    char *new_sig = strdup(signature_b64);
    if (!new_sig) {
        vantaq_evidence_destroy(new_ev);
        return VANTAQ_LATEST_EVIDENCE_ERR_MALLOC_FAILED;
    }

    if (pthread_mutex_lock(&store->mutex) != 0) {
        vantaq_evidence_destroy(new_ev);
        free(new_sig);
        return VANTAQ_LATEST_EVIDENCE_ERR_INTERNAL;
    }

    ssize_t slot      = -1;
    ssize_t free_slot = -1;

    // NOTE: Linear O(n) scan. Optimized for small max_verifiers (addresses D3).
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
            vantaq_evidence_destroy(new_ev);
            vantaq_explicit_bzero(new_sig, strlen(new_sig));
            free(new_sig);
            return VANTAQ_LATEST_EVIDENCE_ERR_FULL;
        }
        slot = free_slot;
    }

    // Replace
    struct vantaq_evidence *old_ev = NULL;
    char *old_sig                  = NULL;
    if (store->entries[slot].active) {
        old_ev  = store->entries[slot].evidence;
        old_sig = store->entries[slot].signature_b64;
    }

    strncpy(store->entries[slot].verifier_id, verifier_id, VANTAQ_VERIFIER_ID_MAX - 1);
    store->entries[slot].verifier_id[VANTAQ_VERIFIER_ID_MAX - 1] = '\0';
    store->entries[slot].evidence                                = new_ev;
    store->entries[slot].signature_b64                           = new_sig;
    store->entries[slot].active                                  = true;

    pthread_mutex_unlock(&store->mutex);
    if (old_ev) {
        vantaq_evidence_destroy(old_ev);
    }
    if (old_sig) {
        vantaq_explicit_bzero(old_sig, strlen(old_sig));
        free(old_sig);
    }
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
    char evidence_id[VANTAQ_EVIDENCE_ID_MAX];
    char device_id[VANTAQ_DEVICE_ID_MAX];
    char verifier_id_copy[VANTAQ_VERIFIER_ID_MAX];
    char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
    char nonce[VANTAQ_NONCE_MAX];
    char purpose[VANTAQ_PURPOSE_MAX];
    int64_t issued_at_unix = 0;
    char claims[VANTAQ_CLAIMS_MAX];
    char signature_alg[VANTAQ_SIGNATURE_ALG_MAX];
    char signature[VANTAQ_SIGNATURE_MAX];
    char signature_b64[VANTAQ_SIGNATURE_MAX];
    bool found = false;

    // NOTE: Linear O(n) scan. Optimized for small max_verifiers (addresses D3).
    for (size_t i = 0; i < store->max_verifiers; i++) {
        if (store->entries[i].active && strcmp(store->entries[i].verifier_id, verifier_id) == 0) {
            strncpy(evidence_id, vantaq_evidence_get_evidence_id(store->entries[i].evidence),
                    VANTAQ_EVIDENCE_ID_MAX - 1);
            evidence_id[VANTAQ_EVIDENCE_ID_MAX - 1] = '\0';
            strncpy(device_id, vantaq_evidence_get_device_id(store->entries[i].evidence),
                    VANTAQ_DEVICE_ID_MAX - 1);
            device_id[VANTAQ_DEVICE_ID_MAX - 1] = '\0';
            strncpy(verifier_id_copy, vantaq_evidence_get_verifier_id(store->entries[i].evidence),
                    VANTAQ_VERIFIER_ID_MAX - 1);
            verifier_id_copy[VANTAQ_VERIFIER_ID_MAX - 1] = '\0';
            strncpy(challenge_id, vantaq_evidence_get_challenge_id(store->entries[i].evidence),
                    VANTAQ_CHALLENGE_ID_MAX - 1);
            challenge_id[VANTAQ_CHALLENGE_ID_MAX - 1] = '\0';
            strncpy(nonce, vantaq_evidence_get_nonce(store->entries[i].evidence),
                    VANTAQ_NONCE_MAX - 1);
            nonce[VANTAQ_NONCE_MAX - 1] = '\0';
            strncpy(purpose, vantaq_evidence_get_purpose(store->entries[i].evidence),
                    VANTAQ_PURPOSE_MAX - 1);
            purpose[VANTAQ_PURPOSE_MAX - 1] = '\0';
            issued_at_unix = vantaq_evidence_get_issued_at_unix(store->entries[i].evidence);
            strncpy(claims, vantaq_evidence_get_claims(store->entries[i].evidence),
                    VANTAQ_CLAIMS_MAX - 1);
            claims[VANTAQ_CLAIMS_MAX - 1] = '\0';
            strncpy(signature_alg, vantaq_evidence_get_signature_alg(store->entries[i].evidence),
                    VANTAQ_SIGNATURE_ALG_MAX - 1);
            signature_alg[VANTAQ_SIGNATURE_ALG_MAX - 1] = '\0';
            strncpy(signature, vantaq_evidence_get_signature(store->entries[i].evidence),
                    VANTAQ_SIGNATURE_MAX - 1);
            signature[VANTAQ_SIGNATURE_MAX - 1] = '\0';
            strncpy(signature_b64, store->entries[i].signature_b64, VANTAQ_SIGNATURE_MAX - 1);
            signature_b64[VANTAQ_SIGNATURE_MAX - 1] = '\0';
            found                                   = true;
            break;
        }
    }

    pthread_mutex_unlock(&store->mutex);
    if (!found) {
        return status;
    }

    struct vantaq_evidence *clone = NULL;
    vantaq_evidence_err_t clone_err =
        vantaq_evidence_create(evidence_id, device_id, verifier_id_copy, challenge_id, nonce,
                               purpose, issued_at_unix, claims, signature_alg, signature, &clone);
    if (clone_err != VANTAQ_EVIDENCE_OK) {
        return (clone_err == VANTAQ_EVIDENCE_ERR_MALLOC_FAILED)
                   ? VANTAQ_LATEST_EVIDENCE_ERR_MALLOC_FAILED
                   : VANTAQ_LATEST_EVIDENCE_ERR_INTERNAL;
    }
    char *sig = strdup(signature_b64);
    if (!sig) {
        vantaq_evidence_destroy(clone);
        return VANTAQ_LATEST_EVIDENCE_ERR_MALLOC_FAILED;
    }
    *out_evidence      = clone;
    *out_signature_b64 = sig;
    status             = VANTAQ_LATEST_EVIDENCE_OK;
    return status;
}
