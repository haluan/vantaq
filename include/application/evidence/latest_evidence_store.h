// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_EVIDENCE_LATEST_EVIDENCE_STORE_H
#define VANTAQ_APPLICATION_EVIDENCE_LATEST_EVIDENCE_STORE_H

#include "domain/evidence/evidence.h"
#include <stddef.h>

/**
 * @brief Opaque structure for the latest evidence store.
 */
struct vantaq_latest_evidence_store;

typedef enum {
    VANTAQ_LATEST_EVIDENCE_OK = 0,
    VANTAQ_LATEST_EVIDENCE_ERR_INVALID_ARG = 1,
    VANTAQ_LATEST_EVIDENCE_ERR_MALLOC_FAILED = 2,
    VANTAQ_LATEST_EVIDENCE_ERR_NOT_FOUND = 3,
    VANTAQ_LATEST_EVIDENCE_ERR_FULL = 4,
    VANTAQ_LATEST_EVIDENCE_ERR_INTERNAL = 5,
    VANTAQ_LATEST_EVIDENCE_ERR_VERIFIER_ID_TOO_LONG = 6
} vantaq_latest_evidence_err_t;

/**
 * @brief Create a latest evidence store with bounded capacity.
 */
struct vantaq_latest_evidence_store *vantaq_latest_evidence_store_create(size_t max_verifiers);

/**
 * @brief Destroy the store and release all resources.
 */
void vantaq_latest_evidence_store_destroy(struct vantaq_latest_evidence_store *store);

/**
 * @brief Store the latest evidence and signature for a verifier.
 * clones the evidence and signature strings.
 */
vantaq_latest_evidence_err_t vantaq_latest_evidence_store_put(
    struct vantaq_latest_evidence_store *store,
    const char *verifier_id,
    const struct vantaq_evidence *evidence,
    const char *signature_b64
);

/**
 * @brief Retrieve the latest evidence and signature for a verifier.
 * Clones the objects, caller is responsible for freeing them.
 */
vantaq_latest_evidence_err_t vantaq_latest_evidence_store_get(
    struct vantaq_latest_evidence_store *store,
    const char *verifier_id,
    struct vantaq_evidence **out_evidence,
    char **out_signature_b64
);

#endif
