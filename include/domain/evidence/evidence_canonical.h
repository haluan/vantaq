// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_EVIDENCE_EVIDENCE_CANONICAL_H
#define VANTAQ_DOMAIN_EVIDENCE_EVIDENCE_CANONICAL_H

#include "domain/evidence/evidence.h"
#include <stddef.h>

/**
 * @brief Serialize evidence deterministically before signing.
 * 
 * NOTE: The canonical form includes the `evidence_id`. This ID must be assigned
 * and stable before calling this function to ensure the resulting signature
 * remains valid for the finalized evidence object.
 * 
 * The output uses a pipe '|' delimiter between fields. Field values are
 * escaped ('|' -> '\|', '\' -> '\\') to prevent format injection and ensure
 * unambiguous parsing if required.
 * 
 * @param evidence The evidence object to serialize.
 * @param out_buffer Pointer to hold the allocated serialized buffer.
 * @param out_len Pointer to hold the length of the serialized buffer.
 * @return vantaq_evidence_err_t Status code.
 */
vantaq_evidence_err_t vantaq_evidence_serialize_canonical(const struct vantaq_evidence *evidence,
                                                          char **out_buffer, size_t *out_len);

/**
 * @brief Destroy the buffer allocated by vantaq_evidence_serialize_canonical.
 * 
 * Securely zeros the buffer before releasing memory.
 */
void vantaq_evidence_canonical_destroy(char *buffer);

#endif
