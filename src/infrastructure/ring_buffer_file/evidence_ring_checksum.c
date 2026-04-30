// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "evidence_ring_checksum.h"

#include "infrastructure/memory/zero_struct.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN 32U
#define VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN 64U
#define VANTAQ_EVIDENCE_RING_SHA256_PREFIX "sha256:"
#define VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN (sizeof(VANTAQ_EVIDENCE_RING_SHA256_PREFIX) - 1U)

_Static_assert(VANTAQ_RING_BUFFER_CHECKSUM_MAX >= (VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN +
                                                   VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN + 1U),
               "VANTAQ_RING_BUFFER_CHECKSUM_MAX too small for checksum format");

static bool is_ascii_hex(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static vantaq_evidence_ring_checksum_status_t
parse_evidence_json_len(const uint8_t *slot_buf, size_t slot_buf_len, size_t max_record_bytes,
                        uint32_t *out_evidence_json_len) {
    uint32_t evidence_json_len;
    size_t min_slot_len;

    if (slot_buf == NULL || out_evidence_json_len == NULL || slot_buf_len == 0U ||
        max_record_bytes == 0U) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    min_slot_len = VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET + max_record_bytes;
    if (slot_buf_len < min_slot_len) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    if (!vantaq_evidence_ring_le32_decode(
            slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET, &evidence_json_len)) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    if (evidence_json_len == 0U || evidence_json_len > max_record_bytes) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    *out_evidence_json_len = evidence_json_len;
    return VANTAQ_EVIDENCE_RING_CHECKSUM_OK;
}

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_compute(const uint8_t *slot_buf, size_t slot_buf_len,
                                      size_t max_record_bytes,
                                      char out_checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX]) {
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char digest[VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN];
    unsigned int digest_len = 0U;
    uint32_t evidence_json_len;
    vantaq_evidence_ring_checksum_status_t status = VANTAQ_EVIDENCE_RING_CHECKSUM_ENGINE_FAILURE;
    size_t i;
    static const char hex_chars[] = "0123456789abcdef";

    if (slot_buf == NULL || out_checksum == NULL) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    status = parse_evidence_json_len(slot_buf, slot_buf_len, max_record_bytes, &evidence_json_len);
    if (status != VANTAQ_EVIDENCE_RING_CHECKSUM_OK) {
        return status;
    }

    /*
     * E-1 Contract: the state byte (at offset 0) is part of the checksum input.
     * Any mutation to the state byte before verification will cause a mismatch.
     * The checksum field itself MUST be all zeros if called before the first write.
     */

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_ENGINE_FAILURE;
        goto cleanup;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_ENGINE_FAILURE;
        goto cleanup;
    }

    if (EVP_DigestUpdate(md_ctx, slot_buf, VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET) != 1) {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_ENGINE_FAILURE;
        goto cleanup;
    }

    if (EVP_DigestUpdate(md_ctx, slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET,
                         evidence_json_len) != 1) {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_ENGINE_FAILURE;
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1 ||
        digest_len != VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN) {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_ENGINE_FAILURE;
        goto cleanup;
    }

    memcpy(out_checksum, VANTAQ_EVIDENCE_RING_SHA256_PREFIX,
           VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN);
    for (i = 0U; i < VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN; i++) {
        out_checksum[VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + (i * 2U)] =
            hex_chars[(digest[i] >> 4U) & 0x0FU];
        out_checksum[VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + (i * 2U) + 1U] =
            hex_chars[digest[i] & 0x0FU];
    }
    out_checksum[VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN] =
        '\0';

    status = VANTAQ_EVIDENCE_RING_CHECKSUM_OK;

cleanup:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    vantaq_explicit_bzero(digest, sizeof(digest));
    return status;
}

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_is_valid_format(const char *checksum) {
    size_t len;
    size_t i;

    if (checksum == NULL) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    len = strnlen(checksum, VANTAQ_RING_BUFFER_CHECKSUM_MAX);
    if (len != (VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN)) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_FORMAT;
    }

    if (memcmp(checksum, VANTAQ_EVIDENCE_RING_SHA256_PREFIX,
               VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN) != 0) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_FORMAT;
    }

    for (i = VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN; i < len; i++) {
        if (!is_ascii_hex((unsigned char)checksum[i])) {
            return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_FORMAT;
        }
    }

    return VANTAQ_EVIDENCE_RING_CHECKSUM_OK;
}

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_verify(const uint8_t *slot_buf, size_t slot_buf_len,
                                     size_t max_record_bytes) {
    char stored_checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
    char computed_checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
    size_t stored_len;
    vantaq_evidence_ring_checksum_status_t status = VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    const size_t checksum_len =
        VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN;

    if (slot_buf == NULL || slot_buf_len == 0U) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    VANTAQ_ZERO_STRUCT(stored_checksum);
    VANTAQ_ZERO_STRUCT(computed_checksum);

    stored_len = strnlen((const char *)(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET),
                         VANTAQ_RING_BUFFER_CHECKSUM_MAX);
    if (stored_len == 0U || stored_len >= VANTAQ_RING_BUFFER_CHECKSUM_MAX) {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_FORMAT;
        goto cleanup;
    }

    memcpy(stored_checksum, slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET, stored_len);
    stored_checksum[stored_len] = '\0';

    status = vantaq_evidence_ring_checksum_is_valid_format(stored_checksum);
    if (status != VANTAQ_EVIDENCE_RING_CHECKSUM_OK) {
        goto cleanup;
    }

    status = vantaq_evidence_ring_checksum_compute(slot_buf, slot_buf_len, max_record_bytes,
                                                   computed_checksum);
    if (status != VANTAQ_EVIDENCE_RING_CHECKSUM_OK) {
        goto cleanup;
    }

    if (CRYPTO_memcmp(stored_checksum, computed_checksum, checksum_len) == 0) {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_OK;
    } else {
        status = VANTAQ_EVIDENCE_RING_CHECKSUM_MISMATCH;
    }

cleanup:
    vantaq_explicit_bzero(stored_checksum, sizeof(stored_checksum));
    vantaq_explicit_bzero(computed_checksum, sizeof(computed_checksum));
    return status;
}

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_compute_into_slot(uint8_t *slot_buf, size_t slot_buf_len,
                                                size_t max_record_bytes) {
    char checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
    vantaq_evidence_ring_checksum_status_t status;

    if (slot_buf == NULL || slot_buf_len == 0U) {
        return VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT;
    }

    /*
     * D-2 implementation: The checksum field MUST be all zeros for the computation
     * to reflect a clean slot. We own the clearing and the write-back here.
     */
    vantaq_explicit_bzero(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET,
                          VANTAQ_RING_BUFFER_CHECKSUM_MAX);

    status =
        vantaq_evidence_ring_checksum_compute(slot_buf, slot_buf_len, max_record_bytes, checksum);
    if (status != VANTAQ_EVIDENCE_RING_CHECKSUM_OK) {
        return status;
    }

    memcpy(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET, checksum,
           VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN);

    vantaq_explicit_bzero(checksum, sizeof(checksum));
    return VANTAQ_EVIDENCE_RING_CHECKSUM_OK;
}
