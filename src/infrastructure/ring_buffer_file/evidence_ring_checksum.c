// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "evidence_ring_checksum.h"

#include "infrastructure/memory/zero_struct.h"

#include <ctype.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN 32U
#define VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN 64U
#define VANTAQ_EVIDENCE_RING_SHA256_PREFIX "sha256:"
#define VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN 7U

_Static_assert(VANTAQ_RING_BUFFER_CHECKSUM_MAX >= (VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN +
                                                   VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN + 1U),
               "VANTAQ_RING_BUFFER_CHECKSUM_MAX too small for checksum format");

static bool parse_evidence_json_len(const uint8_t *slot_buf, size_t max_record_bytes,
                                    uint32_t *out_evidence_json_len) {
    uint32_t evidence_json_len;

    if (slot_buf == NULL || out_evidence_json_len == NULL || max_record_bytes == 0U) {
        return false;
    }

    evidence_json_len = vantaq_evidence_ring_le32_decode(
        slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET);
    if (evidence_json_len == 0U || evidence_json_len > max_record_bytes) {
        return false;
    }

    *out_evidence_json_len = evidence_json_len;
    return true;
}

bool vantaq_evidence_ring_checksum_compute(const uint8_t *slot_buf, size_t max_record_bytes,
                                           char out_checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX]) {
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char digest[VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN];
    unsigned int digest_len = 0U;
    uint32_t evidence_json_len;
    bool ok = false;
    size_t i;

    if (slot_buf == NULL || out_checksum == NULL) {
        return false;
    }

    if (!parse_evidence_json_len(slot_buf, max_record_bytes, &evidence_json_len)) {
        return false;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        goto cleanup;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }

    if (EVP_DigestUpdate(md_ctx, slot_buf, VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET) != 1) {
        goto cleanup;
    }

    if (EVP_DigestUpdate(md_ctx, slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET,
                         evidence_json_len) != 1) {
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1 ||
        digest_len != VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN) {
        goto cleanup;
    }

    memcpy(out_checksum, VANTAQ_EVIDENCE_RING_SHA256_PREFIX,
           VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN);
    for (i = 0U; i < VANTAQ_EVIDENCE_RING_SHA256_BIN_LEN; i++) {
        (void)snprintf(out_checksum + VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + (i * 2U), 3, "%02x",
                       digest[i]);
    }
    out_checksum[VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN] =
        '\0';

    ok = true;

cleanup:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    vantaq_explicit_bzero(digest, sizeof(digest));
    return ok;
}

bool vantaq_evidence_ring_checksum_is_valid_format(const char *checksum) {
    size_t len;
    size_t i;

    if (checksum == NULL) {
        return false;
    }

    len = strnlen(checksum, VANTAQ_RING_BUFFER_CHECKSUM_MAX);
    if (len != (VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN + VANTAQ_EVIDENCE_RING_SHA256_HEX_LEN)) {
        return false;
    }

    if (memcmp(checksum, VANTAQ_EVIDENCE_RING_SHA256_PREFIX,
               VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN) != 0) {
        return false;
    }

    for (i = VANTAQ_EVIDENCE_RING_SHA256_PREFIX_LEN; i < len; i++) {
        if (!isxdigit((unsigned char)checksum[i])) {
            return false;
        }
    }

    return true;
}

bool vantaq_evidence_ring_checksum_verify(const uint8_t *slot_buf, size_t max_record_bytes) {
    char stored_checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
    char computed_checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
    size_t stored_len;

    if (slot_buf == NULL) {
        return false;
    }

    VANTAQ_ZERO_STRUCT(stored_checksum);
    VANTAQ_ZERO_STRUCT(computed_checksum);

    stored_len = strnlen((const char *)(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET),
                         VANTAQ_RING_BUFFER_CHECKSUM_MAX);
    if (stored_len == 0U || stored_len >= VANTAQ_RING_BUFFER_CHECKSUM_MAX) {
        return false;
    }

    memcpy(stored_checksum, slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET, stored_len);
    stored_checksum[stored_len] = '\0';

    if (!vantaq_evidence_ring_checksum_is_valid_format(stored_checksum)) {
        return false;
    }

    if (!vantaq_evidence_ring_checksum_compute(slot_buf, max_record_bytes, computed_checksum)) {
        return false;
    }

    return strcmp(stored_checksum, computed_checksum) == 0;
}
