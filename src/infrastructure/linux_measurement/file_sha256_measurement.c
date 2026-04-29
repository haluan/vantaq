// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "file_sha256_measurement.h"

#include "infrastructure/config_loader.h"
#include "infrastructure/memory/zero_struct.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define VANTAQ_SHA256_BIN_LEN 32
#define VANTAQ_SHA256_HEX_LEN 64
#define VANTAQ_SHA256_PREFIX "sha256:"
#define VANTAQ_SHA256_PREFIX_LEN 7
#define VANTAQ_FILE_HASH_CHUNK_SIZE 4096

_Static_assert(VANTAQ_MEASUREMENT_VALUE_MAX >=
                   (VANTAQ_SHA256_PREFIX_LEN + VANTAQ_SHA256_HEX_LEN + 1),
               "VANTAQ_MEASUREMENT_VALUE_MAX too small for sha256 value");

static vantaq_measurement_error_code_t
map_status_to_measurement_error(enum vantaq_file_sha256_measure_status status) {
    switch (status) {
    case VANTAQ_FILE_SHA256_MEASURE_ERR_SOURCE_NOT_FOUND:
        return MEASUREMENT_SOURCE_NOT_FOUND;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED:
        return MEASUREMENT_HASH_FAILED;
    default:
        return MEASUREMENT_READ_FAILED;
    }
}

enum vantaq_file_sha256_measure_status
vantaq_measure_sha256_file_to_result(const char *source_path, size_t max_file_bytes,
                                     const char *claim_name,
                                     struct vantaq_measurement_result **out_result) {
    enum vantaq_file_sha256_measure_status status = VANTAQ_FILE_SHA256_MEASURE_OK;
    FILE *fp                                      = NULL;
    EVP_MD_CTX *md_ctx                            = NULL;
    unsigned char chunk[VANTAQ_FILE_HASH_CHUNK_SIZE];
    unsigned char digest[VANTAQ_SHA256_BIN_LEN];
    unsigned int digest_len                           = 0;
    char value[VANTAQ_MEASUREMENT_VALUE_MAX]          = {0};
    size_t total_read                                 = 0U;
    size_t read_len                                   = 0U;
    vantaq_measurement_error_code_t measurement_error = MEASUREMENT_READ_FAILED;
    vantaq_measurement_model_err_t model_err          = VANTAQ_MEASUREMENT_MODEL_OK;

    if (out_result == NULL || source_path == NULL || source_path[0] == '\0' || claim_name == NULL ||
        claim_name[0] == '\0' || max_file_bytes == 0U ||
        max_file_bytes > VANTAQ_MEASUREMENT_DEFAULT_MAX_FILE_BYTES) {
        return VANTAQ_FILE_SHA256_MEASURE_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    errno = 0;
    fp    = fopen(source_path, "rb");
    if (fp == NULL) {
        int fopen_errno = errno;

        /* Prefer fopen errno; fall back to stat so missing paths are detected even if errno was not
         * set reliably by fopen on non-standard implementations. */
        if (fopen_errno == ENOENT) {
            status = VANTAQ_FILE_SHA256_MEASURE_ERR_SOURCE_NOT_FOUND;
            goto cleanup;
        }
        struct stat path_st;
        if (stat(source_path, &path_st) != 0) {
            int stat_errno = errno;

            if (stat_errno == ENOENT) {
                status = VANTAQ_FILE_SHA256_MEASURE_ERR_SOURCE_NOT_FOUND;
                goto cleanup;
            }
        }
        status = VANTAQ_FILE_SHA256_MEASURE_ERR_READ_FAILED;
        goto cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        status = VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED;
        goto cleanup;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        status = VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED;
        goto cleanup;
    }

    do {
        read_len = fread(chunk, 1, sizeof(chunk), fp);
        if (read_len > 0U) {
            total_read += read_len;
            if (total_read > max_file_bytes) {
                status = VANTAQ_FILE_SHA256_MEASURE_ERR_FILE_TOO_LARGE;
                goto cleanup;
            }
            if (EVP_DigestUpdate(md_ctx, chunk, read_len) != 1) {
                status = VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED;
                goto cleanup;
            }
        }

        if (read_len < sizeof(chunk) && ferror(fp) != 0) {
            status = VANTAQ_FILE_SHA256_MEASURE_ERR_READ_FAILED;
            goto cleanup;
        }
    } while (read_len == sizeof(chunk));

    if (total_read == 0U) {
        status = VANTAQ_FILE_SHA256_MEASURE_ERR_READ_FAILED;
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1 ||
        digest_len != VANTAQ_SHA256_BIN_LEN) {
        status = VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED;
        goto cleanup;
    }

    memcpy(value, VANTAQ_SHA256_PREFIX, VANTAQ_SHA256_PREFIX_LEN);
    for (size_t i = 0; i < VANTAQ_SHA256_BIN_LEN; i++) {
        (void)snprintf(value + VANTAQ_SHA256_PREFIX_LEN + (i * 2), 3, "%02x", digest[i]);
    }
    value[VANTAQ_SHA256_PREFIX_LEN + VANTAQ_SHA256_HEX_LEN] = '\0';

    model_err =
        vantaq_measurement_result_create_success(claim_name, value, source_path, out_result);
    if (model_err != VANTAQ_MEASUREMENT_MODEL_OK) {
        status = VANTAQ_FILE_SHA256_MEASURE_ERR_MODEL_FAILED;
        goto cleanup;
    }

    status = VANTAQ_FILE_SHA256_MEASURE_OK;

cleanup:
    /* Attach an error-domain result whenever we failed before producing *out_result. Treat
     * ERR_MODEL_FAILED from create_success as recoverable via
     * create_error(MEASUREMENT_READ_FAILED).
     */
    if (status != VANTAQ_FILE_SHA256_MEASURE_OK &&
        status != VANTAQ_FILE_SHA256_MEASURE_ERR_INVALID_ARG && *out_result == NULL) {
        measurement_error = (status == VANTAQ_FILE_SHA256_MEASURE_ERR_MODEL_FAILED)
                                ? MEASUREMENT_READ_FAILED
                                : map_status_to_measurement_error(status);
        model_err         = vantaq_measurement_result_create_error(claim_name, source_path,
                                                                   measurement_error, out_result);
        if (model_err != VANTAQ_MEASUREMENT_MODEL_OK) {
            status      = VANTAQ_FILE_SHA256_MEASURE_ERR_MODEL_FAILED;
            *out_result = NULL;
        }
    }

    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (fp != NULL) {
        fclose(fp);
    }
    vantaq_explicit_bzero(chunk, sizeof(chunk));
    vantaq_explicit_bzero(digest, sizeof(digest));
    vantaq_explicit_bzero(value, sizeof(value));
    return status;
}
