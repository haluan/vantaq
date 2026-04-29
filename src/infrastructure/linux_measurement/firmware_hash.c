// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/linux_measurement/firmware_hash.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VANTAQ_SHA256_BIN_LEN 32
#define VANTAQ_SHA256_HEX_LEN 64
#define VANTAQ_SHA256_PREFIX "sha256:"
#define VANTAQ_SHA256_PREFIX_LEN 7

static enum vantaq_firmware_hash_status
build_measurement_error_result(const char *path, vantaq_measurement_error_code_t error_code,
                               struct vantaq_measurement_result **out_result) {
    vantaq_measurement_model_err_t model_err =
        vantaq_measurement_result_create_error("firmware_hash", path, error_code, out_result);
    if (model_err != VANTAQ_MEASUREMENT_MODEL_OK) {
        return VANTAQ_FIRMWARE_HASH_ERR_MODEL_FAILED;
    }
    return VANTAQ_FIRMWARE_HASH_OK;
}

enum vantaq_firmware_hash_status
vantaq_firmware_hash_measure(const struct vantaq_runtime_config *config,
                             struct vantaq_measurement_result **out_result) {
    enum vantaq_firmware_hash_status status = VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED;
    FILE *fp                                = NULL;
    long file_len                           = -1;
    unsigned char *buffer                   = NULL;
    size_t read_len                         = 0;
    EVP_MD_CTX *md_ctx                      = NULL;
    unsigned char digest[VANTAQ_SHA256_BIN_LEN];
    unsigned int digest_len = 0;
    char value[VANTAQ_MEASUREMENT_VALUE_MAX];
    const char *firmware_path;
    size_t max_file_bytes;

    if (out_result == NULL || config == NULL) {
        return VANTAQ_FIRMWARE_HASH_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    firmware_path  = vantaq_runtime_measurement_firmware_path(config);
    max_file_bytes = vantaq_runtime_measurement_max_file_bytes(config);
    if (firmware_path == NULL || firmware_path[0] == '\0' || max_file_bytes == 0) {
        return VANTAQ_FIRMWARE_HASH_ERR_INVALID_ARG;
    }

    fp = fopen(firmware_path, "rb");
    if (fp == NULL) {
        if (errno == ENOENT) {
            status = VANTAQ_FIRMWARE_HASH_ERR_SOURCE_NOT_FOUND;
            goto map_error;
        }
        status = VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED;
        goto map_error;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        status = VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED;
        goto map_error;
    }

    file_len = ftell(fp);
    if (file_len < 0) {
        status = VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED;
        goto map_error;
    }
    if ((size_t)file_len > max_file_bytes) {
        status = VANTAQ_FIRMWARE_HASH_ERR_FILE_TOO_LARGE;
        goto map_error;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        status = VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED;
        goto map_error;
    }

    buffer = malloc((size_t)file_len);
    if (buffer == NULL && file_len > 0) {
        status = VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED;
        goto map_error;
    }

    read_len = fread(buffer, 1, (size_t)file_len, fp);
    if (read_len != (size_t)file_len) {
        status = VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED;
        goto map_error;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        status = VANTAQ_FIRMWARE_HASH_ERR_HASH_FAILED;
        goto map_error;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        status = VANTAQ_FIRMWARE_HASH_ERR_HASH_FAILED;
        goto map_error;
    }

    if (file_len > 0 && EVP_DigestUpdate(md_ctx, buffer, (size_t)file_len) != 1) {
        status = VANTAQ_FIRMWARE_HASH_ERR_HASH_FAILED;
        goto map_error;
    }

    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1 ||
        digest_len != VANTAQ_SHA256_BIN_LEN) {
        status = VANTAQ_FIRMWARE_HASH_ERR_HASH_FAILED;
        goto map_error;
    }

    memcpy(value, VANTAQ_SHA256_PREFIX, VANTAQ_SHA256_PREFIX_LEN);
    for (size_t i = 0; i < VANTAQ_SHA256_BIN_LEN; i++) {
        (void)snprintf(value + VANTAQ_SHA256_PREFIX_LEN + (i * 2), 3, "%02x", digest[i]);
    }
    value[VANTAQ_SHA256_PREFIX_LEN + VANTAQ_SHA256_HEX_LEN] = '\0';

    if (vantaq_measurement_result_create_success("firmware_hash", value, firmware_path,
                                                 out_result) != VANTAQ_MEASUREMENT_MODEL_OK) {
        status = VANTAQ_FIRMWARE_HASH_ERR_MODEL_FAILED;
        goto cleanup;
    }

    status = VANTAQ_FIRMWARE_HASH_OK;
    goto cleanup;

map_error:
    if (status == VANTAQ_FIRMWARE_HASH_ERR_SOURCE_NOT_FOUND) {
        enum vantaq_firmware_hash_status map_status =
            build_measurement_error_result(firmware_path, MEASUREMENT_SOURCE_NOT_FOUND, out_result);
        if (map_status != VANTAQ_FIRMWARE_HASH_OK) {
            status = map_status;
        }
    } else if (status == VANTAQ_FIRMWARE_HASH_ERR_HASH_FAILED) {
        enum vantaq_firmware_hash_status map_status =
            build_measurement_error_result(firmware_path, MEASUREMENT_HASH_FAILED, out_result);
        if (map_status != VANTAQ_FIRMWARE_HASH_OK) {
            status = map_status;
        }
    } else {
        enum vantaq_firmware_hash_status map_status =
            build_measurement_error_result(firmware_path, MEASUREMENT_READ_FAILED, out_result);
        if (map_status != VANTAQ_FIRMWARE_HASH_OK) {
            status = map_status;
        }
    }

cleanup:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (fp != NULL) {
        fclose(fp);
    }
    if (buffer != NULL) {
        free(buffer);
    }
    return status;
}
