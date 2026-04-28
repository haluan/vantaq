// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/crypto/device_key_loader.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ER_ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))
#define VANTAQ_KEY_FILE_MAX_BYTES (64U * 1024U)

struct vantaq_device_key_t {
    char *private_pem;
    size_t private_pem_len;
    char *public_pem;
    size_t public_pem_len;
};

static void secure_zero_memory(void *ptr, size_t size) {
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
}

static bool has_pem_markers(const char *content, const char *label) {
    char begin_marker[64];
    char end_marker[64];
    snprintf(begin_marker, sizeof(begin_marker), "-----BEGIN %s-----", label);
    snprintf(end_marker, sizeof(end_marker), "-----END %s-----", label);
    return strstr(content, begin_marker) != NULL && strstr(content, end_marker) != NULL;
}

static bool has_any_pem_begin_marker(const char *content) {
    return strstr(content, "-----BEGIN ") != NULL;
}

static vantaq_key_err_t validate_pem_format(const char *private_pem, const char *public_pem) {
    bool private_has_valid = has_pem_markers(private_pem, "PRIVATE KEY") ||
                             has_pem_markers(private_pem, "EC PRIVATE KEY");
    bool public_has_valid =
        has_pem_markers(public_pem, "PUBLIC KEY") || has_pem_markers(public_pem, "CERTIFICATE");

    // Backward compatibility: if a file has no PEM envelope at all, keep accepting it.
    // But if it looks PEM-like and the envelope is malformed/incomplete, reject it.
    if (has_any_pem_begin_marker(private_pem) && !private_has_valid) {
        return VANTAQ_KEY_ERR_INVALID_FORMAT;
    }
    if (has_any_pem_begin_marker(public_pem) && !public_has_valid) {
        return VANTAQ_KEY_ERR_INVALID_FORMAT;
    }
    return VANTAQ_KEY_OK;
}

static vantaq_key_err_t read_file_to_string(const char *path, char **out_content, size_t *out_len) {
    if (!path || !out_content)
        return VANTAQ_KEY_ERR_INVALID_ARG;

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT) {
            return VANTAQ_KEY_ERR_MISSING_FILE;
        }
        if (errno == EACCES) {
            return VANTAQ_KEY_ERR_PERMISSION_DENIED;
        }
        return VANTAQ_KEY_ERR_READ_FAILED;
    }

    vantaq_key_err_t err = VANTAQ_KEY_OK;
    char *buffer         = NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        err = VANTAQ_KEY_ERR_READ_FAILED;
        goto cleanup;
    }

    long length = ftell(f);
    if (length < 0) {
        err = VANTAQ_KEY_ERR_READ_FAILED;
        goto cleanup;
    }
    if ((unsigned long)length > VANTAQ_KEY_FILE_MAX_BYTES) {
        err = VANTAQ_KEY_ERR_FILE_TOO_LARGE;
        goto cleanup;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        err = VANTAQ_KEY_ERR_READ_FAILED;
        goto cleanup;
    }

    buffer = malloc(length + 1);
    if (!buffer) {
        err = VANTAQ_KEY_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    size_t read_bytes = fread(buffer, 1, length, f);
    if (read_bytes != (size_t)length) {
        err = VANTAQ_KEY_ERR_READ_FAILED;
        goto cleanup;
    }

    buffer[length] = '\0';
    *out_content   = buffer;
    if (out_len) {
        *out_len = (size_t)length;
    }

cleanup:
    if (f)
        fclose(f);
    if (err != VANTAQ_KEY_OK && buffer) {
        free(buffer);
    }
    return err;
}

vantaq_key_err_t vantaq_device_key_load(const char *private_key_path, const char *public_key_path,
                                        vantaq_device_key_t **out_key) {
    if (!private_key_path || !public_key_path || !out_key) {
        return VANTAQ_KEY_ERR_INVALID_ARG;
    }

    vantaq_device_key_t *key = malloc(sizeof(vantaq_device_key_t));
    if (!key)
        return VANTAQ_KEY_ERR_MALLOC_FAILED;
    ER_ZERO_STRUCT(*key);

    vantaq_key_err_t err =
        read_file_to_string(private_key_path, &key->private_pem, &key->private_pem_len);
    if (err != VANTAQ_KEY_OK)
        goto error;

    err = read_file_to_string(public_key_path, &key->public_pem, &key->public_pem_len);
    if (err != VANTAQ_KEY_OK)
        goto error;

    err = validate_pem_format(key->private_pem, key->public_pem);
    if (err != VANTAQ_KEY_OK)
        goto error;

    *out_key = key;
    return VANTAQ_KEY_OK;

error:
    vantaq_device_key_destroy(key);
    return err;
}

void vantaq_device_key_destroy(vantaq_device_key_t *key) {
    if (key) {
        if (key->private_pem) {
            // Securely wipe the private key from memory before freeing.
            secure_zero_memory(key->private_pem, key->private_pem_len + 1);
            free(key->private_pem);
        }
        if (key->public_pem) {
            free(key->public_pem);
        }
        free(key);
    }
}

const char *vantaq_device_key_get_private_pem(const vantaq_device_key_t *key) {
    return key ? key->private_pem : NULL;
}

const char *vantaq_device_key_get_public_pem(const vantaq_device_key_t *key) {
    return key ? key->public_pem : NULL;
}
