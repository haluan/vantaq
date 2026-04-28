// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/crypto/device_key_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ER_ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))

struct vantaq_device_key_t {
    char *private_pem;
    char *public_pem;
};

static vantaq_key_err_t read_file_to_string(const char *path, char **out_content) {
    if (!path || !out_content)
        return VANTAQ_KEY_ERR_INVALID_ARG;

    FILE *f = fopen(path, "rb");
    if (!f)
        return VANTAQ_KEY_ERR_MISSING_FILE;

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

    vantaq_key_err_t err = read_file_to_string(private_key_path, &key->private_pem);
    if (err != VANTAQ_KEY_OK)
        goto error;

    err = read_file_to_string(public_key_path, &key->public_pem);
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
            // Securely wipe the private key from memory before freeing
            memset(key->private_pem, 0, strlen(key->private_pem));
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
