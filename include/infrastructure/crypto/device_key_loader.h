// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CRYPTO_DEVICE_KEY_LOADER_H
#define VANTAQ_INFRASTRUCTURE_CRYPTO_DEVICE_KEY_LOADER_H

#include <stddef.h>

typedef enum {
    VANTAQ_KEY_OK = 0,
    VANTAQ_KEY_ERR_INVALID_ARG = 1,
    VANTAQ_KEY_ERR_MISSING_FILE = 2,
    VANTAQ_KEY_ERR_READ_FAILED = 3,
    VANTAQ_KEY_ERR_MALLOC_FAILED = 4,
    VANTAQ_KEY_ERR_INVALID_FORMAT = 5
} vantaq_key_err_t;

typedef struct vantaq_device_key_t vantaq_device_key_t;

/**
 * @brief Load device signing key from PEM files.
 * 
 * @param private_key_path Path to the private key PEM file.
 * @param public_key_path Path to the public key PEM file.
 * @param out_key Pointer to hold the created device key object.
 * @return vantaq_key_err_t Status code.
 */
vantaq_key_err_t vantaq_device_key_load(const char *private_key_path,
                                        const char *public_key_path,
                                        vantaq_device_key_t **out_key);

/**
 * @brief Destroy a device key object.
 */
void vantaq_device_key_destroy(vantaq_device_key_t *key);

/**
 * @brief Get the loaded private key PEM string.
 * @note Only use this internally for signing operations. Do not log.
 */
const char *vantaq_device_key_get_private_pem(const vantaq_device_key_t *key);

/**
 * @brief Get the loaded public key PEM string.
 */
const char *vantaq_device_key_get_public_pem(const vantaq_device_key_t *key);

#endif
