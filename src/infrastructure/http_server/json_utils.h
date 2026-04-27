// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_HTTP_SERVER_JSON_UTILS_H
#define VANTAQ_INFRASTRUCTURE_HTTP_SERVER_JSON_UTILS_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Simple JSON string extractor.
 *
 * Searches for a key in the JSON body and extracts its string value.
 * This is a minimal, robust implementation that handles basic JSON structures.
 *
 * @param json The JSON string to search.
 * @param key The key to look for (e.g., "purpose").
 * @param out_buf Buffer to store the extracted value.
 * @param out_size Size of the output buffer.
 * @return true if found and extracted successfully, false otherwise.
 */
bool vantaq_json_extract_str(const char *json, const char *key, char *out_buf, size_t out_size);

/**
 * @brief Simple JSON integer extractor.
 *
 * Searches for a key in the JSON body and extracts its integer value.
 *
 * @param json The JSON string to search.
 * @param key The key to look for (e.g., "requested_ttl_seconds").
 * @param out_val Pointer to store the extracted integer.
 * @return true if found and extracted successfully, false otherwise.
 */
bool vantaq_json_extract_long(const char *json, const char *key, long *out_val);

/**
 * @brief Escapes a string for inclusion in a JSON value.
 *
 * @param src The source string to escape.
 * @param dst The destination buffer.
 * @param dst_size Size of the destination buffer.
 * @return size_t Number of bytes written (excluding null terminator), or 0 on error/truncation.
 */
size_t vantaq_json_escape_str(const char *src, char *dst, size_t dst_size);

#endif
