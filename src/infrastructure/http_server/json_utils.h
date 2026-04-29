// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_HTTP_SERVER_JSON_UTILS_H
#define VANTAQ_INFRASTRUCTURE_HTTP_SERVER_JSON_UTILS_H

#include <stdbool.h>
#include <stddef.h>

/** Detailed status for JSON extraction helpers (`*_status` APIs). */
typedef enum {
    VANTAQ_JSON_EXTRACT_OK = 0,
    /** Key absent from JSON (only `*_status` APIs distinguish this from malformed input). */
    VANTAQ_JSON_EXTRACT_NOT_FOUND,
    /** Value missing, wrong type, illegal escapes, or truncated JSON string. */
    VANTAQ_JSON_EXTRACT_MALFORMED,
    /** Output buffer too small for decoded string content (including NUL). */
    VANTAQ_JSON_EXTRACT_BUFFER_TOO_SMALL,
    VANTAQ_JSON_EXTRACT_INVALID_ARGUMENT,
} vantaq_json_extract_status_t;

/** Detailed status for `vantaq_json_escape_str_status`. */
typedef enum {
    VANTAQ_JSON_ESCAPE_OK = 0,
    VANTAQ_JSON_ESCAPE_TRUNCATED,
    VANTAQ_JSON_ESCAPE_INVALID_ARGUMENT,
} vantaq_json_escape_status_t;

/**
 * @brief Extract and decode a JSON string field (RFC-style escapes including \\u00XX).
 *
 * Returns false unless decoding succeeds (`NOT_FOUND`, malformed input, and buffer too small all
 * yield false). Use `vantaq_json_extract_str_status` to distinguish outcomes.
 */
bool vantaq_json_extract_str(const char *json, const char *key, char *out_buf, size_t out_size);

vantaq_json_extract_status_t vantaq_json_extract_str_status(const char *json, const char *key,
                                                            char *out_buf, size_t out_size);

/**
 * @brief Extract a JSON integer field (decimal).
 *
 * Collapses failures into false; use `vantaq_json_extract_long_status` for `NOT_FOUND` vs
 * malformed.
 */
bool vantaq_json_extract_long(const char *json, const char *key, long *out_val);

vantaq_json_extract_status_t vantaq_json_extract_long_status(const char *json, const char *key,
                                                             long *out_val);

/**
 * @brief Escape a string for inclusion in a JSON string value (`\\u00XX` for other controls).
 *
 * Returns bytes written excluding the terminating NUL, or `0` if the buffer is unusable or too
 * small. Use `vantaq_json_escape_str_status` to distinguish truncation from invalid arguments.
 */
size_t vantaq_json_escape_str(const char *src, char *dst, size_t dst_size);

vantaq_json_escape_status_t vantaq_json_escape_str_status(const char *src, char *dst,
                                                          size_t dst_size, size_t *out_written);

/**
 * @brief Extract an optional JSON array of strings (decoded per RFC escapes).
 *
 * If the key is absent: returns true and sets `*out_present = false`.
 * If present: returns true only when the value is a well-formed array of strings (empty string
 * elements are allowed).
 *
 * Success (`true`) does **not** imply the key existed — consult `*out_present`.
 */
bool vantaq_json_extract_str_array(const char *json, const char *key, char *out_items,
                                   size_t item_size, size_t max_items, size_t *out_count,
                                   bool *out_present);

#endif
