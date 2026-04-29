// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "json_utils.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const char *skip_whitespace(const char *p) {
    if (!p)
        return NULL;
    while (*p && isspace((unsigned char)*p))
        p++;
    return p;
}

static const char *find_key(const char *json, const char *key) {
    if (!json || !key)
        return NULL;
    size_t key_len = strlen(key);
    const char *p  = json;
    bool in_string = false;
    bool escaped   = false;

    while (*p) {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (*p == '\\') {
                escaped = true;
            } else if (*p == '"') {
                in_string = false;
            }
            p++;
            continue;
        }

        if (*p == '"') {
            const char *start = p + 1;
            const char *end   = start;
            while (*end && *end != '"') {
                end++;
            }
            if (!*end) {
                return NULL;
            }
            if ((size_t)(end - start) == key_len && strncmp(start, key, key_len) == 0) {
                const char *colon = skip_whitespace(end + 1);
                if (colon && *colon == ':') {
                    return colon + 1;
                }
            }
            p = end + 1;
            continue;
        }
        p++;
    }
    return NULL;
}

bool vantaq_json_extract_str(const char *json, const char *key, char *out_buf, size_t out_size) {
    if (!out_buf || out_size == 0)
        return false;
    const char *val_ptr = find_key(json, key);
    if (!val_ptr)
        return false;

    val_ptr = skip_whitespace(val_ptr);
    if (!val_ptr || *val_ptr != '\"')
        return false;
    val_ptr++; /* Skip leading quote */

    const char *end = val_ptr;
    bool escaped    = false;
    while (*end) {
        if (escaped) {
            escaped = false;
        } else if (*end == '\\') {
            escaped = true;
        } else if (*end == '\"') {
            break;
        }
        end++;
    }
    if (!*end)
        return false;

    size_t len = (size_t)(end - val_ptr);
    if (len >= out_size)
        return false; /* Truncation not allowed in security context */

    memcpy(out_buf, val_ptr, len);
    out_buf[len] = '\0';
    return true;
}

bool vantaq_json_extract_long(const char *json, const char *key, long *out_val) {
    if (!out_val)
        return false;
    const char *val_ptr = find_key(json, key);
    if (!val_ptr)
        return false;

    val_ptr = skip_whitespace(val_ptr);
    if (!val_ptr || (!isdigit((unsigned char)*val_ptr) && *val_ptr != '-'))
        return false;

    char *endptr;
    errno    = 0;
    long val = strtol(val_ptr, &endptr, 10);
    if (errno == ERANGE || endptr == val_ptr)
        return false;

    *out_val = val;
    return true;
}

size_t vantaq_json_escape_str(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst || dst_size == 0)
        return 0;

    size_t written = 0;
    const char *p  = src;

    while (*p && written < dst_size - 1) {
        char esc = 0;
        switch (*p) {
        case '\"':
            esc = '\"';
            break;
        case '\\':
            esc = '\\';
            break;
        case '\b':
            esc = 'b';
            break;
        case '\f':
            esc = 'f';
            break;
        case '\n':
            esc = 'n';
            break;
        case '\r':
            esc = 'r';
            break;
        case '\t':
            esc = 't';
            break;
        default:
            if ((unsigned char)*p < 0x20) {
                /* Control character, needs \uXXXX, but simplified for MVP to underscore */
                esc = '?';
            }
            break;
        }

        if (esc) {
            if (written + 2 >= dst_size)
                return 0;
            dst[written++] = '\\';
            dst[written++] = esc;
        } else {
            dst[written++] = *p;
        }
        p++;
    }

    if (*p != '\0')
        return 0; /* Buffer too small */
    dst[written] = '\0';
    return written;
}

bool vantaq_json_extract_str_array(const char *json, const char *key, char *out_items,
                                   size_t item_size, size_t max_items, size_t *out_count,
                                   bool *out_present) {
    const char *val_ptr;
    size_t count = 0;

    if (out_count == NULL || out_present == NULL || out_items == NULL || item_size == 0 ||
        max_items == 0) {
        return false;
    }

    *out_count   = 0;
    *out_present = false;
    val_ptr      = find_key(json, key);
    if (val_ptr == NULL) {
        return true;
    }

    *out_present = true;
    val_ptr      = skip_whitespace(val_ptr);
    if (val_ptr == NULL || *val_ptr != '[') {
        return false;
    }
    val_ptr++;

    while (true) {
        char *dst;
        size_t written = 0;
        bool escaped   = false;

        val_ptr = skip_whitespace(val_ptr);
        if (val_ptr == NULL) {
            return false;
        }

        if (*val_ptr == ']') {
            *out_count = count;
            return true;
        }

        if (*val_ptr != '"') {
            return false;
        }
        if (count >= max_items) {
            return false;
        }

        dst = out_items + (count * item_size);
        val_ptr++;
        while (*val_ptr != '\0') {
            if (!escaped && *val_ptr == '"') {
                break;
            }
            if (!escaped && *val_ptr == '\\') {
                escaped = true;
                val_ptr++;
                continue;
            }

            if (written + 1 >= item_size) {
                return false;
            }
            dst[written++] = *val_ptr;
            escaped        = false;
            val_ptr++;
        }

        if (*val_ptr != '"') {
            return false;
        }
        if (written == 0) {
            return false;
        }
        dst[written] = '\0';
        count++;
        val_ptr++;

        val_ptr = skip_whitespace(val_ptr);
        if (val_ptr == NULL) {
            return false;
        }
        if (*val_ptr == ',') {
            val_ptr++;
            continue;
        }
        if (*val_ptr == ']') {
            *out_count = count;
            return true;
        }
        return false;
    }
}
