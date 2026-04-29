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

static bool hex_value(char c, unsigned int *out) {
    if (out == NULL) {
        return false;
    }
    if (c >= '0' && c <= '9') {
        *out = (unsigned int)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *out = (unsigned int)(10 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *out = (unsigned int)(10 + (c - 'A'));
        return true;
    }
    return false;
}

typedef enum {
    JSON_UNESCAPE_OK = 0,
    JSON_UNESCAPE_INVALID_ARGUMENT,
    JSON_UNESCAPE_MALFORMED,
    JSON_UNESCAPE_TRUNCATED,
} json_unescape_result_t;

static json_unescape_result_t json_unescape_to_buf(const char *src, size_t src_len, char *dst,
                                                   size_t dst_size, size_t *out_written) {
    size_t i = 0;
    size_t w = 0;

    if (src == NULL || dst == NULL || dst_size == 0 || out_written == NULL) {
        return JSON_UNESCAPE_INVALID_ARGUMENT;
    }

    while (i < src_len) {
        char out_ch = '\0';

        if (src[i] != '\\') {
            out_ch = src[i];
            i++;
        } else {
            if (i + 1 >= src_len) {
                return JSON_UNESCAPE_MALFORMED;
            }
            i++;
            switch (src[i]) {
            case '"':
            case '\\':
            case '/':
                out_ch = src[i];
                i++;
                break;
            case 'b':
                out_ch = '\b';
                i++;
                break;
            case 'f':
                out_ch = '\f';
                i++;
                break;
            case 'n':
                out_ch = '\n';
                i++;
                break;
            case 'r':
                out_ch = '\r';
                i++;
                break;
            case 't':
                out_ch = '\t';
                i++;
                break;
            case 'u': {
                unsigned int v0, v1, v2, v3;
                unsigned int codepoint;
                if (i + 4 >= src_len) {
                    return JSON_UNESCAPE_MALFORMED;
                }
                if (!hex_value(src[i + 1], &v0) || !hex_value(src[i + 2], &v1) ||
                    !hex_value(src[i + 3], &v2) || !hex_value(src[i + 4], &v3)) {
                    return JSON_UNESCAPE_MALFORMED;
                }
                codepoint = (v0 << 12) | (v1 << 8) | (v2 << 4) | v3;
                if (codepoint > 0xFF) {
                    return JSON_UNESCAPE_MALFORMED;
                }
                out_ch = (char)codepoint;
                i += 5;
                break;
            }
            default:
                return JSON_UNESCAPE_MALFORMED;
            }
        }

        if (w + 1 >= dst_size) {
            return JSON_UNESCAPE_TRUNCATED;
        }
        dst[w++] = out_ch;
    }

    dst[w]       = '\0';
    *out_written = w;
    return JSON_UNESCAPE_OK;
}

/**
 * Finds "key" only at depth of the root JSON object's immediate properties (brace depth 1,
 * outside arrays). Nested objects and arrays are skipped so `"id"` inside `{"meta":{"id":"x"}}`
 * does not shadow `"id"` at the top level.
 */
static const char *find_key(const char *json, const char *key) {
    size_t key_len;
    size_t brace_depth   = 0;
    size_t bracket_depth = 0;
    const char *p        = json;

    if (!json || !key)
        return NULL;

    key_len = strlen(key);

    while (*p) {
        switch (*p) {
        case '{':
            brace_depth++;
            p++;
            continue;
        case '}':
            if (brace_depth > 0)
                brace_depth--;
            p++;
            continue;
        case '[':
            bracket_depth++;
            p++;
            continue;
        case ']':
            if (bracket_depth > 0)
                bracket_depth--;
            p++;
            continue;
        case '"': {
            const char *start = p + 1;
            const char *end   = start;
            bool escaped      = false;

            while (*end) {
                if (escaped) {
                    escaped = false;
                    end++;
                    continue;
                }
                if (*end == '\\') {
                    escaped = true;
                    end++;
                    continue;
                }
                if (*end == '"')
                    break;
                end++;
            }
            if (!*end)
                return NULL;

            if (brace_depth == 1 && bracket_depth == 0 && (size_t)(end - start) == key_len &&
                strncmp(start, key, key_len) == 0) {
                const char *colon = skip_whitespace(end + 1);

                if (colon != NULL && *colon == ':')
                    return colon + 1;
            }

            p = end + 1;
            continue;
        }
        default:
            p++;
            continue;
        }
    }
    return NULL;
}

vantaq_json_extract_status_t vantaq_json_extract_str_status(const char *json, const char *key,
                                                            char *out_buf, size_t out_size) {
    size_t decoded_written = 0;
    const char *val_ptr;
    const char *end;
    bool escaped = false;

    if (!out_buf || out_size == 0)
        return VANTAQ_JSON_EXTRACT_INVALID_ARGUMENT;

    val_ptr = find_key(json, key);
    if (!val_ptr)
        return VANTAQ_JSON_EXTRACT_NOT_FOUND;

    val_ptr = skip_whitespace(val_ptr);
    if (!val_ptr || *val_ptr != '\"')
        return VANTAQ_JSON_EXTRACT_MALFORMED;

    val_ptr++; /* Skip leading quote */

    end     = val_ptr;
    escaped = false;
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
        return VANTAQ_JSON_EXTRACT_MALFORMED;

    switch (json_unescape_to_buf(val_ptr, (size_t)(end - val_ptr), out_buf, out_size,
                                 &decoded_written)) {
    case JSON_UNESCAPE_OK:
        return VANTAQ_JSON_EXTRACT_OK;
    case JSON_UNESCAPE_TRUNCATED:
        return VANTAQ_JSON_EXTRACT_BUFFER_TOO_SMALL;
    case JSON_UNESCAPE_MALFORMED:
        return VANTAQ_JSON_EXTRACT_MALFORMED;
    case JSON_UNESCAPE_INVALID_ARGUMENT:
    default:
        return VANTAQ_JSON_EXTRACT_INVALID_ARGUMENT;
    }
}

bool vantaq_json_extract_str(const char *json, const char *key, char *out_buf, size_t out_size) {
    return vantaq_json_extract_str_status(json, key, out_buf, out_size) == VANTAQ_JSON_EXTRACT_OK;
}

vantaq_json_extract_status_t vantaq_json_extract_long_status(const char *json, const char *key,
                                                             long *out_val) {
    const char *val_ptr;
    char *endptr;

    if (!out_val)
        return VANTAQ_JSON_EXTRACT_INVALID_ARGUMENT;

    val_ptr = find_key(json, key);
    if (!val_ptr)
        return VANTAQ_JSON_EXTRACT_NOT_FOUND;

    val_ptr = skip_whitespace(val_ptr);
    if (!val_ptr || (!isdigit((unsigned char)*val_ptr) && *val_ptr != '-'))
        return VANTAQ_JSON_EXTRACT_MALFORMED;

    errno    = 0;
    long val = strtol(val_ptr, &endptr, 10);
    if (errno == ERANGE || endptr == val_ptr)
        return VANTAQ_JSON_EXTRACT_MALFORMED;

    *out_val = val;
    return VANTAQ_JSON_EXTRACT_OK;
}

bool vantaq_json_extract_long(const char *json, const char *key, long *out_val) {
    return vantaq_json_extract_long_status(json, key, out_val) == VANTAQ_JSON_EXTRACT_OK;
}

vantaq_json_escape_status_t vantaq_json_escape_str_status(const char *src, char *dst,
                                                          size_t dst_size, size_t *out_written) {
    size_t written = 0;
    const char *p  = src;

    if (out_written != NULL)
        *out_written = 0;

    if (!src || !dst || dst_size == 0)
        return VANTAQ_JSON_ESCAPE_INVALID_ARGUMENT;

    while (*p != '\0' && written < dst_size - 1) {
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
                if (written + 6 >= dst_size) {
                    if (out_written != NULL)
                        *out_written = written;
                    return VANTAQ_JSON_ESCAPE_TRUNCATED;
                }
                dst[written++] = '\\';
                dst[written++] = 'u';
                dst[written++] = '0';
                dst[written++] = '0';
                {
                    static const char hex[] = "0123456789abcdef";
                    unsigned char c         = (unsigned char)*p;

                    dst[written++] = hex[(c >> 4) & 0x0F];
                    dst[written++] = hex[c & 0x0F];
                }
                p++;
                continue;
            }
            break;
        }

        if (esc != '\0') {
            if (written + 2 >= dst_size) {
                if (out_written != NULL)
                    *out_written = written;
                return VANTAQ_JSON_ESCAPE_TRUNCATED;
            }
            dst[written++] = '\\';
            dst[written++] = esc;
        } else {
            dst[written++] = *p;
        }
        p++;
    }

    if (*p != '\0') {
        if (out_written != NULL)
            *out_written = written;
        return VANTAQ_JSON_ESCAPE_TRUNCATED;
    }

    dst[written] = '\0';
    if (out_written != NULL)
        *out_written = written;
    return VANTAQ_JSON_ESCAPE_OK;
}

size_t vantaq_json_escape_str(const char *src, char *dst, size_t dst_size) {
    size_t written = 0;

    if (vantaq_json_escape_str_status(src, dst, dst_size, &written) != VANTAQ_JSON_ESCAPE_OK)
        return 0;
    return written;
}

bool vantaq_json_extract_str_array(const char *json, const char *key, char *out_items,
                                   size_t item_size, size_t max_items, size_t *out_count,
                                   bool *out_present) {
    const char *val_ptr;
    size_t count          = 0;
    size_t decoded_ignore = 0;

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
        const char *item_start;
        const char *item_end;
        size_t raw_len = 0;
        bool escaped   = false;
        json_unescape_result_t ur;

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

        item_start = val_ptr + 1;
        item_end   = item_start;
        while (*item_end != '\0') {
            if (escaped) {
                escaped = false;
                item_end++;
                continue;
            }
            if (*item_end == '\\') {
                escaped = true;
                item_end++;
                continue;
            }
            if (*item_end == '"') {
                break;
            }
            item_end++;
        }

        if (*item_end != '"') {
            return false;
        }
        raw_len = (size_t)(item_end - item_start);
        ur = json_unescape_to_buf(item_start, raw_len, out_items + (count * item_size), item_size,
                                  &decoded_ignore);
        if (ur != JSON_UNESCAPE_OK) {
            return false;
        }
        count++;
        val_ptr = item_end + 1;

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
