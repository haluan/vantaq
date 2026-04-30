// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_EVIDENCE_EVIDENCE_INTERNAL_H
#define VANTAQ_APPLICATION_EVIDENCE_EVIDENCE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/**
 * Validates a text field against a maximum size.
 *
 * @param value The string to validate.
 * @param max_size The maximum allowed size (including NUL).
 * @return true if valid, false otherwise.
 */
static inline bool vantaq_app_evidence_text_is_valid(const char *value, size_t max_size) {
    size_t len;

    if (value == NULL || max_size == 0U) {
        return false;
    }

    len = strnlen(value, max_size);
    if (len == 0U || len >= max_size) {
        return false;
    }

    return true;
}

#endif
