// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_MEMORY_ZERO_STRUCT_H
#define VANTAQ_INFRASTRUCTURE_MEMORY_ZERO_STRUCT_H

#include <string.h>

/**
 * Project-wide macro for secure and consistent zero-initialization.
 * Evaluates sizeof() at the call site to prevent size-mismatch errors.
 */
#define VANTAQ_ZERO_STRUCT(s)                                                                      \
    do {                                                                                           \
        memset(&(s), 0, sizeof(s));                                                                \
    } while (0)

/**
 * Secure explicit memory wipe for cryptographic material.
 * Attempts to prevent the compiler from optimizing away the memset.
 */
static inline void vantaq_explicit_bzero(void *ptr, size_t size) {
    if (ptr != NULL && size > 0) {
        memset(ptr, 0, size);
        /* Compiler barrier to prevent dead-store elimination */
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
    }
}

#endif
