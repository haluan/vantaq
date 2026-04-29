// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INTERNAL_MACROS_H
#define VANTAQ_INTERNAL_MACROS_H

#include <string.h>

/**
 * @brief Zero out a struct or array.
 * Rule 7.1 from c-pattern.md
 */
#define ER_ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))

#endif
