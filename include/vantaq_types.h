// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_TYPES_H
#define VANTAQ_TYPES_H

#include <stddef.h>

/**
 * Common I/O write callback used for logging and console output.
 */
typedef int (*vantaq_io_write_fn)(void *ctx, const char *data);

#endif
