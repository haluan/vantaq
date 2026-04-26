// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_APP_H
#define VANTAQ_APPLICATION_APP_H

#include <stddef.h>

typedef int (*vantaq_write_fn)(void *ctx, const char *data);

struct vantaq_app_io {
    vantaq_write_fn write_out;
    vantaq_write_fn write_err;
    void *ctx;
};

int vantaq_app_run(int argc, char **argv, const struct vantaq_app_io *io);

#endif
