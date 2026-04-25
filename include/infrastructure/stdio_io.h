// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_STDIO_IO_H
#define VANTAQ_INFRASTRUCTURE_STDIO_IO_H

#include "application/app.h"

struct vantaq_stdio_io {
    struct vantaq_app_io io;
};

void vantaq_stdio_io_init(struct vantaq_stdio_io *stdio_io);

#endif
