// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"
#include "infrastructure/memory/zero_struct.h"
#include "infrastructure/stdio_io.h"

#include <string.h>

int main(int argc, char **argv) {
    struct vantaq_app_io io;
    VANTAQ_ZERO_STRUCT(io);

    vantaq_stdio_io_init(&io);
    return vantaq_app_run(argc, argv, &io);
}
