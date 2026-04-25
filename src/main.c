// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"
#include "infrastructure/stdio_io.h"

int main(int argc, char **argv) {
    struct vantaq_stdio_io stdio_io;

    vantaq_stdio_io_init(&stdio_io);
    return vantaq_app_run(argc, argv, &stdio_io.io);
}
