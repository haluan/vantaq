// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_VERIFIER_ACCESS_VERIFIER_IDENTITY_H
#define VANTAQ_DOMAIN_VERIFIER_ACCESS_VERIFIER_IDENTITY_H

#define VANTAQ_VERIFIER_ID_MAX_LEN 64

enum vantaq_verifier_identity_status {
    VANTAQ_VERIFIER_IDENTITY_STATUS_OK = 0,
    VANTAQ_VERIFIER_IDENTITY_STATUS_MISSING,
    VANTAQ_VERIFIER_IDENTITY_STATUS_INVALID,
};

struct vantaq_verifier_identity {
    char id[VANTAQ_VERIFIER_ID_MAX_LEN];
};

#endif
