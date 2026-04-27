// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_SECURITY_VERIFIER_CONTEXT_H
#define VANTAQ_APPLICATION_SECURITY_VERIFIER_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>

#include "domain/verifier_access/verifier_identity.h"

enum vantaq_verifier_auth_status {
    VANTAQ_VERIFIER_AUTH_STATUS_UNAUTHENTICATED = 0,
    VANTAQ_VERIFIER_AUTH_STATUS_AUTHENTICATED,
};

struct vantaq_verifier_auth_context {
    size_t cbSize;
    enum vantaq_verifier_auth_status status;
    struct vantaq_verifier_identity identity;
};

static inline bool
vantaq_verifier_auth_is_authenticated(const struct vantaq_verifier_auth_context *context) {
    if (context == NULL ||
        context->cbSize < offsetof(struct vantaq_verifier_auth_context, status) +
                              sizeof(context->status)) {
        return false;
    }
    return context->status == VANTAQ_VERIFIER_AUTH_STATUS_AUTHENTICATED;
}

#endif
