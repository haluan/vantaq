// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_TLS_CLIENT_CERT_H
#define VANTAQ_INFRASTRUCTURE_TLS_CLIENT_CERT_H

#include "domain/verifier_access/verifier_identity.h"

enum vantaq_verifier_identity_status
vantaq_tls_extract_verifier_id(void *x509_cert, struct vantaq_verifier_identity *identity_out);

#endif
