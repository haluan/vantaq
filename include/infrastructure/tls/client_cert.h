// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/verifier_access/verifier_identity.h"

#ifndef VANTAQ_INFRASTRUCTURE_TLS_CLIENT_CERT_H
#define VANTAQ_INFRASTRUCTURE_TLS_CLIENT_CERT_H

struct x509_st;
struct vantaq_tls_ops;

enum vantaq_verifier_identity_status
vantaq_tls_extract_verifier_id(const struct vantaq_tls_ops *ops, struct x509_st *x509_cert,
                               struct vantaq_verifier_identity *identity_out);

#endif
