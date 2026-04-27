// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_MEMORY_CHALLENGE_STORE_MEMORY_H
#define VANTAQ_INFRASTRUCTURE_MEMORY_CHALLENGE_STORE_MEMORY_H

#include "domain/attestation_challenge/challenge_store.h"

struct vantaq_challenge_store* vantaq_challenge_store_memory_create(size_t max_global, size_t max_per_verifier);

#endif
