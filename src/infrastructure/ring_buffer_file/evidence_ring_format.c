// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "evidence_ring_format.h"

const uint8_t VANTAQ_EVIDENCE_RING_MAGIC[VANTAQ_EVIDENCE_RING_MAGIC_SIZE] = {
    0x56, /* V */
    0x51, /* Q */
    0x45, /* E */
    0x52, /* R */
    0x49, /* I */
    0x4E, /* N */
    0x47, /* G */
    0x31, /* 1 */
};

size_t vantaq_evidence_ring_header_size_bytes(void) {
    return (size_t)VANTAQ_EVIDENCE_RING_HEADER_SIZE;
}

size_t vantaq_evidence_ring_record_slot_size_bytes(size_t max_record_bytes) {
    return (size_t)VANTAQ_EVIDENCE_RING_RECORD_METADATA_SIZE + max_record_bytes;
}

size_t vantaq_evidence_ring_slot_offset(size_t slot_index, size_t max_record_bytes) {
    return vantaq_evidence_ring_header_size_bytes() +
           (slot_index * vantaq_evidence_ring_record_slot_size_bytes(max_record_bytes));
}

void vantaq_evidence_ring_le32_encode(uint8_t out[VANTAQ_EVIDENCE_RING_U32_SIZE], uint32_t value) {
    if (out == NULL) {
        return;
    }

    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
}

uint32_t vantaq_evidence_ring_le32_decode(const uint8_t in[VANTAQ_EVIDENCE_RING_U32_SIZE]) {
    uint32_t value = 0;

    if (in == NULL) {
        return 0;
    }

    value |= (uint32_t)in[0];
    value |= ((uint32_t)in[1]) << 8;
    value |= ((uint32_t)in[2]) << 16;
    value |= ((uint32_t)in[3]) << 24;

    return value;
}

void vantaq_evidence_ring_le64_encode(uint8_t out[VANTAQ_EVIDENCE_RING_U64_SIZE], uint64_t value) {
    if (out == NULL) {
        return;
    }

    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
    out[4] = (uint8_t)((value >> 32) & 0xFFu);
    out[5] = (uint8_t)((value >> 40) & 0xFFu);
    out[6] = (uint8_t)((value >> 48) & 0xFFu);
    out[7] = (uint8_t)((value >> 56) & 0xFFu);
}

uint64_t vantaq_evidence_ring_le64_decode(const uint8_t in[VANTAQ_EVIDENCE_RING_U64_SIZE]) {
    uint64_t value = 0;

    if (in == NULL) {
        return 0;
    }

    value |= (uint64_t)in[0];
    value |= ((uint64_t)in[1]) << 8;
    value |= ((uint64_t)in[2]) << 16;
    value |= ((uint64_t)in[3]) << 24;
    value |= ((uint64_t)in[4]) << 32;
    value |= ((uint64_t)in[5]) << 40;
    value |= ((uint64_t)in[6]) << 48;
    value |= ((uint64_t)in[7]) << 56;

    return value;
}
