// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "evidence_ring_format.h"

#include <limits.h>

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

ring_buffer_err_t vantaq_evidence_ring_record_slot_size_bytes(size_t max_record_bytes,
                                                              size_t *out_size) {
    if (out_size == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    if (max_record_bytes == 0U || max_record_bytes > VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    if (max_record_bytes > SIZE_MAX - VANTAQ_EVIDENCE_RING_RECORD_METADATA_SIZE) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    *out_size = (size_t)VANTAQ_EVIDENCE_RING_RECORD_METADATA_SIZE + max_record_bytes;
    return RING_BUFFER_OK;
}

ring_buffer_err_t vantaq_evidence_ring_slot_offset(size_t slot_index, size_t max_record_bytes,
                                                   size_t *out_offset) {
    size_t slot_size;
    ring_buffer_err_t err;

    if (out_offset == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    err = vantaq_evidence_ring_record_slot_size_bytes(max_record_bytes, &slot_size);
    if (err != RING_BUFFER_OK) {
        return err;
    }

    /* Check for slot_index * slot_size overflow */
    if (slot_index > 0 && slot_size > SIZE_MAX / slot_index) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    size_t slots_total_size = slot_index * slot_size;

    /* Check for header_size + slots_total_size overflow */
    if (slots_total_size > SIZE_MAX - VANTAQ_EVIDENCE_RING_HEADER_SIZE) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    *out_offset = (size_t)VANTAQ_EVIDENCE_RING_HEADER_SIZE + slots_total_size;
    return RING_BUFFER_OK;
}

bool vantaq_evidence_ring_u8_encode(uint8_t *out, uint8_t value) {
    if (out == NULL) {
        return false;
    }
    *out = value;
    return true;
}

bool vantaq_evidence_ring_u8_decode(const uint8_t *in, uint8_t *out_value) {
    if (in == NULL || out_value == NULL) {
        return false;
    }
    *out_value = *in;
    return true;
}

bool vantaq_evidence_ring_le32_encode(uint8_t out[VANTAQ_EVIDENCE_RING_U32_SIZE], uint32_t value) {
    if (out == NULL) {
        return false;
    }

    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
    return true;
}

bool vantaq_evidence_ring_le32_decode(const uint8_t in[VANTAQ_EVIDENCE_RING_U32_SIZE],
                                      uint32_t *out_value) {
    if (in == NULL || out_value == NULL) {
        return false;
    }

    uint32_t value = 0;
    value |= (uint32_t)in[0];
    value |= ((uint32_t)in[1]) << 8;
    value |= ((uint32_t)in[2]) << 16;
    value |= ((uint32_t)in[3]) << 24;

    *out_value = value;
    return true;
}

bool vantaq_evidence_ring_le64_encode(uint8_t out[VANTAQ_EVIDENCE_RING_U64_SIZE], uint64_t value) {
    if (out == NULL) {
        return false;
    }

    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
    out[4] = (uint8_t)((value >> 32) & 0xFFu);
    out[5] = (uint8_t)((value >> 40) & 0xFFu);
    out[6] = (uint8_t)((value >> 48) & 0xFFu);
    out[7] = (uint8_t)((value >> 56) & 0xFFu);
    return true;
}

bool vantaq_evidence_ring_le64_decode(const uint8_t in[VANTAQ_EVIDENCE_RING_U64_SIZE],
                                      uint64_t *out_value) {
    if (in == NULL || out_value == NULL) {
        return false;
    }

    uint64_t value = 0;
    value |= (uint64_t)in[0];
    value |= ((uint64_t)in[1]) << 8;
    value |= ((uint64_t)in[2]) << 16;
    value |= ((uint64_t)in[3]) << 24;
    value |= ((uint64_t)in[4]) << 32;
    value |= ((uint64_t)in[5]) << 40;
    value |= ((uint64_t)in[6]) << 48;
    value |= ((uint64_t)in[7]) << 56;

    *out_value = value;
    return true;
}
