// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "evidence_ring_format.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <cmocka.h>

struct EvidenceRingFormatSuite {
    size_t max_records;
    size_t max_record_bytes;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_false(s, a) assert_false(a)
#define s_assert_non_null(s, a) assert_non_null(a)

static int suite_setup(void **state) {
    struct EvidenceRingFormatSuite *s = calloc(1, sizeof(struct EvidenceRingFormatSuite));
    if (s == NULL) {
        return -1;
    }

    s->max_records      = 1024U;
    s->max_record_bytes = 8192U;

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    free(s);
    return 0;
}

static void test_header_size_is_deterministic(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    const size_t expected =
        (size_t)VANTAQ_EVIDENCE_RING_MAGIC_SIZE + (size_t)VANTAQ_EVIDENCE_RING_U32_SIZE +
        (size_t)VANTAQ_EVIDENCE_RING_U32_SIZE + (size_t)VANTAQ_EVIDENCE_RING_U32_SIZE +
        (size_t)VANTAQ_EVIDENCE_RING_U32_SIZE + (size_t)VANTAQ_EVIDENCE_RING_U32_SIZE +
        (size_t)VANTAQ_EVIDENCE_RING_U32_SIZE + (size_t)VANTAQ_EVIDENCE_RING_U64_SIZE;

    s_assert_int_equal(s, vantaq_evidence_ring_header_size_bytes(), expected);
    s_assert_int_equal(s, VANTAQ_EVIDENCE_RING_HEADER_SIZE, expected);
}

static void test_record_slot_size_is_deterministic(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    size_t slot_size_a;
    size_t slot_size_b;

    s_assert_int_equal(
        s, vantaq_evidence_ring_record_slot_size_bytes(s->max_record_bytes, &slot_size_a),
        RING_BUFFER_OK);
    s_assert_int_equal(
        s, vantaq_evidence_ring_record_slot_size_bytes(s->max_record_bytes, &slot_size_b),
        RING_BUFFER_OK);

    s_assert_int_equal(s, slot_size_a, slot_size_b);
    s_assert_int_equal(s, slot_size_a,
                       (size_t)VANTAQ_EVIDENCE_RING_RECORD_METADATA_SIZE + s->max_record_bytes);
}

static void test_slot_zero_offset_matches_header_size(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    size_t slot0_offset;

    s_assert_int_equal(s, vantaq_evidence_ring_slot_offset(0U, s->max_record_bytes, &slot0_offset),
                       RING_BUFFER_OK);

    s_assert_int_equal(s, slot0_offset, vantaq_evidence_ring_header_size_bytes());
}

static void test_last_slot_offset_matches_formula(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    size_t slot_size;
    size_t last_slot = s->max_records - 1U;
    size_t expected;
    size_t actual;

    s_assert_int_equal(s,
                       vantaq_evidence_ring_record_slot_size_bytes(s->max_record_bytes, &slot_size),
                       RING_BUFFER_OK);
    expected = vantaq_evidence_ring_header_size_bytes() + (last_slot * slot_size);

    s_assert_int_equal(s, vantaq_evidence_ring_slot_offset(last_slot, s->max_record_bytes, &actual),
                       RING_BUFFER_OK);
    s_assert_int_equal(s, actual, expected);
}

static void test_slot_offsets_monotonic_and_non_overlapping(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    size_t slot_size;
    size_t prev;

    s_assert_int_equal(s,
                       vantaq_evidence_ring_record_slot_size_bytes(s->max_record_bytes, &slot_size),
                       RING_BUFFER_OK);
    s_assert_int_equal(s, vantaq_evidence_ring_slot_offset(0U, s->max_record_bytes, &prev),
                       RING_BUFFER_OK);

    for (size_t i = 1U; i < 16U; i++) {
        size_t current;
        s_assert_int_equal(s, vantaq_evidence_ring_slot_offset(i, s->max_record_bytes, &current),
                           RING_BUFFER_OK);
        s_assert_true(s, current > prev);
        s_assert_true(s, current >= (prev + slot_size));
        prev = current;
    }
}

static void test_little_endian_encode_decode_roundtrip(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    uint8_t le32[VANTAQ_EVIDENCE_RING_U32_SIZE];
    uint8_t le64[VANTAQ_EVIDENCE_RING_U64_SIZE];
    uint32_t decoded32;
    uint64_t decoded64;

    const uint32_t value32 = 0x78563412u;
    const uint64_t value64 = 0xEFCDAB9078563412ull;

    s_assert_true(s, vantaq_evidence_ring_le32_encode(le32, value32));
    s_assert_true(s, vantaq_evidence_ring_le64_encode(le64, value64));

    s_assert_int_equal(s, le32[0], 0x12);
    s_assert_int_equal(s, le32[1], 0x34);
    s_assert_int_equal(s, le32[2], 0x56);
    s_assert_int_equal(s, le32[3], 0x78);

    s_assert_int_equal(s, le64[0], 0x12);
    s_assert_int_equal(s, le64[1], 0x34);
    s_assert_int_equal(s, le64[2], 0x56);
    s_assert_int_equal(s, le64[3], 0x78);
    s_assert_int_equal(s, le64[4], 0x90);
    s_assert_int_equal(s, le64[5], 0xAB);
    s_assert_int_equal(s, le64[6], 0xCD);
    s_assert_int_equal(s, le64[7], 0xEF);

    s_assert_true(s, vantaq_evidence_ring_le32_decode(le32, &decoded32));
    s_assert_int_equal(s, decoded32, value32);
    s_assert_true(s, vantaq_evidence_ring_le64_decode(le64, &decoded64));
    s_assert_int_equal(s, decoded64, value64);
}

static void test_u8_encode_decode_roundtrip(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    uint8_t val;
    uint8_t decoded;

    s_assert_true(s, vantaq_evidence_ring_u8_encode(&val, 0x42));
    s_assert_int_equal(s, val, 0x42);
    s_assert_true(s, vantaq_evidence_ring_u8_decode(&val, &decoded));
    s_assert_int_equal(s, decoded, 0x42);
}

static void test_overflow_protection(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    size_t size;
    size_t offset;

    /* S-1: Integer overflow in slot_size */
    s_assert_int_equal(s, vantaq_evidence_ring_record_slot_size_bytes(SIZE_MAX, &size),
                       RING_BUFFER_INVALID_CONFIG);

    /* S-2: Compounded overflow in slot_offset */
    s_assert_int_equal(s, vantaq_evidence_ring_slot_offset(SIZE_MAX / 2, SIZE_MAX / 2, &offset),
                       RING_BUFFER_INVALID_CONFIG);
}

static void test_null_safety(void **state) {
    struct EvidenceRingFormatSuite *s = *state;
    uint8_t buf[8];
    uint32_t v32;
    uint64_t v64;
    uint8_t v8;

    s_assert_false(s, vantaq_evidence_ring_le32_encode(NULL, 0));
    s_assert_false(s, vantaq_evidence_ring_le64_encode(NULL, 0));
    s_assert_false(s, vantaq_evidence_ring_u8_encode(NULL, 0));

    s_assert_false(s, vantaq_evidence_ring_le32_decode(NULL, &v32));
    s_assert_false(s, vantaq_evidence_ring_le32_decode(buf, NULL));
    s_assert_false(s, vantaq_evidence_ring_le64_decode(NULL, &v64));
    s_assert_false(s, vantaq_evidence_ring_le64_decode(buf, NULL));
    s_assert_false(s, vantaq_evidence_ring_u8_decode(NULL, &v8));
    s_assert_false(s, vantaq_evidence_ring_u8_decode(buf, NULL));
}

static void test_record_state_constants_are_stable(void **state) {
    struct EvidenceRingFormatSuite *s = *state;

    s_assert_int_equal(s, VANTAQ_EVIDENCE_RING_RECORD_STATE_EMPTY, 0);
    s_assert_int_equal(s, VANTAQ_EVIDENCE_RING_RECORD_STATE_WRITTEN, 1);
    s_assert_int_equal(s, VANTAQ_EVIDENCE_RING_RECORD_STATE_CORRUPTED, 2);
    s_assert_non_null(s, VANTAQ_EVIDENCE_RING_MAGIC);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_header_size_is_deterministic, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_record_slot_size_is_deterministic, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_slot_zero_offset_matches_header_size, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_last_slot_offset_matches_formula, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_slot_offsets_monotonic_and_non_overlapping,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_little_endian_encode_decode_roundtrip, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_u8_encode_decode_roundtrip, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_overflow_protection, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_null_safety, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_record_state_constants_are_stable, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("evidence_ring_format_suite", tests, NULL, NULL);
}
