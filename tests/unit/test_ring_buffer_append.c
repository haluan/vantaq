// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/ring_buffer/ring_buffer.h"
#include "evidence_ring_buffer.h"
#include "evidence_ring_format.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>

struct RingBufferAppendSuite {
    char temp_dir[256];
    char ring_path[512];
    struct vantaq_ring_buffer_config *config;
    struct vantaq_evidence_ring_buffer *buffer;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_null(s, a) assert_null(a)

static int make_temp_dir(char *out, size_t out_size) {
    char templ[] = "/tmp/vantaq_ring_append_XXXXXX";
    char *dir    = mkdtemp(templ);

    if (dir == NULL) {
        return -1;
    }
    if (strlen(dir) >= out_size) {
        return -1;
    }
    memcpy(out, dir, strlen(dir) + 1U);
    return 0;
}

static void remove_tree_best_effort(const struct RingBufferAppendSuite *s) {
    char p2[600];
    char p1[600];
    char p0[600];

    if (s == NULL || s->temp_dir[0] == '\0') {
        return;
    }

    (void)unlink(s->ring_path);

    (void)snprintf(p2, sizeof(p2), "%s/var/lib/vantaqd", s->temp_dir);
    (void)snprintf(p1, sizeof(p1), "%s/var/lib", s->temp_dir);
    (void)snprintf(p0, sizeof(p0), "%s/var", s->temp_dir);

    (void)rmdir(p2);
    (void)rmdir(p1);
    (void)rmdir(p0);
    (void)rmdir(s->temp_dir);
}

static int read_bytes_at(const char *path, off_t offset, uint8_t *out, size_t len) {
    FILE *fp;

    if (path == NULL || out == NULL) {
        return -1;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (fseeko(fp, offset, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    if (fread(out, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int read_header_u32(const char *path, off_t offset, uint32_t *out) {
    uint8_t buf[VANTAQ_EVIDENCE_RING_U32_SIZE];

    if (out == NULL) {
        return -1;
    }
    if (read_bytes_at(path, offset, buf, sizeof(buf)) != 0) {
        return -1;
    }

    *out = vantaq_evidence_ring_le32_decode(buf);
    return 0;
}

static int read_header_u64(const char *path, off_t offset, uint64_t *out) {
    uint8_t buf[VANTAQ_EVIDENCE_RING_U64_SIZE];

    if (out == NULL) {
        return -1;
    }
    if (read_bytes_at(path, offset, buf, sizeof(buf)) != 0) {
        return -1;
    }

    *out = vantaq_evidence_ring_le64_decode(buf);
    return 0;
}

static struct vantaq_ring_buffer_record *create_record(const struct vantaq_ring_buffer_config *cfg,
                                                       const char *evidence_id,
                                                       const char *verifier_id, int64_t issued_at,
                                                       const char *json) {
    struct vantaq_ring_buffer_record *record = NULL;
    ring_buffer_err_t rc =
        vantaq_ring_buffer_record_create(cfg, 0U, 0U, evidence_id, verifier_id, issued_at, json,
                                         "sha256:record-hash", "pending", &record);
    if (rc != RING_BUFFER_OK) {
        return NULL;
    }
    return record;
}

static int suite_setup(void **state) {
    struct RingBufferAppendSuite *s = calloc(1, sizeof(struct RingBufferAppendSuite));

    if (s == NULL) {
        return -1;
    }

    if (make_temp_dir(s->temp_dir, sizeof(s->temp_dir)) != 0) {
        free(s);
        return -1;
    }

    (void)snprintf(s->ring_path, sizeof(s->ring_path), "%s/var/lib/vantaqd/evidence.ring",
                   s->temp_dir);

    if (vantaq_ring_buffer_config_create(s->ring_path, 8U, 256U, true, &s->config) !=
        RING_BUFFER_OK) {
        remove_tree_best_effort(s);
        free(s);
        return -1;
    }

    if (vantaq_evidence_ring_buffer_open(s->config, &s->buffer) != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        vantaq_ring_buffer_config_destroy(s->config);
        remove_tree_best_effort(s);
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct RingBufferAppendSuite *s = *state;

    if (s != NULL) {
        if (s->buffer != NULL) {
            vantaq_evidence_ring_buffer_destroy(s->buffer);
        }
        if (s->config != NULL) {
            vantaq_ring_buffer_config_destroy(s->config);
        }
        remove_tree_best_effort(s);
        free(s);
    }
    return 0;
}

static void test_first_append_succeeds(void **state) {
    struct RingBufferAppendSuite *s                 = *state;
    struct vantaq_ring_buffer_record *record        = NULL;
    struct vantaq_ring_buffer_append_result *result = NULL;

    record = create_record(s->config, "ev-001", "verifier-001", 1770000001, "{\"k\":1}");
    s_assert_non_null(s, record);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, &result),
                       VANTAQ_EVIDENCE_RING_APPEND_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_append_result_get_status(result), RING_BUFFER_OK);
    s_assert_int_equal(s, vantaq_ring_buffer_append_result_get_record_slot(result), 0U);
    s_assert_int_equal(s, vantaq_ring_buffer_append_result_get_record_sequence(result), 1U);

    vantaq_ring_buffer_append_result_destroy(result);
    vantaq_ring_buffer_record_destroy(record);
}

static void test_multiple_appends_advance_slots(void **state) {
    struct RingBufferAppendSuite *s = *state;
    size_t i;

    for (i = 0U; i < 3U; i++) {
        char evidence_id[32];
        struct vantaq_ring_buffer_record *record;
        struct vantaq_ring_buffer_append_result *result = NULL;

        (void)snprintf(evidence_id, sizeof(evidence_id), "ev-%03zu", i + 1U);
        record = create_record(s->config, evidence_id, "verifier-001", 1770000100 + (int64_t)i,
                               "{\"n\":1}");
        s_assert_non_null(s, record);

        s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, &result),
                           VANTAQ_EVIDENCE_RING_APPEND_OK);
        s_assert_int_equal(s, vantaq_ring_buffer_append_result_get_record_slot(result),
                           (uint64_t)i);

        vantaq_ring_buffer_append_result_destroy(result);
        vantaq_ring_buffer_record_destroy(record);
    }
}

static void test_append_wraps_after_capacity(void **state) {
    struct RingBufferAppendSuite *s = *state;
    size_t i;
    uint32_t write_slot    = 999U;
    uint64_t next_sequence = 999U;

    for (i = 0U; i < 9U; i++) {
        char evidence_id[32];
        struct vantaq_ring_buffer_record *record;
        struct vantaq_ring_buffer_append_result *result = NULL;

        (void)snprintf(evidence_id, sizeof(evidence_id), "wrap-%03zu", i + 1U);
        record = create_record(s->config, evidence_id, "verifier-wrap", 1770000200 + (int64_t)i,
                               "{\"w\":1}");
        s_assert_non_null(s, record);
        s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, &result),
                           VANTAQ_EVIDENCE_RING_APPEND_OK);

        if (i == 8U) {
            s_assert_int_equal(s, vantaq_ring_buffer_append_result_get_record_slot(result), 0U);
            s_assert_int_equal(s, vantaq_ring_buffer_append_result_get_record_sequence(result), 9U);
        }

        vantaq_ring_buffer_append_result_destroy(result);
        vantaq_ring_buffer_record_destroy(record);
    }

    s_assert_int_equal(
        s,
        read_header_u32(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET, &write_slot),
        0);
    s_assert_int_equal(s,
                       read_header_u64(s->ring_path,
                                       VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET,
                                       &next_sequence),
                       0);

    s_assert_int_equal(s, write_slot, 1U);
    s_assert_int_equal(s, next_sequence, 10U);
}

static void test_oversized_record_is_rejected(void **state) {
    struct RingBufferAppendSuite *s                 = *state;
    struct vantaq_ring_buffer_config *wide_cfg      = NULL;
    struct vantaq_ring_buffer_record *record        = NULL;
    struct vantaq_ring_buffer_append_result *result = NULL;
    uint32_t write_slot_before                      = 999U;
    uint64_t next_seq_before                        = 999U;
    uint32_t write_slot_after                       = 999U;
    uint64_t next_seq_after                         = 999U;
    char json_buf[400];

    memset(json_buf, 'x', sizeof(json_buf) - 1U);
    json_buf[0]                     = '{';
    json_buf[1]                     = '"';
    json_buf[2]                     = 'a';
    json_buf[3]                     = '"';
    json_buf[4]                     = ':';
    json_buf[5]                     = '"';
    json_buf[sizeof(json_buf) - 2U] = '"';
    json_buf[sizeof(json_buf) - 1U] = '\0';

    s_assert_int_equal(s, vantaq_ring_buffer_config_create(s->ring_path, 8U, 512U, true, &wide_cfg),
                       RING_BUFFER_OK);

    record = create_record(wide_cfg, "ev-oversized", "verifier-oversized", 1770000300, json_buf);
    s_assert_non_null(s, record);

    s_assert_int_equal(s,
                       read_header_u32(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET,
                                       &write_slot_before),
                       0);
    s_assert_int_equal(s,
                       read_header_u64(s->ring_path,
                                       VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET,
                                       &next_seq_before),
                       0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, &result),
                       VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT);
    s_assert_null(s, result);

    s_assert_int_equal(s,
                       read_header_u32(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET,
                                       &write_slot_after),
                       0);
    s_assert_int_equal(s,
                       read_header_u64(s->ring_path,
                                       VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET,
                                       &next_seq_after),
                       0);

    s_assert_int_equal(s, write_slot_after, write_slot_before);
    s_assert_int_equal(s, next_seq_after, next_seq_before);

    vantaq_ring_buffer_record_destroy(record);
    vantaq_ring_buffer_config_destroy(wide_cfg);
}

static void test_stored_record_readable_by_test_helper(void **state) {
    struct RingBufferAppendSuite *s                 = *state;
    struct vantaq_ring_buffer_record *record        = NULL;
    struct vantaq_ring_buffer_append_result *result = NULL;
    uint8_t slot_buf[1024];
    uint32_t slot;
    uint64_t seq;
    uint64_t issued_at;
    uint32_t json_len;

    record = create_record(s->config, "ev-check", "verifier-check", 1770000400,
                           "{\"claims\":{\"firmware_hash\":\"sha256:abc\"}}");
    s_assert_non_null(s, record);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, &result),
                       VANTAQ_EVIDENCE_RING_APPEND_OK);
    s_assert_non_null(s, result);

    s_assert_true(s, vantaq_evidence_ring_buffer_record_slot_size(s->buffer) <= sizeof(slot_buf));

    s_assert_int_equal(s,
                       read_bytes_at(s->ring_path,
                                     (off_t)vantaq_evidence_ring_slot_offset(
                                         vantaq_ring_buffer_append_result_get_record_slot(result),
                                         vantaq_evidence_ring_buffer_max_record_bytes(s->buffer)),
                                     slot_buf,
                                     vantaq_evidence_ring_buffer_record_slot_size(s->buffer)),
                       0);

    s_assert_int_equal(s, slot_buf[VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET],
                       VANTAQ_EVIDENCE_RING_RECORD_STATE_WRITTEN);

    slot = vantaq_evidence_ring_le32_decode(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_SLOT_OFFSET);
    seq  = vantaq_evidence_ring_le64_decode(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_SEQUENCE_OFFSET);
    issued_at = vantaq_evidence_ring_le64_decode(slot_buf +
                                                 VANTAQ_EVIDENCE_RING_RECORD_ISSUED_AT_UNIX_OFFSET);
    json_len  = vantaq_evidence_ring_le32_decode(
        slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET);

    s_assert_int_equal(s, slot, 0U);
    s_assert_int_equal(s, seq, 1U);
    s_assert_int_equal(s, issued_at, 1770000400U);
    s_assert_int_equal(s, json_len, strlen("{\"claims\":{\"firmware_hash\":\"sha256:abc\"}}"));

    s_assert_string_equal(
        s, (const char *)(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET), "ev-check");
    s_assert_string_equal(s,
                          (const char *)(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_VERIFIER_ID_OFFSET),
                          "verifier-check");

    s_assert_true(s, memcmp(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET,
                            "{\"claims\":{\"firmware_hash\":\"sha256:abc\"}}", json_len) == 0);

    vantaq_ring_buffer_append_result_destroy(result);
    vantaq_ring_buffer_record_destroy(record);
}

static void test_header_updates_per_append(void **state) {
    struct RingBufferAppendSuite *s                 = *state;
    struct vantaq_ring_buffer_record *record        = NULL;
    struct vantaq_ring_buffer_append_result *result = NULL;
    uint32_t write_slot;
    uint64_t next_sequence;

    record = create_record(s->config, "ev-hdr", "verifier-hdr", 1770000500, "{\"h\":1}");
    s_assert_non_null(s, record);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, &result),
                       VANTAQ_EVIDENCE_RING_APPEND_OK);

    s_assert_int_equal(
        s,
        read_header_u32(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET, &write_slot),
        0);
    s_assert_int_equal(s,
                       read_header_u64(s->ring_path,
                                       VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET,
                                       &next_sequence),
                       0);

    s_assert_int_equal(s, write_slot, 1U);
    s_assert_int_equal(s, next_sequence, 2U);

    vantaq_ring_buffer_append_result_destroy(result);
    vantaq_ring_buffer_record_destroy(record);
}

static void test_invalid_arguments_rejected(void **state) {
    struct RingBufferAppendSuite *s                 = *state;
    struct vantaq_ring_buffer_record *record        = NULL;
    struct vantaq_ring_buffer_append_result *result = NULL;

    record = create_record(s->config, "ev-invalid", "verifier-invalid", 1770000600, "{\"x\":1}");
    s_assert_non_null(s, record);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(NULL, record, &result),
                       VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, NULL, &result),
                       VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, NULL),
                       VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT);

    vantaq_ring_buffer_record_destroy(record);
}

static void test_file_size_stays_bounded_after_appends(void **state) {
    struct RingBufferAppendSuite *s = *state;
    struct stat before;
    struct stat after;
    size_t i;

    s_assert_int_equal(s, stat(s->ring_path, &before), 0);

    for (i = 0U; i < 16U; i++) {
        char evidence_id[32];
        struct vantaq_ring_buffer_record *record;
        struct vantaq_ring_buffer_append_result *result = NULL;

        (void)snprintf(evidence_id, sizeof(evidence_id), "ev-bnd-%03zu", i);
        record = create_record(s->config, evidence_id, "verifier-bnd", 1770000700 + (int64_t)i,
                               "{\"bounded\":1}");
        s_assert_non_null(s, record);

        s_assert_int_equal(s, vantaq_evidence_ring_buffer_append(s->buffer, record, &result),
                           VANTAQ_EVIDENCE_RING_APPEND_OK);

        vantaq_ring_buffer_append_result_destroy(result);
        vantaq_ring_buffer_record_destroy(record);
    }

    s_assert_int_equal(s, stat(s->ring_path, &after), 0);
    s_assert_int_equal(s, before.st_size, after.st_size);
    s_assert_int_equal(s, (size_t)after.st_size, vantaq_evidence_ring_buffer_file_size(s->buffer));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_first_append_succeeds, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_multiple_appends_advance_slots, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_append_wraps_after_capacity, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_oversized_record_is_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_stored_record_readable_by_test_helper, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_header_updates_per_append, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_arguments_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_file_size_stays_bounded_after_appends, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("ring_buffer_append_suite", tests, NULL, NULL);
}
