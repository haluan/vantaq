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
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>

struct RingBufferReadLatestSuite {
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
    char templ[] = "/tmp/vantaq_ring_latest_XXXXXX";
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

static void remove_tree_best_effort(const struct RingBufferReadLatestSuite *s) {
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

static int write_bytes_at(const char *path, off_t offset, const uint8_t *buf, size_t len) {
    FILE *fp;

    if (path == NULL || buf == NULL) {
        return -1;
    }

    fp = fopen(path, "r+b");
    if (fp == NULL) {
        return -1;
    }

    if (fseeko(fp, offset, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    if (fwrite(buf, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static struct vantaq_ring_buffer_record *create_record(const struct vantaq_ring_buffer_config *cfg,
                                                       const char *evidence_id,
                                                       int64_t issued_at_unix,
                                                       const char *evidence_json) {
    struct vantaq_ring_buffer_record *record = NULL;

    if (vantaq_ring_buffer_record_create(cfg, 0U, 0U, evidence_id, "verifier-latest",
                                         issued_at_unix, evidence_json, "sha256:record-hash",
                                         "pending", &record) != RING_BUFFER_OK) {
        return NULL;
    }

    return record;
}

static int append_record(struct RingBufferReadLatestSuite *s, const char *evidence_id,
                         int64_t issued_at_unix, const char *evidence_json) {
    struct vantaq_ring_buffer_record *record        = NULL;
    struct vantaq_ring_buffer_append_result *result = NULL;
    enum vantaq_evidence_ring_append_status status;

    record = create_record(s->config, evidence_id, issued_at_unix, evidence_json);
    if (record == NULL) {
        return -1;
    }

    status = vantaq_evidence_ring_buffer_append(s->buffer, record, &result);
    vantaq_ring_buffer_record_destroy(record);
    if (status != VANTAQ_EVIDENCE_RING_APPEND_OK || result == NULL) {
        if (result != NULL) {
            vantaq_ring_buffer_append_result_destroy(result);
        }
        return -1;
    }

    vantaq_ring_buffer_append_result_destroy(result);
    return 0;
}

static int suite_setup(void **state) {
    struct RingBufferReadLatestSuite *s = calloc(1, sizeof(struct RingBufferReadLatestSuite));

    if (s == NULL) {
        return -1;
    }

    if (make_temp_dir(s->temp_dir, sizeof(s->temp_dir)) != 0) {
        free(s);
        return -1;
    }

    (void)snprintf(s->ring_path, sizeof(s->ring_path), "%s/var/lib/vantaqd/evidence.ring",
                   s->temp_dir);

    if (vantaq_ring_buffer_config_create(s->ring_path, 4U, 256U, true, &s->config) !=
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
    struct RingBufferReadLatestSuite *s = *state;

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

static void test_empty_ring_returns_not_found(void **state) {
    struct RingBufferReadLatestSuite *s           = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_NOT_FOUND);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_single_record_returns_that_record(void **state) {
    struct RingBufferReadLatestSuite *s           = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    const struct vantaq_ring_buffer_record *record;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770010001, "{\"n\":1}"), 0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result), RING_BUFFER_OK);

    record = vantaq_ring_buffer_read_result_get_record(result);
    s_assert_non_null(s, record);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_id(record), "ev-001");
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_sequence(record), 1U);
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_slot(record), 0U);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_json(record), "{\"n\":1}");

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_multiple_records_returns_highest_sequence(void **state) {
    struct RingBufferReadLatestSuite *s           = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    const struct vantaq_ring_buffer_record *record;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770010101, "{\"n\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-002", 1770010102, "{\"n\":2}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-003", 1770010103, "{\"n\":3}"), 0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result), RING_BUFFER_OK);

    record = vantaq_ring_buffer_read_result_get_record(result);
    s_assert_non_null(s, record);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_id(record), "ev-003");
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_sequence(record), 3U);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_wraparound_still_returns_highest_sequence(void **state) {
    struct RingBufferReadLatestSuite *s           = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    const struct vantaq_ring_buffer_record *record;
    size_t i;

    for (i = 1U; i <= 10U; i++) {
        char evidence_id[32];
        char json[32];

        (void)snprintf(evidence_id, sizeof(evidence_id), "ev-%03zu", i);
        (void)snprintf(json, sizeof(json), "{\"n\":%zu}", i);
        s_assert_int_equal(s, append_record(s, evidence_id, 1770010200 + (int64_t)i, json), 0);
    }

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result), RING_BUFFER_OK);

    record = vantaq_ring_buffer_read_result_get_record(result);
    s_assert_non_null(s, record);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_id(record), "ev-010");
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_sequence(record), 10U);
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_slot(record), 1U);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_corrupted_newest_slot_is_skipped(void **state) {
    struct RingBufferReadLatestSuite *s           = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    const struct vantaq_ring_buffer_record *record;
    uint8_t bad_len[VANTAQ_EVIDENCE_RING_U32_SIZE];
    off_t len_offset;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770010301, "{\"n\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-002", 1770010302, "{\"n\":2}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-003", 1770010303, "{\"n\":3}"), 0);

    s_assert_true(s, vantaq_evidence_ring_le32_encode(bad_len, 9999U));
    {
        size_t offset;
        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                2U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset),
            RING_BUFFER_OK);
        len_offset = (off_t)offset + (off_t)VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET;
    }
    s_assert_int_equal(s, write_bytes_at(s->ring_path, len_offset, bad_len, sizeof(bad_len)), 0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result), RING_BUFFER_OK);

    record = vantaq_ring_buffer_read_result_get_record(result);
    s_assert_non_null(s, record);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_id(record), "ev-002");
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_sequence(record), 2U);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_all_non_empty_invalid_returns_not_found(void **state) {
    struct RingBufferReadLatestSuite *s           = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    uint8_t state_corrupted                       = VANTAQ_EVIDENCE_RING_RECORD_STATE_CORRUPTED;
    uint8_t state_unknown                         = 99U;
    off_t slot0_state_offset;
    off_t slot1_state_offset;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770010401, "{\"n\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-002", 1770010402, "{\"n\":2}"), 0);

    {
        size_t offset0, offset1;
        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                0U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset0),
            RING_BUFFER_OK);
        slot0_state_offset = (off_t)offset0 + (off_t)VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET;

        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                1U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset1),
            RING_BUFFER_OK);
        slot1_state_offset = (off_t)offset1 + (off_t)VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET;
    }

    {
        uint8_t encoded_corrupted, encoded_unknown;
        s_assert_true(s, vantaq_evidence_ring_u8_encode(&encoded_corrupted, state_corrupted));
        s_assert_true(s, vantaq_evidence_ring_u8_encode(&encoded_unknown, state_unknown));

        s_assert_int_equal(
            s, write_bytes_at(s->ring_path, slot0_state_offset, &encoded_corrupted, 1U), 0);
        s_assert_int_equal(
            s, write_bytes_at(s->ring_path, slot1_state_offset, &encoded_unknown, 1U), 0);
    }

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_NOT_FOUND);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_invalid_arguments_rejected(void **state) {
    struct RingBufferReadLatestSuite *s           = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(NULL, &result),
                       VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, NULL),
                       VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT);
}

static void test_invalid_header_returns_invalid_header_status(void **state) {
    struct RingBufferReadLatestSuite *s                = *state;
    struct vantaq_ring_buffer_read_result *result      = NULL;
    uint8_t bad_magic[VANTAQ_EVIDENCE_RING_MAGIC_SIZE] = {'B', 'A', 'D', 'M', 'A', 'G', 'I', 'C'};

    s_assert_int_equal(s,
                       write_bytes_at(s->ring_path, (off_t)VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET,
                                      bad_magic, sizeof(bad_magic)),
                       0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER);
    s_assert_null(s, result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_empty_ring_returns_not_found, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_single_record_returns_that_record, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_multiple_records_returns_highest_sequence, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_wraparound_still_returns_highest_sequence, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_corrupted_newest_slot_is_skipped, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_all_non_empty_invalid_returns_not_found, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_arguments_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_header_returns_invalid_header_status,
                                        suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("ring_buffer_read_latest_suite", tests, NULL, NULL);
}
