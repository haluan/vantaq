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

struct RingBufferReadByIdSuite {
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
    char templ[] = "/tmp/vantaq_ring_by_id_XXXXXX";
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

static void remove_tree_best_effort(const struct RingBufferReadByIdSuite *s) {
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

    if (vantaq_ring_buffer_record_create(cfg, 0U, 0U, evidence_id, "verifier-by-id", issued_at_unix,
                                         evidence_json, "sha256:record-hash", "pending",
                                         &record) != RING_BUFFER_OK) {
        return NULL;
    }

    return record;
}

static int append_record(struct RingBufferReadByIdSuite *s, const char *evidence_id,
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
    struct RingBufferReadByIdSuite *s = calloc(1, sizeof(struct RingBufferReadByIdSuite));

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
    struct RingBufferReadByIdSuite *s = *state;

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

static void test_existing_evidence_id_returns_record(void **state) {
    struct RingBufferReadByIdSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    const struct vantaq_ring_buffer_record *record;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770020001, "{\"claims\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-002", 1770020002, "{\"claims\":2}"), 0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-001", &result),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result), RING_BUFFER_OK);

    record = vantaq_ring_buffer_read_result_get_record(result);
    s_assert_non_null(s, record);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_id(record), "ev-001");
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_sequence(record), 1U);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_json(record), "{\"claims\":1}");

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_unknown_evidence_id_returns_not_found(void **state) {
    struct RingBufferReadByIdSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770020101, "{\"claims\":1}"), 0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-999", &result),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_NOT_FOUND);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_overwritten_evidence_id_returns_not_found(void **state) {
    struct RingBufferReadByIdSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770020201, "{\"n\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-002", 1770020202, "{\"n\":2}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-003", 1770020203, "{\"n\":3}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-004", 1770020204, "{\"n\":4}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-005", 1770020205, "{\"n\":5}"), 0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-001", &result),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_NOT_FOUND);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_read_by_id_does_not_change_file_size(void **state) {
    struct RingBufferReadByIdSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    struct stat before;
    struct stat after;

    s_assert_int_equal(s, append_record(s, "ev-001", 1770020301, "{\"n\":1}"), 0);
    s_assert_int_equal(s, stat(s->ring_path, &before), 0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-001", &result),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, stat(s->ring_path, &after), 0);

    s_assert_int_equal(s, before.st_size, after.st_size);
    s_assert_int_equal(s, (size_t)after.st_size, vantaq_evidence_ring_buffer_file_size(s->buffer));

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_invalid_arguments_rejected(void **state) {
    struct RingBufferReadByIdSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_by_evidence_id(NULL, "ev-001", &result),
                       VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, NULL, &result),
                       VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "", &result),
                       VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT);
    s_assert_int_equal(s,
                       vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-001", NULL),
                       VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT);
}

static void test_invalid_header_returns_invalid_header_status(void **state) {
    struct RingBufferReadByIdSuite *s                  = *state;
    struct vantaq_ring_buffer_read_result *result      = NULL;
    uint8_t bad_magic[VANTAQ_EVIDENCE_RING_MAGIC_SIZE] = {'B', 'A', 'D', 'M', 'A', 'G', 'I', 'C'};

    s_assert_int_equal(s,
                       write_bytes_at(s->ring_path, (off_t)VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET,
                                      bad_magic, sizeof(bad_magic)),
                       0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-001", &result),
        VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER);
    s_assert_null(s, result);
}

static void test_invalid_written_slots_are_skipped(void **state) {
    struct RingBufferReadByIdSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    uint8_t bad_len[VANTAQ_EVIDENCE_RING_U32_SIZE];
    off_t len_offset;

    s_assert_int_equal(s, append_record(s, "ev-target", 1770020401, "{\"n\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-other", 1770020402, "{\"n\":2}"), 0);

    vantaq_evidence_ring_le32_encode(bad_len, 9999U);
    len_offset = (off_t)vantaq_evidence_ring_slot_offset(
                     0U, vantaq_ring_buffer_config_get_max_record_bytes(s->config)) +
                 (off_t)VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET;
    s_assert_int_equal(s, write_bytes_at(s->ring_path, len_offset, bad_len, sizeof(bad_len)), 0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-target", &result),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_NOT_FOUND);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_multiple_same_evidence_id_returns_highest_sequence(void **state) {
    struct RingBufferReadByIdSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    const struct vantaq_ring_buffer_record *record;

    s_assert_int_equal(s, append_record(s, "ev-same", 1770020501, "{\"v\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-other", 1770020502, "{\"v\":2}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-same", 1770020503, "{\"v\":3}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-same", 1770020504, "{\"v\":4}"), 0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-same", &result),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result), RING_BUFFER_OK);

    record = vantaq_ring_buffer_read_result_get_record(result);
    s_assert_non_null(s, record);
    s_assert_int_equal(s, vantaq_ring_buffer_record_get_record_sequence(record), 4U);
    s_assert_string_equal(s, vantaq_ring_buffer_record_get_evidence_json(record), "{\"v\":4}");

    vantaq_ring_buffer_read_result_destroy(result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_existing_evidence_id_returns_record, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_unknown_evidence_id_returns_not_found, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_overwritten_evidence_id_returns_not_found, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_read_by_id_does_not_change_file_size, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_arguments_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_header_returns_invalid_header_status,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_written_slots_are_skipped, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_multiple_same_evidence_id_returns_highest_sequence,
                                        suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("ring_buffer_read_by_id_suite", tests, NULL, NULL);
}
