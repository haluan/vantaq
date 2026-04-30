// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/ring_buffer/ring_buffer.h"
#include "evidence_ring_buffer.h"
#include "evidence_ring_checksum.h"
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

struct RingBufferChecksumSuite {
    char temp_dir[256];
    char ring_path[512];
    struct vantaq_ring_buffer_config *config;
    struct vantaq_evidence_ring_buffer *buffer;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_false(s, a) assert_false(a)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_null(s, a) assert_null(a)

static int make_temp_dir(char *out, size_t out_size) {
    char templ[] = "/tmp/vantaq_ring_checksum_XXXXXX";
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

static void remove_tree_best_effort(const struct RingBufferChecksumSuite *s) {
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

static int append_record(struct RingBufferChecksumSuite *s, const char *evidence_id,
                         int64_t issued_at_unix, const char *evidence_json) {
    struct vantaq_ring_buffer_record *record        = NULL;
    struct vantaq_ring_buffer_append_result *result = NULL;
    enum vantaq_evidence_ring_append_status status;

    if (vantaq_ring_buffer_record_create(s->config, 0U, 0U, evidence_id, "verifier-checksum",
                                         issued_at_unix, evidence_json, "sha256:record-hash",
                                         "pending", &record) != RING_BUFFER_OK) {
        return -1;
    }

    status = vantaq_evidence_ring_buffer_append(s->buffer, record, &result);
    vantaq_ring_buffer_record_destroy(record);

    if (status != VANTAQ_EVIDENCE_RING_APPEND_OK || result == NULL ||
        vantaq_ring_buffer_append_result_get_status(result) != RING_BUFFER_OK) {
        if (result != NULL) {
            vantaq_ring_buffer_append_result_destroy(result);
        }
        return -1;
    }

    vantaq_ring_buffer_append_result_destroy(result);
    return 0;
}

static int read_slot(struct RingBufferChecksumSuite *s, size_t slot_index, uint8_t *slot_buf,
                     size_t slot_buf_size) {
    size_t slot_size = vantaq_evidence_ring_buffer_record_slot_size(s->buffer);
    size_t max_record_bytes;

    if (slot_buf == NULL || slot_buf_size < slot_size) {
        return -1;
    }

    max_record_bytes = vantaq_ring_buffer_config_get_max_record_bytes(s->config);
    {
        size_t offset;
        if (vantaq_evidence_ring_slot_offset(slot_index, max_record_bytes, &offset) !=
            RING_BUFFER_OK) {
            return -1;
        }
        return read_bytes_at(s->ring_path, (off_t)offset, slot_buf, slot_size);
    }
}

static int suite_setup(void **state) {
    struct RingBufferChecksumSuite *s = calloc(1, sizeof(struct RingBufferChecksumSuite));

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
    struct RingBufferChecksumSuite *s = *state;

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

static void test_checksum_is_deterministic_for_same_slot_content(void **state) {
    struct RingBufferChecksumSuite *s = *state;
    uint8_t slot_buf[1024];
    char c1[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
    char c2[VANTAQ_RING_BUFFER_CHECKSUM_MAX];

    s_assert_int_equal(s, append_record(s, "ev-001", 1770100001, "{\"k\":1}"), 0);
    s_assert_int_equal(s, read_slot(s, 0U, slot_buf, sizeof(slot_buf)), 0);

    s_assert_int_equal(s,
                       vantaq_evidence_ring_checksum_compute(
                           slot_buf, vantaq_evidence_ring_buffer_record_slot_size(s->buffer),
                           vantaq_ring_buffer_config_get_max_record_bytes(s->config), c1),
                       VANTAQ_EVIDENCE_RING_CHECKSUM_OK);
    s_assert_int_equal(s,
                       vantaq_evidence_ring_checksum_compute(
                           slot_buf, vantaq_evidence_ring_buffer_record_slot_size(s->buffer),
                           vantaq_ring_buffer_config_get_max_record_bytes(s->config), c2),
                       VANTAQ_EVIDENCE_RING_CHECKSUM_OK);
    s_assert_string_equal(s, c1, c2);
}

static void test_valid_appended_record_passes_checksum_verification(void **state) {
    struct RingBufferChecksumSuite *s = *state;
    uint8_t slot_buf[1024];

    s_assert_int_equal(s, append_record(s, "ev-002", 1770100002, "{\"k\":2}"), 0);
    s_assert_int_equal(s, read_slot(s, 0U, slot_buf, sizeof(slot_buf)), 0);

    s_assert_int_equal(s,
                       vantaq_evidence_ring_checksum_verify(
                           slot_buf, vantaq_evidence_ring_buffer_record_slot_size(s->buffer),
                           vantaq_ring_buffer_config_get_max_record_bytes(s->config)),
                       VANTAQ_EVIDENCE_RING_CHECKSUM_OK);
}

static void test_tampered_evidence_json_fails_checksum(void **state) {
    struct RingBufferChecksumSuite *s = *state;
    uint8_t original_byte;
    uint8_t slot_buf[1024];
    off_t json_off;

    s_assert_int_equal(s, append_record(s, "ev-003", 1770100003, "{\"a\":\"x\"}"), 0);

    {
        size_t offset;
        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                0U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset),
            RING_BUFFER_OK);
        json_off = (off_t)offset + (off_t)VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET + 5;
    }

    s_assert_int_equal(s, read_bytes_at(s->ring_path, json_off, &original_byte, 1U), 0);
    original_byte ^= 0x01U;
    s_assert_int_equal(s, write_bytes_at(s->ring_path, json_off, &original_byte, 1U), 0);

    s_assert_int_equal(s, read_slot(s, 0U, slot_buf, sizeof(slot_buf)), 0);
    s_assert_int_equal(s,
                       vantaq_evidence_ring_checksum_verify(
                           slot_buf, vantaq_evidence_ring_buffer_record_slot_size(s->buffer),
                           vantaq_ring_buffer_config_get_max_record_bytes(s->config)),
                       VANTAQ_EVIDENCE_RING_CHECKSUM_MISMATCH);
}

static void test_tampered_metadata_fails_checksum(void **state) {
    struct RingBufferChecksumSuite *s = *state;
    uint8_t original_byte;
    uint8_t slot_buf[1024];
    off_t meta_off;

    s_assert_int_equal(s, append_record(s, "ev-004", 1770100004, "{\"m\":1}"), 0);

    {
        size_t offset;
        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                0U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset),
            RING_BUFFER_OK);
        meta_off = (off_t)offset + (off_t)VANTAQ_EVIDENCE_RING_RECORD_ISSUED_AT_UNIX_OFFSET;
    }

    s_assert_int_equal(s, read_bytes_at(s->ring_path, meta_off, &original_byte, 1U), 0);
    original_byte ^= 0x10U;
    s_assert_int_equal(s, write_bytes_at(s->ring_path, meta_off, &original_byte, 1U), 0);

    s_assert_int_equal(s, read_slot(s, 0U, slot_buf, sizeof(slot_buf)), 0);
    s_assert_int_equal(s,
                       vantaq_evidence_ring_checksum_verify(
                           slot_buf, vantaq_evidence_ring_buffer_record_slot_size(s->buffer),
                           vantaq_ring_buffer_config_get_max_record_bytes(s->config)),
                       VANTAQ_EVIDENCE_RING_CHECKSUM_MISMATCH);
}

static void test_read_by_id_returns_corrupted_for_latest_corrupted_match(void **state) {
    struct RingBufferChecksumSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    uint8_t byte;
    off_t json_off;

    s_assert_int_equal(s, append_record(s, "ev-target", 1770100101, "{\"v\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-other", 1770100102, "{\"v\":2}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-target", 1770100103, "{\"v\":3}"), 0);

    {
        size_t offset;
        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                2U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset),
            RING_BUFFER_OK);
        json_off = (off_t)offset + (off_t)VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET + 6;
    }

    s_assert_int_equal(s, read_bytes_at(s->ring_path, json_off, &byte, 1U), 0);
    byte ^= 0x20U;
    s_assert_int_equal(s, write_bytes_at(s->ring_path, json_off, &byte, 1U), 0);

    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(s->buffer, "ev-target", &result),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_CORRUPTED);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_record_slot(result), 2U);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_record_sequence(result), 3U);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_read_latest_skips_checksum_corrupted_slot(void **state) {
    struct RingBufferChecksumSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    const struct vantaq_ring_buffer_record *record;
    uint8_t byte;
    off_t json_off;

    s_assert_int_equal(s, append_record(s, "ev-100", 1770100201, "{\"n\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-200", 1770100202, "{\"n\":2}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-300", 1770100203, "{\"n\":3}"), 0);

    {
        size_t offset;
        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                2U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset),
            RING_BUFFER_OK);
        json_off = (off_t)offset + (off_t)VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET + 5;
    }

    s_assert_int_equal(s, read_bytes_at(s->ring_path, json_off, &byte, 1U), 0);
    byte ^= 0x04U;
    s_assert_int_equal(s, write_bytes_at(s->ring_path, json_off, &byte, 1U), 0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_CORRUPTED);

    record = vantaq_ring_buffer_read_result_get_record(result);
    s_assert_null(s, record);

    vantaq_ring_buffer_read_result_destroy(result);
}

static void test_all_written_slots_checksum_invalid_returns_not_found_for_latest(void **state) {
    struct RingBufferChecksumSuite *s             = *state;
    struct vantaq_ring_buffer_read_result *result = NULL;
    uint8_t byte;
    off_t slot0_json_off;
    off_t slot1_json_off;

    s_assert_int_equal(s, append_record(s, "ev-a", 1770100301, "{\"a\":1}"), 0);
    s_assert_int_equal(s, append_record(s, "ev-b", 1770100302, "{\"b\":2}"), 0);

    {
        size_t offset0, offset1;
        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                0U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset0),
            RING_BUFFER_OK);
        slot0_json_off =
            (off_t)offset0 + (off_t)VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET + 5;

        s_assert_int_equal(
            s,
            vantaq_evidence_ring_slot_offset(
                1U, vantaq_ring_buffer_config_get_max_record_bytes(s->config), &offset1),
            RING_BUFFER_OK);
        slot1_json_off =
            (off_t)offset1 + (off_t)VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET + 5;
    }

    s_assert_int_equal(s, read_bytes_at(s->ring_path, slot0_json_off, &byte, 1U), 0);
    byte ^= 0x08U;
    s_assert_int_equal(s, write_bytes_at(s->ring_path, slot0_json_off, &byte, 1U), 0);

    s_assert_int_equal(s, read_bytes_at(s->ring_path, slot1_json_off, &byte, 1U), 0);
    byte ^= 0x10U;
    s_assert_int_equal(s, write_bytes_at(s->ring_path, slot1_json_off, &byte, 1U), 0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(s->buffer, &result),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(result),
                       RING_BUFFER_RECORD_CORRUPTED);

    vantaq_ring_buffer_read_result_destroy(result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_checksum_is_deterministic_for_same_slot_content,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_valid_appended_record_passes_checksum_verification,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_tampered_evidence_json_fails_checksum, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_tampered_metadata_fails_checksum, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(
            test_read_by_id_returns_corrupted_for_latest_corrupted_match, suite_setup,
            suite_teardown),
        cmocka_unit_test_setup_teardown(test_read_latest_skips_checksum_corrupted_slot, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(
            test_all_written_slots_checksum_invalid_returns_not_found_for_latest, suite_setup,
            suite_teardown),
    };

    return cmocka_run_group_tests_name("ring_buffer_checksum_suite", tests, NULL, NULL);
}
