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

struct RingBufferOpenInitSuite {
    char temp_dir[256];
    char ring_path[512];
    struct vantaq_ring_buffer_config *config;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)

static int make_temp_dir(char *out, size_t out_size) {
    char templ[] = "/tmp/vantaq_ring_init_XXXXXX";
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

static int read_file_bytes(const char *path, uint8_t *buf, size_t len) {
    FILE *fp;

    if (path == NULL || buf == NULL) {
        return -1;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (fread(buf, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int read_u32_field(const char *path, off_t offset, uint32_t *out) {
    uint8_t buf[VANTAQ_EVIDENCE_RING_U32_SIZE];
    FILE *fp;

    if (out == NULL) {
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
    if (fread(buf, 1, sizeof(buf), fp) != sizeof(buf)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    *out = vantaq_evidence_ring_le32_decode(buf);
    return 0;
}

static int read_u64_field(const char *path, off_t offset, uint64_t *out) {
    uint8_t buf[VANTAQ_EVIDENCE_RING_U64_SIZE];
    FILE *fp;

    if (out == NULL) {
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
    if (fread(buf, 1, sizeof(buf), fp) != sizeof(buf)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *out = vantaq_evidence_ring_le64_decode(buf);
    return 0;
}

static void remove_tree_best_effort(const struct RingBufferOpenInitSuite *s) {
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

static int suite_setup(void **state) {
    struct RingBufferOpenInitSuite *s = calloc(1, sizeof(struct RingBufferOpenInitSuite));

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

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct RingBufferOpenInitSuite *s = *state;

    if (s != NULL) {
        if (s->config != NULL) {
            vantaq_ring_buffer_config_destroy(s->config);
            s->config = NULL;
        }
        remove_tree_best_effort(s);
        free(s);
    }
    return 0;
}

static void test_create_missing_file_and_header_valid(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;
    struct stat st;
    uint8_t header[VANTAQ_EVIDENCE_RING_HEADER_SIZE];
    uint32_t version;
    uint32_t max_records;
    uint32_t max_record_bytes;
    uint64_t next_sequence;
    size_t expected_file_size;

    enum vantaq_evidence_ring_open_status rc = vantaq_evidence_ring_buffer_open(s->config, &buffer);
    s_assert_int_equal(s, rc, VANTAQ_EVIDENCE_RING_OPEN_OK);
    s_assert_non_null(s, buffer);

    s_assert_int_equal(s, stat(s->ring_path, &st), 0);
    s_assert_true(s, S_ISREG(st.st_mode));
    s_assert_int_equal(s, (st.st_mode & 0777), 0600);

    {
        struct stat st_dir;
        char dir_path[600];
        (void)snprintf(dir_path, sizeof(dir_path), "%s/var/lib/vantaqd", s->temp_dir);
        s_assert_int_equal(s, stat(dir_path, &st_dir), 0);
        s_assert_true(s, S_ISDIR(st_dir.st_mode));
        s_assert_int_equal(s, (st_dir.st_mode & 0777), 0700);
    }

    expected_file_size = vantaq_evidence_ring_header_size_bytes() +
                         (vantaq_ring_buffer_config_get_max_records(s->config) *
                          vantaq_evidence_ring_record_slot_size_bytes(
                              vantaq_ring_buffer_config_get_max_record_bytes(s->config)));

    s_assert_int_equal(s, (size_t)st.st_size, expected_file_size);
    s_assert_int_equal(s, read_file_bytes(s->ring_path, header, sizeof(header)), 0);

    s_assert_true(s, memcmp(header + VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET,
                            VANTAQ_EVIDENCE_RING_MAGIC, VANTAQ_EVIDENCE_RING_MAGIC_SIZE) == 0);

    version = vantaq_evidence_ring_le32_decode(header + VANTAQ_EVIDENCE_RING_HEADER_VERSION_OFFSET);
    max_records =
        vantaq_evidence_ring_le32_decode(header + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORDS_OFFSET);
    max_record_bytes = vantaq_evidence_ring_le32_decode(
        header + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORD_BYTES_OFFSET);
    next_sequence =
        vantaq_evidence_ring_le64_decode(header + VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET);

    s_assert_int_equal(s, version, VANTAQ_EVIDENCE_RING_FORMAT_VERSION);
    s_assert_int_equal(s, max_records, 8U);
    s_assert_int_equal(s, max_record_bytes, 256U);
    s_assert_int_equal(s, next_sequence, 1U);

    vantaq_evidence_ring_buffer_destroy(buffer);
}

static void test_open_existing_valid_file_success(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *first  = NULL;
    struct vantaq_evidence_ring_buffer *second = NULL;
    uint32_t write_slot_before;
    uint64_t next_seq_before;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &first),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    s_assert_non_null(s, first);
    s_assert_int_equal(s,
                       read_u32_field(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET,
                                      &write_slot_before),
                       0);
    s_assert_int_equal(s,
                       read_u64_field(s->ring_path,
                                      VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET,
                                      &next_seq_before),
                       0);
    vantaq_evidence_ring_buffer_destroy(first);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &second),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    s_assert_non_null(s, second);

    {
        uint32_t write_slot_after;
        uint64_t next_seq_after;
        s_assert_int_equal(s,
                           read_u32_field(s->ring_path,
                                          VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET,
                                          &write_slot_after),
                           0);
        s_assert_int_equal(s,
                           read_u64_field(s->ring_path,
                                          VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET,
                                          &next_seq_after),
                           0);
        s_assert_int_equal(s, write_slot_after, write_slot_before);
        s_assert_int_equal(s, next_seq_after, next_seq_before);
    }

    vantaq_evidence_ring_buffer_destroy(second);
}

static void test_invalid_magic_returns_invalid_header(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;
    uint8_t bad                                = 0x00;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    vantaq_evidence_ring_buffer_destroy(buffer);

    s_assert_int_equal(
        s, write_bytes_at(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET, &bad, 1U), 0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER);
    s_assert_null(s, buffer);
}

static void test_version_mismatch_returns_invalid_header(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;
    uint8_t ver[VANTAQ_EVIDENCE_RING_U32_SIZE];

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    vantaq_evidence_ring_buffer_destroy(buffer);

    vantaq_evidence_ring_le32_encode(ver, VANTAQ_EVIDENCE_RING_FORMAT_VERSION + 1U);
    s_assert_int_equal(
        s,
        write_bytes_at(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_VERSION_OFFSET, ver, sizeof(ver)),
        0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER);
    s_assert_null(s, buffer);
}

static void test_config_mismatch_returns_explicit_error(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;
    struct vantaq_ring_buffer_config *mismatch = NULL;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    vantaq_evidence_ring_buffer_destroy(buffer);

    s_assert_int_equal(s, vantaq_ring_buffer_config_create(s->ring_path, 9U, 256U, true, &mismatch),
                       RING_BUFFER_OK);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(mismatch, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_CONFIG_MISMATCH);
    s_assert_null(s, buffer);

    vantaq_ring_buffer_config_destroy(mismatch);
}

static void test_corrupt_layout_sizes_returns_invalid_header(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;
    uint8_t bad[VANTAQ_EVIDENCE_RING_U32_SIZE];

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    vantaq_evidence_ring_buffer_destroy(buffer);

    vantaq_evidence_ring_le32_encode(bad, 0U);
    s_assert_int_equal(s,
                       write_bytes_at(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_SLOT_SIZE_OFFSET,
                                      bad, sizeof(bad)),
                       0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER);
    s_assert_null(s, buffer);
}

static void test_out_of_range_write_slot_returns_invalid_header(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;
    uint8_t write_slot[VANTAQ_EVIDENCE_RING_U32_SIZE];

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    vantaq_evidence_ring_buffer_destroy(buffer);

    vantaq_evidence_ring_le32_encode(write_slot, 8U);
    s_assert_int_equal(s,
                       write_bytes_at(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET,
                                      write_slot, sizeof(write_slot)),
                       0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER);
    s_assert_null(s, buffer);
}

static void test_wrong_file_size_returns_invalid_header(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    vantaq_evidence_ring_buffer_destroy(buffer);

    s_assert_int_equal(s, truncate(s->ring_path, 64), 0);

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER);
    s_assert_null(s, buffer);
}

static void test_invalid_existing_file_not_reinitialized(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;
    uint8_t before[VANTAQ_EVIDENCE_RING_HEADER_SIZE];
    uint8_t after[VANTAQ_EVIDENCE_RING_HEADER_SIZE];
    uint8_t bad = 0xEE;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    vantaq_evidence_ring_buffer_destroy(buffer);

    s_assert_int_equal(
        s, write_bytes_at(s->ring_path, VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET, &bad, 1U), 0);

    s_assert_int_equal(s, read_file_bytes(s->ring_path, before, sizeof(before)), 0);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER);
    s_assert_null(s, buffer);
    s_assert_int_equal(s, read_file_bytes(s->ring_path, after, sizeof(after)), 0);
    s_assert_true(s, memcmp(before, after, sizeof(before)) == 0);
}

static void test_invalid_arguments_rejected(void **state) {
    struct RingBufferOpenInitSuite *s          = *state;
    struct vantaq_evidence_ring_buffer *buffer = NULL;

    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(NULL, &buffer),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(s->config, NULL),
                       VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_create_missing_file_and_header_valid, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_open_existing_valid_file_success, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_magic_returns_invalid_header, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_version_mismatch_returns_invalid_header, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_config_mismatch_returns_explicit_error, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_corrupt_layout_sizes_returns_invalid_header,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_out_of_range_write_slot_returns_invalid_header,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_wrong_file_size_returns_invalid_header, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_existing_file_not_reinitialized, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_arguments_rejected, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("ring_buffer_open_init_suite", tests, NULL, NULL);
}
