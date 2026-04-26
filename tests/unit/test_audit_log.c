// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/audit_log.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

static int make_temp_path(char *out, size_t out_size) {
    char template[] = "/tmp/vantaq_audit_XXXXXX.log";
    int fd          = mkstemps(template, 4);

    if (fd < 0) {
        return -1;
    }

    close(fd);
    if (strlen(template) >= out_size) {
        unlink(template);
        return -1;
    }

    strcpy(out, template);
    return 0;
}

static int read_file_text(const char *path, char *out, size_t out_size) {
    FILE *f;
    size_t n;

    if (path == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }

    n      = fread(out, 1, out_size - 1, f);
    out[n] = '\0';
    fclose(f);
    return 0;
}

static void test_serialize_event_contains_required_fields(void **state) {
    (void)state;
    struct vantaq_audit_event event = {0};
    char line[1024];
    size_t len;

    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = 1704067200; // 2024-01-01T00:00:00Z
    event.source_ip              = "10.60.10.20";
    event.method                 = "GET";
    event.path                   = "/v1/health";
    event.result                 = "DENY";
    event.reason                 = "SUBNET_NOT_ALLOWED";
    event.request_id             = "req-000001";

    assert_int_equal(vantaq_audit_log_serialize_event(&event, line, sizeof(line)),
                     VANTAQ_AUDIT_LOG_STATUS_OK);
    assert_non_null(strstr(line, "\"time\":\"2024-01-01T00:00:00Z\""));
    assert_non_null(strstr(line, "\"source_ip\":\"10.60.10.20\""));
    assert_non_null(strstr(line, "\"method\":\"GET\""));
    assert_non_null(strstr(line, "\"path\":\"/v1/health\""));
    assert_non_null(strstr(line, "\"result\":\"DENY\""));
    assert_non_null(strstr(line, "\"reason\":\"SUBNET_NOT_ALLOWED\""));
    assert_non_null(strstr(line, "\"request_id\":\"req-000001\""));

    len = strlen(line);
    assert_true(len > 0);
    assert_int_equal(line[len - 1], '\n');
}

static void test_append_writes_single_jsonl_record(void **state) {
    (void)state;
    char path[256];
    char text[2048];
    struct vantaq_audit_log *log = NULL;
    struct vantaq_audit_event event;

    assert_int_equal(make_temp_path(path, sizeof(path)), 0);
    assert_int_equal(vantaq_audit_log_create(path, 4096, &log), VANTAQ_AUDIT_LOG_STATUS_OK);
    assert_non_null(log);

    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = 1704067200;
    event.source_ip              = "127.0.0.1";
    event.method                 = "GET";
    event.path                   = "/v1/device/identity";
    event.result                 = "DENY";
    event.reason                 = "SUBNET_NOT_ALLOWED";
    event.request_id             = "req-123456";

    assert_int_equal(vantaq_audit_log_append(log, &event), VANTAQ_AUDIT_LOG_STATUS_OK);
    assert_int_equal(read_file_text(path, text, sizeof(text)), 0);
    assert_non_null(strstr(text, "\"source_ip\":\"127.0.0.1\""));
    assert_non_null(strstr(text, "\"path\":\"/v1/device/identity\""));
    assert_non_null(strstr(text, "\"reason\":\"SUBNET_NOT_ALLOWED\""));
    assert_non_null(strstr(text, "\"request_id\":\"req-123456\""));
    assert_non_null(strstr(text, "\"result\":\"DENY\""));

    vantaq_audit_log_destroy(log);
    unlink(path);
}

static void test_bounded_append_truncates_old_records(void **state) {
    (void)state;
    char path[256];
    char text[2048];
    struct stat st;
    struct vantaq_audit_log *log = NULL;
    struct vantaq_audit_event first;
    struct vantaq_audit_event second;
    size_t max_bytes = 180;

    assert_int_equal(make_temp_path(path, sizeof(path)), 0);
    assert_int_equal(vantaq_audit_log_create(path, max_bytes, &log), VANTAQ_AUDIT_LOG_STATUS_OK);
    assert_non_null(log);

    first.cbSize                 = sizeof(first);
    first.time_utc_epoch_seconds = 1704067200;
    first.source_ip              = "127.0.0.1";
    first.method                 = "GET";
    first.path                   = "/first";
    first.result                 = "DENY";
    first.reason                 = "SUBNET_NOT_ALLOWED";
    first.request_id             = "req-first";

    second.cbSize                 = sizeof(second);
    second.time_utc_epoch_seconds = 1704067201;
    second.source_ip              = "127.0.0.1";
    second.method                 = "GET";
    second.path                   = "/second";
    second.result                 = "DENY";
    second.reason                 = "SUBNET_NOT_ALLOWED";
    second.request_id             = "req-second";

    assert_int_equal(vantaq_audit_log_append(log, &first), VANTAQ_AUDIT_LOG_STATUS_OK);
    assert_int_equal(vantaq_audit_log_append(log, &second), VANTAQ_AUDIT_LOG_STATUS_OK);
    assert_int_equal(read_file_text(path, text, sizeof(text)), 0);
    assert_non_null(strstr(text, "\"path\":\"/second\""));
    assert_null(strstr(text, "\"path\":\"/first\""));
    assert_int_equal(stat(path, &st), 0);
    assert_true((size_t)st.st_size <= max_bytes);

    vantaq_audit_log_destroy(log);
    unlink(path);
}

static void test_append_invalid_path_returns_io_error(void **state) {
    (void)state;
    struct vantaq_audit_log *log = NULL;
    struct vantaq_audit_event event;
    char invalid_dir[256];
    char invalid_path[320];

    assert_true(snprintf(invalid_dir, sizeof(invalid_dir), "/tmp/vantaq_audit_missing_%ld",
                         (long)getpid()) > 0);
    (void)rmdir(invalid_dir);
    assert_true(snprintf(invalid_path, sizeof(invalid_path), "%s/audit.log", invalid_dir) > 0);

    assert_int_equal(vantaq_audit_log_create(invalid_path, 4096, &log), VANTAQ_AUDIT_LOG_STATUS_OK);
    assert_non_null(log);

    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = 1704067200;
    event.source_ip              = "127.0.0.1";
    event.method                 = "GET";
    event.path                   = "/v1/health";
    event.result                 = "DENY";
    event.reason                 = "SUBNET_NOT_ALLOWED";
    event.request_id             = "req-io-fail";

    assert_int_equal(vantaq_audit_log_append(log, &event), VANTAQ_AUDIT_LOG_STATUS_IO_ERROR);
    assert_non_null(vantaq_audit_log_last_error(log));

    vantaq_audit_log_destroy(log);
}

static void test_append_invalid_timestamp_returns_error(void **state) {
    (void)state;
    char path[256];
    struct vantaq_audit_log *log = NULL;
    struct vantaq_audit_event event;

    assert_int_equal(make_temp_path(path, sizeof(path)), 0);
    assert_int_equal(vantaq_audit_log_create(path, 4096, &log), VANTAQ_AUDIT_LOG_STATUS_OK);

    // Case 1: Zero timestamp (uninitialized)
    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = 0;
    event.source_ip              = "127.0.0.1";
    event.method                 = "GET";
    event.path                   = "/";
    event.result                 = "DENY";
    event.reason                 = "TEST";
    event.request_id             = "req-timestamp-fail";
    assert_int_equal(vantaq_audit_log_append(log, &event),
                     VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT);

    // Case 2: Far-future timestamp
    event.time_utc_epoch_seconds = time(NULL) + 1000;
    assert_int_equal(vantaq_audit_log_append(log, &event),
                     VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT);

    vantaq_audit_log_destroy(log);
    unlink(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_serialize_event_contains_required_fields),
        cmocka_unit_test(test_append_writes_single_jsonl_record),
        cmocka_unit_test(test_bounded_append_truncates_old_records),
        cmocka_unit_test(test_append_invalid_path_returns_io_error),
        cmocka_unit_test(test_append_invalid_timestamp_returns_error),
    };

    return cmocka_run_group_tests_name("unit_audit_log", tests, NULL, NULL);
}
