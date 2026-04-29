// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/evidence/evidence.h"
#include "domain/evidence/evidence_canonical.h"
#include "infrastructure/crypto/evidence_signer.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_JSON_FILE_BYTES (64U * 1024U)
#define SUPPORTED_SIGNATURE_ALG "ECDSA-P256-SHA256"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long len = ftell(f);
    if (len < 0 || (unsigned long)len > MAX_JSON_FILE_BYTES) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)len + 1U);
    if (buf) {
        size_t read_n = fread(buf, 1, (size_t)len, f);
        if (read_n != (size_t)len) {
            free(buf);
            fclose(f);
            return NULL;
        }
        buf[len] = '\0';
    }
    fclose(f);
    return buf;
}

static const char *skip_ws(const char *p) {
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static const char *find_string_end(const char *start) {
    const char *p = start;
    bool escaped  = false;
    while (*p) {
        if (escaped) {
            escaped = false;
        } else if (*p == '\\') {
            escaped = true;
        } else if (*p == '"') {
            return p;
        }
        p++;
    }
    return NULL;
}

static const char *find_object_end(const char *start) {
    const char *p = start;
    int depth     = 0;
    bool in_str   = false;
    bool escaped  = false;
    while (*p) {
        char c = *p;
        if (in_str) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_str = false;
            }
        } else {
            if (c == '"') {
                in_str = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return p + 1;
                }
            }
        }
        p++;
    }
    return NULL;
}

static char *extract_raw_value(const char *json, const char *key) {
    size_t key_len   = strlen(key);
    char *quoted_key = malloc(key_len + 3);
    if (!quoted_key) {
        return NULL;
    }
    snprintf(quoted_key, key_len + 3, "\"%s\"", key);

    const char *p = strstr(json, quoted_key);
    free(quoted_key);
    if (!p)
        return NULL;
    p += key_len + 2;
    p = skip_ws(p);

    if (*p != ':') {
        return NULL;
    }
    p++;
    p = skip_ws(p);

    const char *start = p;
    const char *end   = NULL;
    if (*p == '\"') {
        start++;
        end = find_string_end(start);
        if (end) {
            end++; // include closing quote boundary for slicing logic below
        }
    } else if (*p == '{') {
        end = find_object_end(start);
    } else {
        end = p;
        while (*end && !isspace((unsigned char)*end) && *end != ',' && *end != '}' && *end != ']')
            end++;
    }

    if (!end)
        return NULL;
    size_t len = (size_t)(end - start);
    if (*p == '"' && len > 0) {
        len--; // remove trailing quote for string values
    }
    char *val = malloc(len + 1);
    if (val) {
        memcpy(val, start, len);
        val[len] = '\0';
    }
    return val;
}

static int verify_evidence_payload(const char *json, EVP_PKEY *pkey) {
    int result                       = -1;
    char *ev_id                      = NULL;
    char *dev_id                     = NULL;
    char *ver_id                     = NULL;
    char *ch_id                      = NULL;
    char *nonce                      = NULL;
    char *purpose                    = NULL;
    char *timestamp_str              = NULL;
    char *claims                     = NULL;
    char *sig_alg                    = NULL;
    char *sig_b64                    = NULL;
    struct vantaq_evidence *evidence = NULL;
    char *canonical_buf              = NULL;
    size_t canonical_len             = 0;
    BIO *b64_bio                     = NULL;
    BIO *mem_bio                     = NULL;
    unsigned char *sig               = NULL;
    EVP_MD_CTX *ctx                  = NULL;

    ev_id         = extract_raw_value(json, "evidence_id");
    dev_id        = extract_raw_value(json, "device_id");
    ver_id        = extract_raw_value(json, "verifier_id");
    ch_id         = extract_raw_value(json, "challenge_id");
    nonce         = extract_raw_value(json, "nonce");
    purpose       = extract_raw_value(json, "purpose");
    timestamp_str = extract_raw_value(json, "timestamp");
    claims        = extract_raw_value(json, "claims");
    sig_alg       = extract_raw_value(json, "signature_algorithm");
    sig_b64       = extract_raw_value(json, "signature");

    if (!ev_id || !dev_id || !ver_id || !ch_id || !nonce || !purpose || !timestamp_str || !claims ||
        !sig_alg || !sig_b64) {
        fprintf(stderr, "Error: Missing required fields in evidence JSON\n");
        goto cleanup;
    }

    if (strcmp(sig_alg, SUPPORTED_SIGNATURE_ALG) != 0) {
        fprintf(stderr, "Error: Unsupported signature_algorithm: %s\n", sig_alg);
        goto cleanup;
    }

    errno           = 0;
    char *endptr    = NULL;
    long long ts_ll = strtoll(timestamp_str, &endptr, 10);
    if (errno != 0 || endptr == timestamp_str || (endptr && *skip_ws(endptr) != '\0') ||
        ts_ll <= 0) {
        fprintf(stderr, "Error: Invalid timestamp value\n");
        goto cleanup;
    }

    vantaq_evidence_err_t err =
        vantaq_evidence_create(ev_id, dev_id, ver_id, ch_id, nonce, purpose, (int64_t)ts_ll, claims,
                               sig_alg, sig_b64, &evidence);

    if (err != VANTAQ_EVIDENCE_OK) {
        fprintf(stderr, "Error: Failed to create evidence object (%d)\n", err);
        goto cleanup;
    }

    err = vantaq_evidence_serialize_canonical(evidence, &canonical_buf, &canonical_len);
    if (err != VANTAQ_EVIDENCE_OK) {
        fprintf(stderr, "Error: Failed to serialize canonical payload\n");
        goto cleanup;
    }

    // Verify Signature
    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new_mem_buf(sig_b64, -1);
    if (!b64_bio || !mem_bio)
        goto cleanup;
    BIO_push(b64_bio, mem_bio);
    mem_bio = NULL;
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    size_t sig_buf_len = strlen(sig_b64);
    sig                = malloc(sig_buf_len);
    if (!sig)
        goto cleanup;
    int sig_len = BIO_read(b64_bio, sig, (int)sig_buf_len);
    if (sig_len <= 0)
        goto cleanup;

    ERR_clear_error();
    ctx = EVP_MD_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) > 0) {
        if (EVP_DigestVerifyUpdate(ctx, canonical_buf, canonical_len) > 0) {
            if (EVP_DigestVerifyFinal(ctx, sig, (size_t)sig_len) > 0) {
                result = 0; // Success
            } else {
                result = 1; // Invalid signature
            }
        }
    }

cleanup:
    if (ctx)
        EVP_MD_CTX_free(ctx);
    if (b64_bio)
        BIO_free_all(b64_bio);
    else if (mem_bio)
        BIO_free(mem_bio);
    if (canonical_buf)
        vantaq_evidence_canonical_destroy(canonical_buf);
    if (evidence)
        vantaq_evidence_destroy(evidence);
    free(ev_id);
    free(dev_id);
    free(ver_id);
    free(ch_id);
    free(nonce);
    free(purpose);
    free(timestamp_str);
    free(claims);
    free(sig_alg);
    free(sig_b64);
    free(sig);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <evidence.json> <public_key.pem>\n", argv[0]);
        return 1;
    }

    char *json = read_file(argv[1]);
    if (!json) {
        fprintf(stderr, "Error: Failed to read JSON file\n");
        return 1;
    }

    FILE *key_f = fopen(argv[2], "rb");
    if (!key_f) {
        perror("Failed to open key file");
        free(json);
        return 1;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(key_f, NULL, NULL, NULL);
    if (!pkey) {
        fseek(key_f, 0, SEEK_SET);
        X509 *x509 = PEM_read_X509(key_f, NULL, NULL, NULL);
        if (x509) {
            pkey = X509_get_pubkey(x509);
            X509_free(x509);
        }
    }
    fclose(key_f);

    if (!pkey) {
        fprintf(stderr, "Error: Failed to load public key\n");
        ERR_print_errors_fp(stderr);
        free(json);
        return 1;
    }

    int res = verify_evidence_payload(json, pkey);
    EVP_PKEY_free(pkey);
    free(json);

    if (res == 0) {
        printf("Signature verification: SUCCESS\n");
        return 0;
    } else {
        fprintf(stderr, "Signature verification: FAILURE\n");
        return 1;
    }
}
