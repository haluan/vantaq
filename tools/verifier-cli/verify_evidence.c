// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/evidence/evidence.h"
#include "domain/evidence/evidence_canonical.h"
#include "infrastructure/crypto/evidence_signer.h"
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (buf) {
        fread(buf, 1, len, f);
        buf[len] = '\0';
    }
    fclose(f);
    return buf;
}

static char *extract_raw_value(const char *json, const char *key) {
    char search_key[128];
    snprintf(search_key, sizeof(search_key), "\"%s\":", key);
    const char *p = strstr(json, search_key);
    if (!p) return NULL;
    p += strlen(search_key);
    while (*p && isspace((unsigned char)*p)) p++;

    const char *start = p;
    const char *end = NULL;

    if (*p == '\"') {
        start++;
        end = strchr(start, '\"');
    } else if (*p == '{') {
        int depth = 1;
        const char *walker = start + 1;
        while (*walker && depth > 0) {
            if (*walker == '{') depth++;
            else if (*walker == '}') depth--;
            walker++;
        }
        if (depth == 0) end = walker;
    } else {
        end = p;
        while (*end && !isspace((unsigned char)*end) && *end != ',' && *end != '}') end++;
    }

    if (!end) return NULL;
    size_t len = (size_t)(end - start);
    char *val = malloc(len + 1);
    if (val) {
        memcpy(val, start, len);
        val[len] = '\0';
    }
    return val;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <evidence.json> <public_key.pem>\n", argv[0]);
        return 1;
    }

    char *json = read_file(argv[1]);
    if (!json) {
        perror("Failed to read JSON file");
        return 1;
    }

    char *ev_id = extract_raw_value(json, "evidence_id");
    char *dev_id = extract_raw_value(json, "device_id");
    char *ver_id = extract_raw_value(json, "verifier_id");
    char *ch_id = extract_raw_value(json, "challenge_id");
    char *nonce = extract_raw_value(json, "nonce");
    char *purpose = extract_raw_value(json, "purpose");
    char *timestamp_str = extract_raw_value(json, "timestamp");
    char *claims = extract_raw_value(json, "claims");
    char *sig_alg = extract_raw_value(json, "signature_algorithm");
    char *sig_b64 = extract_raw_value(json, "signature");

    if (!ev_id) fprintf(stderr, "Error: Missing evidence_id\n");
    if (!dev_id) fprintf(stderr, "Error: Missing device_id\n");
    if (!ver_id) fprintf(stderr, "Error: Missing verifier_id\n");
    if (!ch_id) fprintf(stderr, "Error: Missing challenge_id\n");
    if (!nonce) fprintf(stderr, "Error: Missing nonce\n");
    if (!purpose) fprintf(stderr, "Error: Missing purpose\n");
    if (!timestamp_str) fprintf(stderr, "Error: Missing timestamp\n");
    if (!claims) fprintf(stderr, "Error: Missing claims\n");
    if (!sig_alg) fprintf(stderr, "Error: Missing signature_algorithm\n");
    if (!sig_b64) fprintf(stderr, "Error: Missing signature\n");

    if (!ev_id || !dev_id || !ver_id || !ch_id || !nonce || !purpose || !timestamp_str || !claims || !sig_alg || !sig_b64) {
        return 1;
    }

    int64_t timestamp = atoll(timestamp_str);

    struct vantaq_evidence *evidence = NULL;
    vantaq_evidence_err_t err = vantaq_evidence_create(
        ev_id, dev_id, ver_id, ch_id, nonce, purpose,
        timestamp, claims, sig_alg, "pending-signature", &evidence);

    if (err != VANTAQ_EVIDENCE_OK) {
        fprintf(stderr, "Error: Failed to create evidence object (%d)\n", err);
        return 1;
    }

    char *canonical_buf = NULL;
    size_t canonical_len = 0;
    err = vantaq_evidence_serialize_canonical(evidence, &canonical_buf, &canonical_len);
    if (err != VANTAQ_EVIDENCE_OK) {
        fprintf(stderr, "Error: Failed to serialize canonical payload\n");
        return 1;
    }

    // Verify Signature
    // 1. Decode Base64
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(sig_b64, -1);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    size_t sig_buf_len = strlen(sig_b64);
    unsigned char *sig = malloc(sig_buf_len);
    int sig_len = BIO_read(b64_bio, sig, (int)sig_buf_len);
    BIO_free_all(b64_bio);

    if (sig_len <= 0) {
        fprintf(stderr, "Error: Failed to decode base64 signature\n");
        return 1;
    }

    // 2. Load Public Key
    FILE *key_file = fopen(argv[2], "rb");
    if (!key_file) {
        perror("Failed to open public key file");
        return 1;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    if (!pkey) {
        // Try reading as certificate
        fseek(key_file, 0, SEEK_SET);
        X509 *x509 = PEM_read_X509(key_file, NULL, NULL, NULL);
        if (x509) {
            pkey = X509_get_pubkey(x509);
            X509_free(x509);
        }
    }
    fclose(key_file);

    if (!pkey) {
        fprintf(stderr, "Error: Failed to load public key from %s\n", argv[2]);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // 3. Verify
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) > 0) {
        if (EVP_DigestVerifyUpdate(ctx, canonical_buf, canonical_len) > 0) {
            if (EVP_DigestVerifyFinal(ctx, sig, (size_t)sig_len) > 0) {
                result = 1;
            }
        }
    }

    if (result) {
        printf("Signature verification: SUCCESS\n");
    } else {
        fprintf(stderr, "Signature verification: FAILURE\n");
        ERR_print_errors_fp(stderr);
    }

    // Cleanup
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    vantaq_evidence_canonical_free(canonical_buf);
    vantaq_evidence_destroy(evidence);
    free(json);
    free(ev_id); free(dev_id); free(ver_id); free(ch_id);
    free(nonce); free(purpose); free(timestamp_str);
    free(claims); free(sig_alg); free(sig_b64);
    free(sig);

    return result ? 0 : 1;
}
