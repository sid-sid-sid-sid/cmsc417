

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "hash.h"

struct checksum_ctx {
    EVP_MD_CTX *mdctx;
    uint8_t *salt;
    size_t salt_len;
};

static int start_digest_with_salt(struct checksum_ctx *csm) {
    int ok;

    ok = EVP_DigestInit_ex(csm->mdctx, EVP_sha256(), NULL);
    if (ok != 1) {
        return -1;
    }

    if (csm->salt_len > 0) {
        ok = EVP_DigestUpdate(csm->mdctx, csm->salt, csm->salt_len);
        if (ok != 1) {
            return -1;
        }
    }

    return 0;
}

struct checksum_ctx *checksum_create(const uint8_t *salt, size_t len) {
    struct checksum_ctx *csm;

    csm = malloc(sizeof(struct checksum_ctx));
    if (csm == NULL) {
        return NULL;
    }
    csm->mdctx = NULL;
    csm->salt = NULL;
    csm->salt_len = 0;

    csm->mdctx = EVP_MD_CTX_new();
    if (csm->mdctx == NULL) {
        free(csm);
        return NULL;
    }

    if (len > 0) {
        csm->salt = malloc(len);
        if (csm->salt == NULL) {
            EVP_MD_CTX_free(csm->mdctx);
            free(csm);
            return NULL;
        }
        memcpy(csm->salt, salt, len);
        csm->salt_len = len;
    }

    if (start_digest_with_salt(csm) != 0) {
        EVP_MD_CTX_free(csm->mdctx);
        free(csm->salt);
        free(csm);
        return NULL;
    }

    return csm;
}

int checksum_update(struct checksum_ctx *csm, const uint8_t *payload) {
    int ok;

    ok = EVP_DigestUpdate(csm->mdctx, payload, UPDATE_PAYLOAD_SIZE);
    if (ok != 1) {
        return -1;
    }
    return 0;
}

int checksum_finish(struct checksum_ctx *csm, const uint8_t *payload, size_t len, uint8_t *out) {
    int ok;

    if (len > 0) {
        ok = EVP_DigestUpdate(csm->mdctx, payload, len);
        if (ok != 1) {
            return -1;
        }
    }

    ok = EVP_DigestFinal_ex(csm->mdctx, out, NULL);
    if (ok != 1) {
        return -1;
    }
    return 0;
}

int checksum_reset(struct checksum_ctx *csm) {
    return start_digest_with_salt(csm);
}

int checksum_destroy(struct checksum_ctx *csm) {
    if (csm == NULL) {
        return 0;
    }
    EVP_MD_CTX_free(csm->mdctx);
    free(csm->salt);
    free(csm);
    return 0;
}