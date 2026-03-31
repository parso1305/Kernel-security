#ifndef _PHASE4_CRYPTO_H
#define _PHASE4_CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

static inline void compute_token(const char *key, size_t key_len,
                                 uint64_t epoch_id, uint64_t path_id,
                                 const unsigned char *prev_token,
                                 unsigned char *out_token) {
    unsigned char msg[16 + 32];
    memcpy(msg, &epoch_id, 8);
    memcpy(msg + 8, &path_id, 8);
    memcpy(msg + 16, prev_token, 32);

    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, key_len, msg, sizeof(msg), out_token, &out_len);
}

#endif
