#ifndef _PHASE4_PROTOCOL_H
#define _PHASE4_PROTOCOL_H

#include <stdint.h>

#define SHA256_MAC_LEN 32

struct attest_record {
    uint64_t epoch_id;
    uint64_t path_id;
    unsigned char token[SHA256_MAC_LEN];
} __attribute__((packed));

#endif
