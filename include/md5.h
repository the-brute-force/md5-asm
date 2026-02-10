#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint8_t bytesInUse;
    uint64_t totalBits;
    union {
        uint8_t bytes[64];
        uint32_t words[16];
    } buffer __attribute__((aligned(4)));
} MD5_CTX;

void MD5_Init(MD5_CTX* const context);
void MD5_Update(MD5_CTX* const context, const void* const data, size_t length);
void MD5_Final(uint8_t digest[16], MD5_CTX* const context);

#ifdef __cplusplus
}
#endif
