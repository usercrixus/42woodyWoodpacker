#include "xtea_ctr.h"
#include <string.h>

#define STUB_CODE __attribute__((section(".text.woody_stub"), used))
#define NO_STACK __attribute__((no_stack_protector))

STUB_CODE NO_STACK void xtea_ctr_decrypt(uint8_t *cursor, uint64_t remaining, const uint8_t algo_data[ALGO_DATA_SIZE])
{
    const struct xtea_ctr_data *ctx;
    const uint32_t *key;
    uint64_t counter;

    ctx = (const struct xtea_ctr_data *)algo_data;
    key = ctx->key;
    counter = ctx->nonce;
    while (remaining)
    {
        uint32_t v0 = (uint32_t)counter;
        uint32_t v1 = (uint32_t)(counter >> 32);
        uint32_t sum = 0;
        for (int i = 0; i < 32; ++i)
        {
            sum += 0x9E3779B9u;
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        }
        const uint64_t stream = ((uint64_t)v1 << 32) | v0;
        const size_t chunk = remaining >= 8 ? 8 : (size_t)remaining;

        if (chunk == 8)
        {
            uint64_t block;
            memcpy(&block, cursor, sizeof(block));
            block ^= stream;
            memcpy(cursor, &block, sizeof(block));
        }
        else
        {
            uint64_t tmp = stream;
            for (size_t i = 0; i < chunk; ++i)
            {
                cursor[i] ^= (uint8_t)(tmp & 0xFFu);
                tmp >>= 8;
            }
        }
        cursor += chunk;
        remaining -= chunk;
        ++counter;
    }
}
