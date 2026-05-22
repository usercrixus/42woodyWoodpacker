#define _GNU_SOURCE
#include "woody.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/random.h>
#include <string.h>

#define STUB_CODE __attribute__((section(".text.woody_stub"), used))
#define NO_STACK __attribute__((no_stack_protector))

struct xtea_ctr_data
{
    uint64_t nonce;
    uint32_t key[4];
};

static void xtea_ctr_transform(uint8_t *data, size_t len, const uint32_t key[4], uint64_t nonce)
{
    size_t offset;

    offset = 0;
    while (offset < len)
    {
        uint32_t v0 = (uint32_t)nonce;
        uint32_t v1 = (uint32_t)(nonce >> 32);
        uint32_t sum = 0;
        const uint32_t delta = 0x9E3779B9u;
        size_t chunk;

        for (unsigned int i = 0; i < 32; ++i)
        {
            sum += delta;
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        }
        uint64_t keystream = ((uint64_t)v1 << 32) | v0;
        chunk = len - offset;
        if (chunk > 8)
            chunk = 8;
        for (size_t i = 0; i < chunk; ++i)
        {
            data[offset + i] ^= (uint8_t)keystream;
            keystream >>= 8;
        }
        nonce++;
        offset += chunk;
    }
}

int xtea_ctr_encrypt(uint8_t *data, size_t len, uint8_t algo_data[ALGO_DATA_SIZE])
{
    struct xtea_ctr_data *ctx;

    ctx = (struct xtea_ctr_data *)algo_data;
    if (getentropy(ctx, sizeof(*ctx)) < 0)
        return (-1);
    if (ctx->nonce == 0)
        ctx->nonce = 1;
    xtea_ctr_transform(data, len, ctx->key, ctx->nonce);
    printf("key %08x-%08x-%08x-%08x nonce %016llx\n",
           ctx->key[0], ctx->key[1], ctx->key[2], ctx->key[3],
           (unsigned long long)ctx->nonce);
    return (0);
}

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
