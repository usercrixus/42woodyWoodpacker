#define _GNU_SOURCE
#include "xtea_ctr.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/random.h>

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
