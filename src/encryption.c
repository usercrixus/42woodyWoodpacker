#define _GNU_SOURCE
#include "woody.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/random.h>

void    xtea_ctr_transform(uint8_t *data, size_t len,
            const uint32_t key[4], uint64_t nonce)
{
    size_t  offset;

    offset = 0;
    while (offset < len)
    {
        uint32_t    v0 = (uint32_t)(nonce & 0xffffffffu);
        uint32_t    v1 = (uint32_t)(nonce >> 32);
        uint32_t    sum = 0;
        const uint32_t  delta = 0x9E3779B9u;
        size_t          chunk;

        for (unsigned int i = 0; i < 32; ++i)
        {
            sum += delta;
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1)
                ^ (sum + key[sum & 3]);
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0)
                ^ (sum + key[(sum >> 11) & 3]);
        }
        uint64_t    keystream = ((uint64_t)v1 << 32) | v0;
        chunk = len - offset;
        if (chunk > 8)
            chunk = 8;
        for (size_t i = 0; i < chunk; ++i)
        {
            data[offset + i] ^= (uint8_t)(keystream & 0xffu);
            keystream >>= 8;
        }
        nonce++;
        offset += chunk;
    }
}
