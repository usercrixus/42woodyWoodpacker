#include "woody.h"

void *woody_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d;
    const unsigned char *s;

    d = (unsigned char *)dst;
    s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return (dst);
}

void woody_bzero(void *ptr, size_t n)
{
    unsigned char *p;

    p = (unsigned char *)ptr;
    while (n--)
        *p++ = 0;
}

int woody_memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa;
    const unsigned char *pb;

    pa = (const unsigned char *)a;
    pb = (const unsigned char *)b;
    while (n--)
    {
        if (*pa != *pb)
            return ((int)(*pa) - (int)(*pb));
        ++pa;
        ++pb;
    }
    return (0);
}

uint64_t align_up(uint64_t value, uint64_t alignment)
{
    uint64_t mask;

    if (alignment == 0)
        return (value);
    mask = alignment - 1;
    return ((value + mask) & ~mask);
}

uint64_t align_down(uint64_t value, uint64_t alignment)
{
    uint64_t mask;

    if (alignment == 0)
        return (value);
    mask = alignment - 1;
    return (value & ~mask);
}
