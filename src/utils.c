#include "woody.h"

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
