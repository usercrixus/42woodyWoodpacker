#include "woody.h"
#include <stdio.h>
#include <string.h>

static int is_valid_algo(const char *algo)
{
    return (strcmp(algo, "xtea_ctr") == 0);
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <64-bit ELF> <Algo>\n", argv[0]);
        fprintf(stderr, "Available algo: xtea_ctr\n");
        return (1);
    }
    if (!is_valid_algo(argv[2]))
        return (fprintf(stderr, "woody_woodpacker: unknown algorithm '%s'\n", argv[2]), 1);
    return (pack_elf64(argv[1], argv[2]) != 0);
}
