#include "woody.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <64-bit ELF>\n", argv[0]);
        return (1);
    }
    return (pack_elf64(argv[1]) != 0);
}
