#ifndef WOODY_H
#define WOODY_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#define WOODY_OUTPUT "woody"
#define PAGE_SIZE 0x1000u

struct stub_metadata
{
    uint64_t self_entry_rva;
    uint64_t original_entry_rva;
    uint64_t encrypted_rva;
    uint64_t encrypted_size;
    uint64_t page_rva;
    uint64_t page_size;
    uint32_t original_prot;
    uint32_t reserved;
    uint64_t nonce;
    uint32_t key[4];
};

int pack_elf64(const char *path);

uint64_t align_up(uint64_t value, uint64_t alignment);
uint64_t align_down(uint64_t value, uint64_t alignment);

void xtea_ctr_transform(uint8_t *data, size_t len, const uint32_t key[4], uint64_t nonce);

const unsigned char *woody_stub_data(void);
size_t woody_stub_size(void);
size_t woody_stub_meta_offset(void);
size_t woody_stub_entry_offset(void);

#endif
