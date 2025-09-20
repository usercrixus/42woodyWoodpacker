#ifndef WOODY_H
#define WOODY_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#define WOODY_OUTPUT "woody"
#define PAGE_SIZE 0x1000u

struct stub_metadata
{
    uint64_t self_entry_rva;     // RVA (relative virtual address) of the stub’s own entry point (woody_stub_start).
    uint64_t original_entry_rva; // RVA of the program’s real entry point (before packing).
    uint64_t encrypted_rva;      // RVA of the encrypted payload in memory.
    uint64_t encrypted_size;     // Size in bytes of the encrypted region.
    uint32_t original_prot;      // Original memory protection flags of the page (PROT_READ, PROT_EXEC, etc.).
    uint32_t reserved;           // Padding/alignment slot.
    uint64_t nonce;              // Starting counter value for the stream cipher.
    uint32_t key[4];             // 128-bit encryption key.
};

int pack_elf64(const char *path);

uint64_t align_up(uint64_t value, uint64_t alignment);
uint64_t align_down(uint64_t value, uint64_t alignment);

void xtea_ctr_transform(uint8_t *data, size_t len, const uint32_t key[4], uint64_t nonce);

const unsigned char *woody_stub_data(void);
size_t woody_stub_size(void);
size_t woody_stub_meta_offset(void);

#endif
