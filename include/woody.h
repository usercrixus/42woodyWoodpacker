#pragma once

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#define WOODY_OUTPUT "woody"
#define PAGE_SIZE 0x1000u

typedef enum e_algo
{
    ALGO_INVALID = 0,
    XTEA_CTR = 1
} e_algo;

/**
 * Metadata structure that the stub will use to locate and decrypt the encrypted payload at runtime.
 * This structure will be embedded in the stub code itself, and the stub will read it to know where the encrypted payload is in memory,
 * how big it is, what the original entry point was, and how to decrypt it.
 */
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
    e_algo algo_id;              // the algo id with which the program was encrypted
};
/**
 * Pack a 64-bit ELF binary at the given path, producing a new file named "woody" in the current directory.
 * The function returns 0 on success, or a non-zero value on failure.
 */
int pack_elf64(const char *path, const char *algo);
/**
 * Align value up to alignment, alignment must be a power of 2
 * Alignment is the number of bytes that the value must be a multiple of
 * Example: 
 * align_up(0x1234, 0x100) = 0x1300
 * align_up(0x1234, 0) = 0x1234
 */
uint64_t align_up(uint64_t value, uint64_t alignment);
/**
 * Align value down to alignment, alignment must be a power of 2
 * Alignment is the number of bytes that the value must be a multiple of
 * Example: 
 * align_down(0x1234, 0x100) = 0x1200
 * align_down(0x1234, 0) = 0x1234
 */ uint64_t align_down(uint64_t value, uint64_t alignment);
/**
 * Encrypt or decrypt data in-place using XTEA in CTR mode. The same function can be used for both encryption and decryption since CTR mode is symmetric.
 * - data: pointer to the data to be encrypted/decrypted
 * - len: length of the data in bytes
 * - key: 128-bit encryption key (array of 4 uint32_t)
 * - nonce: 64-bit starting counter value for the stream cipher
 */
void xtea_ctr_encrypt(uint8_t *data, size_t len, const uint32_t key[4], uint64_t nonce);
void xtea_ctr_decrypt(uint8_t *cursor, uint64_t remaining, const uint32_t key[4], uint64_t counter);
/**
 * Get a pointer to the embedded stub data.
 * Returns a pointer to the beginning of the stub data.
 */
const unsigned char *woody_stub_data(void);
/**
 * Get the size of the embedded stub data.
 * Returns the size in bytes.
 */
size_t woody_stub_size(void);
/**
 * Get the offset of the metadata within the stub data.
 * Returns the offset in bytes.
 */
size_t woody_stub_meta_offset(void);
