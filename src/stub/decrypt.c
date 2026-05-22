#include "woody.h"
#include <stddef.h>
#include <stdint.h>

#define STUB_CODE   __attribute__((section(".text.woody_stub"), used))
#define STUB_ENTRY  __attribute__((section(".text.woody_stub.entry"), used, aligned(16)))
#define STUB_RODATA __attribute__((section(".rodata.woody_stub"), used))
#define STUB_BSS    __attribute__((section(".bss.woody_stub"), used))
#define NO_STACK __attribute__((no_stack_protector))
#define NORETURN __attribute__((noreturn))

enum
{
    SYS_WRITE = 1,
    SYS_MPROTECT = 10,
    SYS_EXIT = 60
};

extern const unsigned char __start_woody_stub[] __asm__("__start_.woody_stub");
extern const unsigned char __stop_woody_stub[] __asm__("__stop_.woody_stub");
STUB_RODATA static const char stub_banner[] = "....WOODY....\n";
STUB_BSS struct stub_metadata woody_stub_metadata;

static STUB_CODE inline long stub_syscall(long n, long a, long b, long c)
{
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}

static STUB_CODE NO_STACK void decrypt_payload(uint8_t *cursor, uint64_t remaining, const uint32_t key[4], uint64_t counter)
{
    if (woody_stub_metadata.algo_id == XTEA_CTR)
    {
        xtea_ctr_decrypt(cursor, remaining, key, counter);
    }
}

static STUB_CODE NO_STACK uintptr_t prepare_original_entry(uintptr_t stub_addr)
{
    const uintptr_t bias = stub_addr - woody_stub_metadata.self_entry_rva;
    const uint64_t encrypted_end_rva = woody_stub_metadata.encrypted_rva + woody_stub_metadata.encrypted_size;
    const uint64_t page_rva = woody_stub_metadata.encrypted_rva & ~(uint64_t)(PAGE_SIZE - 1u);
    const uint64_t page_end_rva = (encrypted_end_rva + (PAGE_SIZE - 1u)) & ~(uint64_t)(PAGE_SIZE - 1u);
    const size_t page_size = (size_t)(page_end_rva - page_rva);
    uint32_t key[4];

    stub_syscall(SYS_WRITE, 1, (long)stub_banner, (long)(sizeof(stub_banner) - 1));

    for (int i = 0; i < 4; ++i)
        key[i] = woody_stub_metadata.key[i];

    void *page = (void *)(page_rva + bias);
    if (stub_syscall(SYS_MPROTECT, (long)page, (long)page_size, 7) < 0)
        stub_syscall(SYS_EXIT, 1, 0, 0);

    decrypt_payload((uint8_t *)(woody_stub_metadata.encrypted_rva + bias), woody_stub_metadata.encrypted_size, key, woody_stub_metadata.nonce);

    if (stub_syscall(SYS_MPROTECT, (long)page, (long)page_size, (long)woody_stub_metadata.original_prot) < 0)
        stub_syscall(SYS_EXIT, 1, 0, 0);

    return woody_stub_metadata.original_entry_rva + bias;
}

STUB_ENTRY NO_STACK void woody_stub_start(uint64_t argc, char **argv, char **envp)
{
    const uintptr_t stub_addr = (uintptr_t)(const void *)&woody_stub_start;
    const uintptr_t entry = prepare_original_entry(stub_addr);
    ((void (*)(uint64_t, char **, char **))entry)(argc, argv, envp);
    stub_syscall(SYS_EXIT, 0, 0, 0);
    __builtin_unreachable();
}

const unsigned char *woody_stub_data(void)
{
    return __start_woody_stub;
}

size_t woody_stub_size(void)
{
    return (size_t)(__stop_woody_stub - __start_woody_stub);
}

size_t woody_stub_meta_offset(void)
{
    return (size_t)((const unsigned char *)&woody_stub_metadata - __start_woody_stub);
}
