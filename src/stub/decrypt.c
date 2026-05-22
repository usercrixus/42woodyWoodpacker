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

static STUB_CODE NO_STACK uintptr_t stub_entry_addr(void)
{
    uintptr_t addr;

    __asm__ volatile("leaq woody_stub_start(%%rip), %0" : "=r"(addr));
    return (addr);
}

static STUB_CODE NO_STACK const char *stub_banner_addr(void)
{
    const char *addr;

    __asm__ volatile("leaq stub_banner(%%rip), %0" : "=r"(addr));
    return (addr);
}

static STUB_CODE NO_STACK const struct stub_metadata *stub_metadata_addr(void)
{
    const struct stub_metadata *addr;

    __asm__ volatile("leaq woody_stub_metadata(%%rip), %0" : "=r"(addr));
    return (addr);
}

static STUB_CODE inline long stub_syscall(long n, long a, long b, long c)
{
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}

static STUB_CODE NO_STACK void decrypt_payload(uint8_t *cursor, uint64_t remaining, const struct stub_metadata *meta)
{
    if (meta->algo_id == XTEA_CTR)
    {
        xtea_ctr_decrypt(cursor, remaining, meta->algo_data);
    }
}

static STUB_CODE NO_STACK uintptr_t prepare_original_entry(uintptr_t stub_addr)
{
    const struct stub_metadata *meta = stub_metadata_addr();
    const uintptr_t bias = stub_addr - meta->self_entry_rva;
    const uint64_t encrypted_end_rva = meta->encrypted_rva + meta->encrypted_size;
    const uint64_t page_rva = meta->encrypted_rva & ~(uint64_t)(PAGE_SIZE - 1u);
    const uint64_t page_end_rva = (encrypted_end_rva + (PAGE_SIZE - 1u)) & ~(uint64_t)(PAGE_SIZE - 1u);
    const size_t page_size = (size_t)(page_end_rva - page_rva);

    stub_syscall(SYS_WRITE, 1, (long)stub_banner_addr(), (long)(sizeof(stub_banner) - 1));

    void *page = (void *)(page_rva + bias);
    if (stub_syscall(SYS_MPROTECT, (long)page, (long)page_size, 7) < 0)
        stub_syscall(SYS_EXIT, 1, 0, 0);

    decrypt_payload((uint8_t *)(meta->encrypted_rva + bias), meta->encrypted_size, meta);

    if (stub_syscall(SYS_MPROTECT, (long)page, (long)page_size, (long)meta->original_prot) < 0)
        stub_syscall(SYS_EXIT, 1, 0, 0);

    return meta->original_entry_rva + bias;
}

STUB_ENTRY NO_STACK void woody_stub_start(uint64_t argc, char **argv, char **envp)
{
    const uintptr_t stub_addr = stub_entry_addr();
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
