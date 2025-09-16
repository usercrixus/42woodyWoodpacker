#define _GNU_SOURCE
#include "woody.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/random.h>
#include <stdbool.h>
#include <string.h>

typedef struct s_file_view
{
    int fd;
    size_t size;
    uint8_t *data;
} t_file_view;

static int report_error(const char *msg)
{
    fprintf(stderr, "woody_woodpacker: %s\n", msg);
    return (-1);
}

static uint32_t flags_to_prot(uint32_t flags)
{
    uint32_t prot;

    prot = 0;
    if (flags & PF_R)
        prot |= PROT_READ;
    if (flags & PF_W)
        prot |= PROT_WRITE;
    if (flags & PF_X)
        prot |= PROT_EXEC;
    return (prot);
}

/**
 * clean the t_file_view data
 */
static void unmap_input(t_file_view *view)
{
    if (view->data)
        munmap(view->data, view->size);
    if (view->fd >= 0)
        close(view->fd);
}

/**
 * feed the t_file_view data with the required file from path.
 * @return -1 on error
 */
static bool map_input(const char *path, t_file_view *view)
{
    off_t size;

    view->fd = open(path, O_RDONLY);
    view->data = NULL;
    view->size = 0;
    if (view->fd < 0)
        return (perror("open"), false);
    size = lseek(view->fd, 0, SEEK_END);
    if (size <= 0 || lseek(view->fd, 0, SEEK_SET) < 0)
        return (perror("lseek"), close(view->fd), false);
    view->size = (size_t)size;
    view->data = (uint8_t *)mmap(NULL, view->size, PROT_READ, MAP_PRIVATE, view->fd, 0);
    if (view->data == MAP_FAILED)
        return (perror("mmap"), close(view->fd), false);
    return (true);
}

static int write_output(const uint8_t *buf, size_t size)
{
    int fd;
    size_t written;

    fd = open(WOODY_OUTPUT, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
    {
        perror("open");
        return (-1);
    }
    written = 0;
    while (written < size)
    {
        ssize_t ret = write(fd, buf + written, size - written);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            perror("write");
            close(fd);
            return (-1);
        }
        if (ret == 0)
            break;
        written += (size_t)ret;
    }
    if (written != size)
    {
        fprintf(stderr, "woody_woodpacker: short write\n");
        close(fd);
        return (-1);
    }
    if (close(fd) != 0)
    {
        perror("close");
        return (-1);
    }
    return (0);
}


static int process_elf(const t_file_view *view)
{
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *ph_table;
    size_t exec_idx;

    if (view->size < sizeof(*ehdr))
        return (report_error("file too small to be an ELF"));
    ehdr = (const Elf64_Ehdr *)view->data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64 || ehdr->e_ident[EI_DATA] != ELFDATA2LSB || ehdr->e_version != EV_CURRENT || (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) || ehdr->e_machine != EM_X86_64)
        return (report_error("unsupported ELF format"));
    if (ehdr->e_phoff + (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > view->size || ehdr->e_phentsize != sizeof(Elf64_Phdr) || ehdr->e_phnum == 0)
        return (report_error("corrupted program header table"));
    ph_table = (const Elf64_Phdr *)(view->data + ehdr->e_phoff);
    exec_idx = (size_t)-1;
    for (size_t i = 0; i < ehdr->e_phnum; ++i)
    {
        const Elf64_Phdr *ph = &ph_table[i];

        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X) && exec_idx == (size_t)-1)
            exec_idx = i;
    }
    if (exec_idx == (size_t)-1)
        return (report_error("missing executable PT_LOAD segment"));
    const Elf64_Phdr *exec = &ph_table[exec_idx];
    const uint64_t entry = ehdr->e_entry;
    if (entry < exec->p_vaddr || entry >= exec->p_vaddr + exec->p_memsz)
        return (report_error("entry point outside executable segment"));
    const uint64_t enc_file_off = exec->p_offset + (entry - exec->p_vaddr);
    const uint64_t enc_file_end = exec->p_offset + exec->p_filesz;
    if (enc_file_off >= enc_file_end || enc_file_end > view->size)
        return (report_error("cannot determine encryption range"));
    const size_t enc_len = (size_t)(enc_file_end - enc_file_off);
    if (enc_len == 0)
        return (report_error("empty executable payload"));
    const size_t stub_size = (size_t)(woody_stub_end - woody_stub_start);
    const size_t meta_offset = (size_t)(woody_stub_metadata - woody_stub_start);
    if (meta_offset + sizeof(struct stub_metadata) > stub_size)
        return (report_error("stub metadata layout mismatch"));
    const uint64_t insert_point = exec->p_offset + exec->p_filesz;
    uint64_t next_offset = view->size;
    for (size_t i = 0; i < ehdr->e_phnum; ++i)
    {
        const Elf64_Phdr *ph = &ph_table[i];

        if (ph->p_offset > insert_point && ph->p_offset < next_offset)
            next_offset = ph->p_offset;
    }
    const size_t pad = (size_t)(align_up(insert_point, 16) - insert_point);
    const uint64_t stub_file_off = insert_point + pad;
    const uint64_t stub_file_end = stub_file_off + stub_size;
    if (next_offset > insert_point && stub_file_end > next_offset)
        return (report_error("not enough room for stub"));
    const size_t growth = pad + stub_size;
    const size_t new_size = view->size;
    uint8_t *output = (uint8_t *)malloc(new_size);
    if (!output)
    {
        perror("malloc");
        return (-1);
    }
    woody_memcpy(output, view->data, view->size);
    if (pad)
        woody_bzero(output + insert_point, pad);
    woody_memcpy(output + stub_file_off, woody_stub_start, stub_size);
    Elf64_Ehdr *out_ehdr = (Elf64_Ehdr *)output;
    Elf64_Phdr *out_phdr = (Elf64_Phdr *)(output + out_ehdr->e_phoff);
    Elf64_Phdr *out_exec = &out_phdr[exec_idx];
    const uint64_t old_exec_filesz = exec->p_filesz;
    out_exec->p_filesz = old_exec_filesz + growth;
    out_exec->p_memsz = exec->p_memsz + growth;
    uint8_t *enc_ptr = output + (size_t)enc_file_off;
    uint8_t entropy[sizeof(uint32_t) * 4 + sizeof(uint64_t)];
    uint32_t key[4];
    uint64_t nonce;
    if (getentropy(entropy, sizeof(entropy)) < 0)
    {
        free(output);
        return (report_error("random generation failed"));
    }
    woody_memcpy(key, entropy, sizeof(key));
    woody_memcpy(&nonce, entropy + sizeof(key), sizeof(nonce));
    if (nonce == 0)
        nonce = ((uint64_t)enc_file_off << 32) ^ stub_file_off;
    xtea_ctr_transform(enc_ptr, enc_len, key, nonce);
    struct stub_metadata *meta = (struct stub_metadata *)(output + stub_file_off + meta_offset);
    const uint64_t stub_rva = exec->p_vaddr + old_exec_filesz + pad;
    meta->self_entry_rva = stub_rva;
    meta->original_entry_rva = entry;
    meta->encrypted_rva = entry;
    meta->encrypted_size = enc_len;
    meta->page_rva = align_down(meta->encrypted_rva, PAGE_SIZE);
    meta->page_size = align_up(meta->encrypted_rva + meta->encrypted_size, PAGE_SIZE) - meta->page_rva;
    meta->original_prot = flags_to_prot(out_exec->p_flags);
    meta->nonce = nonce;
    for (size_t i = 0; i < 4; ++i)
        meta->key[i] = key[i];
    out_ehdr->e_entry = stub_rva;
    out_ehdr->e_shoff = 0;
    out_ehdr->e_shnum = 0;
    out_ehdr->e_shstrndx = SHN_UNDEF;
    printf("key %08x-%08x-%08x-%08x nonce %016llx\n",
           key[0], key[1], key[2], key[3],
           (unsigned long long)nonce);
    if (write_output(output, new_size) != 0)
    {
        free(output);
        return (-1);
    }
    free(output);
    return (0);
}

int pack_elf64(const char *path)
{
    t_file_view view;
    int status;

    if (!map_input(path, &view))
        return (1);
    status = process_elf(&view);
    unmap_input(&view);
    return (status != 0);
}
