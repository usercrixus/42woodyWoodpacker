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

struct pack_job
{
    const t_file_view *view; // raw elf file
    const Elf64_Ehdr *ehdr;  // elf header
    const Elf64_Phdr *phdrs; // program header
    const Elf64_Phdr *exec;  // exec segment
    size_t exec_idx;         // exec segment idx
};

struct pack_layout
{
    uint64_t insert_point;  // where we will insert the stub (not aligned)
    size_t pad;             // insert point termination pad
    uint64_t stub_file_off; // where we will insert the stub (aligned)
    size_t growth;          // pad + stub size (aligned)
    size_t tail_pad;        // final alignement
    size_t stub_size;       // stub size
    size_t meta_offset;     // meta offset from stub_file_off
};

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
        return (perror("open"), -1);
    written = 0;
    while (written < size)
    {
        ssize_t ret = write(fd, buf + written, size - written);
        if (ret < 0)
        {
            if (errno != EINTR)
                return (perror("write"), close(fd), -1);
        }
        else if (ret == 0)
            break;
        written += (size_t)ret;
    }
    if (written != size)
        return (fprintf(stderr, "woody_woodpacker: short write\n"), close(fd), -1);
    return (close(fd), 0);
}

static void fill_stub_metadata(const struct pack_job *job, const struct pack_layout *layout, uint8_t *output, const uint32_t key[4], uint64_t nonce)
{
    Elf64_Ehdr *out_ehdr = (Elf64_Ehdr *)output;
    struct stub_metadata *meta;
    const uint64_t stub_base_rva = job->exec->p_vaddr + job->exec->p_filesz + layout->pad;
    const uint64_t entry_rva = stub_base_rva;

    meta = (struct stub_metadata *)(output + (size_t)layout->stub_file_off + layout->meta_offset);
    meta->self_entry_rva = entry_rva;
    meta->original_entry_rva = job->ehdr->e_entry;
    meta->encrypted_rva = job->exec->p_vaddr;
    meta->encrypted_size = job->exec->p_filesz;
    meta->original_prot = flags_to_prot(job->exec->p_flags);
    meta->nonce = nonce;
    for (size_t i = 0; i < 4; ++i)
        meta->key[i] = key[i];
    out_ehdr->e_entry = entry_rva;
    out_ehdr->e_shoff = SHN_UNDEF;
    out_ehdr->e_shnum = SHN_UNDEF;
    out_ehdr->e_shstrndx = SHN_UNDEF;
}

/**
 * replace and reset header at adapted offset
 */
static void reconstruct_header(uint8_t *output, const struct pack_job *job, const struct pack_layout *layout)
{
    Elf64_Ehdr *out_ehdr = (Elf64_Ehdr *)output;
    if (job->ehdr->e_phoff >= layout->insert_point)
        out_ehdr->e_phoff += layout->growth;
    Elf64_Phdr *out_phdr = (Elf64_Phdr *)(output + out_ehdr->e_phoff);
    for (size_t i = 0; i < job->ehdr->e_phnum; ++i)
        if (job->phdrs[i].p_offset >= layout->insert_point)
            out_phdr[i].p_offset += layout->growth;
    Elf64_Phdr *out_exec = &out_phdr[job->exec_idx];
    out_exec->p_filesz += layout->growth;
    out_exec->p_memsz += layout->growth;
}

/**
 * clone the elf inserting the stub we need to decryption
 * @return the output binary
 */
static uint8_t *clone_with_stub(const struct pack_job *job, const struct pack_layout *layout)
{
    uint8_t *output = (uint8_t *)malloc(job->view->size + layout->growth);
    const size_t insert = (size_t)layout->insert_point;
    const size_t stub_off = (size_t)layout->stub_file_off;
    const unsigned char *stub = woody_stub_data();

    if (!output)
        return (NULL);
    memcpy(output, job->view->data, insert);                                                      // copy first part
    memset(output + insert, 0, layout->pad);                                                      // align
    memcpy(output + stub_off, stub, layout->stub_size);                                           // insert stub
    memset(output + stub_off + layout->stub_size, 0, layout->tail_pad);                           // align
    memcpy(output + insert + layout->growth, job->view->data + insert, job->view->size - insert); // copy last part
    reconstruct_header(output, job, layout);
    return (output);
}

/**
 * set pack_layout depending on pack_job
 */
static void set_layout(const struct pack_job *job, struct pack_layout *layout)
{
    const uint64_t insert_point = job->exec->p_offset + job->exec->p_filesz;
    const size_t stub_size = woody_stub_size();
    const size_t pad = (size_t)(align_up(insert_point, 16) - insert_point);
    const uint64_t segment_align = job->exec->p_align ? job->exec->p_align : 0x10u;
    const size_t raw_growth = pad + stub_size;
    const size_t aligned_growth = (size_t)align_up(raw_growth, segment_align);

    layout->insert_point = job->exec->p_offset + job->exec->p_filesz;
    layout->pad = pad;
    layout->stub_file_off = insert_point + pad;
    layout->growth = aligned_growth;
    layout->tail_pad = aligned_growth - raw_growth;
    layout->stub_size = stub_size;
    layout->meta_offset = woody_stub_meta_offset();
}

/**
 * set pack_job struct depending on t_file_view struct
 * @return true on success, false on error
 */
static bool set_job(const t_file_view *view, struct pack_job *job)
{
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)view->data;
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(view->data + ehdr->e_phoff);
    size_t exec_idx = 0;
    for (size_t i = 0; i < ehdr->e_phnum; ++i)
    {
        if (phdrs[i].p_type == PT_LOAD && (phdrs[i].p_flags & PF_X))
        {
            exec_idx = i;
            break;
        }
    }
    const Elf64_Phdr *exec = &phdrs[exec_idx];
    if (ehdr->e_entry < exec->p_vaddr || ehdr->e_entry >= exec->p_vaddr + exec->p_filesz)
        return (fprintf(stderr, "woody_woodpacker: entry not in chosen exec PT_LOAD\n"), false);
    job->view = view;
    job->ehdr = ehdr;
    job->phdrs = phdrs;
    job->exec = exec;
    job->exec_idx = exec_idx;
    return (true);
}

static int process_elf(const t_file_view *view)
{
    struct pack_job job;
    struct pack_layout layout;
    uint8_t entropy[sizeof(uint32_t) * 4 + sizeof(uint64_t)];
    uint32_t key[4];
    uint64_t nonce;

    if (!set_job(view, &job))
        return (-1);
    set_layout(&job, &layout);
    uint8_t *output = clone_with_stub(&job, &layout);
    if (!output)
        return (perror("malloc"), -1);
    if (getentropy(entropy, sizeof(entropy)) < 0)
        return (free(output), fprintf(stderr, "random generation failed\n"), -1);
    memcpy(key, entropy, sizeof(key));
    memcpy(&nonce, entropy + sizeof(key), sizeof(nonce));
    if (nonce == 0)
        nonce = ((uint64_t)job.exec->p_offset << 32) ^ layout.stub_file_off;
    xtea_ctr_transform(output + job.exec->p_offset, job.exec->p_filesz, key, nonce);
    fill_stub_metadata(&job, &layout, output, key, nonce);
    printf("key %08x-%08x-%08x-%08x nonce %016llx\n", key[0], key[1], key[2], key[3], (unsigned long long)nonce);
    if (write_output(output, job.view->size + layout.growth) != 0)
        return (free(output), -1);
    return (free(output), 0);
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
