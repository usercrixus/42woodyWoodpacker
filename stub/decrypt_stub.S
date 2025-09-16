.intel_syntax noprefix
.section .woody_stub,"ax",@progbits
.p2align 4
.globl woody_stub_start
.globl woody_stub_end
.globl woody_stub_metadata

.set META_SELF_RVA, 0
.set META_ORIG_ENTRY, 8
.set META_ENC_RVA, 16
.set META_ENC_SIZE, 24
.set META_PAGE_RVA, 32
.set META_PAGE_SIZE, 40
.set META_ORIG_PROT, 48
.set META_NONCE, 56
.set META_KEY, 64

.set BANNER_OFFSET, woody_banner - woody_stub_start
.set BANNER_LEN, woody_banner_end - woody_banner
.set META_OFFSET, woody_stub_metadata - woody_stub_start

woody_stub_start:
    call get_base
get_base:
    pop r11
    sub r11, get_base - woody_stub_start
    mov r14, r11

    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    lea rsi, [r14 + BANNER_OFFSET]
    mov edx, BANNER_LEN
    mov edi, 1
    mov eax, 1
    syscall

    lea rbx, [r14 + META_OFFSET]
    mov r15, r14
    mov r10, qword ptr [rbx + META_SELF_RVA]
    sub r15, r10
    mov rbp, r15

    mov r12, qword ptr [rbx + META_ENC_RVA]
    add r12, rbp
    mov r13, qword ptr [rbx + META_ENC_SIZE]
    mov r9, qword ptr [rbx + META_ORIG_ENTRY]
    add r9, rbp
    mov r10, qword ptr [rbx + META_NONCE]

    mov eax, 10
    mov rdi, qword ptr [rbx + META_PAGE_RVA]
    add rdi, rbp
    mov rsi, qword ptr [rbx + META_PAGE_SIZE]
    mov edx, 7
    syscall
    test rax, rax
    js Lfail

Ldecrypt_loop:
    test r13, r13
    jz Lrestore

    mov rax, r10
    mov edx, eax
    shr rax, 32
    mov ecx, eax
    mov eax, edx
    mov edx, ecx
    xor r8d, r8d
    mov ecx, 32
Lxtea_round:
    add r8d, 0x9E3779B9
    mov r14d, edx
    shl r14d, 4
    mov r15d, edx
    shr r15d, 5
    xor r14d, r15d
    add r14d, edx
    mov esi, r8d
    and esi, 3
    mov esi, dword ptr [rbx + META_KEY + rsi*4]
    add esi, r8d
    xor r14d, esi
    add eax, r14d

    mov r14d, eax
    shl r14d, 4
    mov r15d, eax
    shr r15d, 5
    xor r14d, r15d
    add r14d, eax
    mov esi, r8d
    shr esi, 11
    and esi, 3
    mov esi, dword ptr [rbx + META_KEY + rsi*4]
    add esi, r8d
    xor r14d, esi
    add edx, r14d

    dec ecx
    jnz Lxtea_round

    mov rsi, rdx
    shl rsi, 32
    mov eax, eax
    or rsi, rax

    cmp r13, 8
    jb Lpartial

    mov rax, qword ptr [r12]
    xor rax, rsi
    mov qword ptr [r12], rax
    add r12, 8
    sub r13, 8
    inc r10
    jmp Ldecrypt_loop

Lpartial:
    mov rcx, r13
    test rcx, rcx
    jz Lafter_partial
    mov rax, rsi
Lpartial_loop:
    mov r15b, byte ptr [r12]
    mov dl, al
    xor r15b, dl
    mov byte ptr [r12], r15b
    shr rax, 8
    inc r12
    dec rcx
    jnz Lpartial_loop

Lafter_partial:
    xor r13, r13
    inc r10
    jmp Ldecrypt_loop

Lrestore:
    mov eax, 10
    mov rdi, qword ptr [rbx + META_PAGE_RVA]
    add rdi, rbp
    mov rsi, qword ptr [rbx + META_PAGE_SIZE]
    mov edx, dword ptr [rbx + META_ORIG_PROT]
    syscall

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    jmp r9

Lfail:
    mov eax, 60
    mov edi, 1
    syscall

.p2align 3
woody_banner:
    .ascii "....WOODY....\n"
woody_banner_end:
    .set WOODY_BANNER_LEN, BANNER_LEN

.p2align 3
woody_stub_metadata:
    .quad 0, 0, 0, 0
    .quad 0, 0
    .long 0
    .long 0
    .quad 0
    .long 0, 0, 0, 0

.p2align 3
woody_stub_end:

.section .note.GNU-stack,"",@progbits
