.section .text
    lea     flag(%rip), %rax
    mov     %rax, %rdi
    mov     $0, %rsi
    mov     $0, %rdx
    mov     $59, %rax
    syscall
flag:
    .string "/bin/sh"
