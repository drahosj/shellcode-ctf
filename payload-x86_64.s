.section .text
    lea     flag(%rip), %rax
    mov     %rax, %rdi
    mov     $0, %rsi
    mov     $0, %rdx
    mov     $2, %rax
    syscall

    mov     %rax, %rdi
    mov     %rsp, %rsi
    mov     $128, %rdx
    mov     $0, %rax
    syscall

    mov     $1, %rdi
    mov     %rax, %rdx
    mov     $1, %rax
    syscall

    mov     $60, %rax
    syscall
flag:
    .string "flag.txt"
