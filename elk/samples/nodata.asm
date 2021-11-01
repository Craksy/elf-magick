global _start
    section .text

_start:
    mov rdi, 1
    sub rsp, 13
    mov byte [rsp+12], 101,
    mov byte [rsp+11], 114,
    mov byte [rsp+10], 101,
    mov byte [rsp+9], 104,
    mov byte [rsp+8], 116,
    mov byte [rsp+7], 32,
    mov byte [rsp+6], 44,
    mov byte [rsp+5], 111,
    mov byte [rsp+4], 108,
    mov byte [rsp+3], 108,
    mov byte [rsp+2], 101,
    mov byte [rsp+1], 104,
    mov byte [rsp+0], 10,

    mov rsi, rsp
    mov rdx, 13
    mov rax, 1
    syscall

    add rsp, 10
    xor rdi,rdi
    mov rax,60
    syscall
