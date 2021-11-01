    default rel
    global _start
    section .text

_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [_hello]
    lea rdx, [_hello_len]
    syscall
    mov rax, 60
    syscall


    section .data
_hello: db "Hello PIE!.",10
_hello_len: equ $ - _hello
