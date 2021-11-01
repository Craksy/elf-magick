global _start
    section .data
_hello: db "Hello.",10
_hello_len: equ $ - _hello
    section .bss
buf:    resq 1
    section .text

_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, _hello
    mov rdx, _hello_len
    syscall
    mov rax, 60
    syscall
