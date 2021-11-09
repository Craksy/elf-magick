    global _start
    section .text

_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, _hello
    mov rdx, 12
    syscall
    xor rdi, rdi
    mov rax, 60
    syscall


    section .data
_hello: db "Hello PIE!.",10
