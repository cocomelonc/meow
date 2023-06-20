; hello.asm: writes "hello world" to the console using only system calls.
; author:    @cocomelonc
; run:
; nasm -f elf64 -o hello.o hello.asm
; ld -o hello hello.o && ./hello
; 64-bit linux

section .text
  global _start

_start:
  mov rax, 1                ; system call for write
  mov rdi, 1                ; file handle 1 is stdout
  mov rsi, msg              ; address of string to output
  mov rdx, 12               ; number of bytes
  syscall

_exit:
  mov rax, 60               ; sys_exit system call
  mov rdi, 219              ; exit code 0 successfull exec
  syscall

section .data
  msg: db "hello world", 10 ; note the newline at the end
