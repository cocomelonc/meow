; example2.asm - spawn a linux shell.
; author @cocomelonc
; nasm -f elf32 -o example2.o example2.asm
; ld -m elf_i386 -o example2 example2.o && ./example2
; 32-bit linux

section .data
  msg: db '/bin/sh'

section .bss

section .text
  global _start   ; must be declared for linker

_start:           ; linker entry point

  ; xoring anything with itself clears itself:
  xor eax, eax    ; zero out eax
  xor ebx, ebx    ; zero out ebx
  xor ecx, ecx    ; zero out ecx
  xor edx, edx    ; zero out edx

  mov al, 0xb     ; mov eax, 11: execve
  mov ebx, msg    ; load the string pointer to ebx
  int 0x80        ; syscall

  ; normal exit
  mov al, 1       ; sys_exit system call (mov eax, 1) with remove null bytes
  xor ebx, ebx    ; no errors (mov ebx, 0)
  int 0x80        ; call sys_exit
