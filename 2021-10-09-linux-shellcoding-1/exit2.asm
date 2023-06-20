; just normal exit
; author @cocomelonc
; nasm -f elf32 -o exit2.o exit2.asm
; ld -m elf_i386 -o exit2 exit2.o && ./exit2
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  xor eax, eax    ; zero out eax
  mov al, 1       ; sys_exit system call (mov eax, 1) with remove null bytes
  int 0x80        ; call sys_exit
