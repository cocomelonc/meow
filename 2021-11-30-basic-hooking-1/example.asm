; just normal exit
; author @cocomelonc
; nasm -f elf32 -o example.o example.asm
; ld -m elf_i386 -o example example.o
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  xor  eax, eax         ; zero out eax
  push ebp
  mov  ebp, esp
  push eax              ; push NULL
  mov  eax, 0x759279b0  ; call ExitProcess function addr in kernel32.dll
  jmp  eax
