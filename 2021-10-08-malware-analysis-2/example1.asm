; example1.asm
; author: @cocomelonc
; run:
; nasm -f elf32 -o example1.o example1.asm
; gcc -static -m32 -o example1 example1.o
; 32-bit linux

section .text
  global main

main:
  push ebp
  mov ebp, esp
  mov eax, 123
  mov esp, ebp
  pop ebp
  ret

section .data
