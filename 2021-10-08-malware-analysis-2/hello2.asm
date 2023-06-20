; hello.asm: writes "hello world" to the console by using C lib.
; author:    @cocomelonc
; run:
; nasm -f elf32 -o hello2.o hello2.asm
; gcc -static -m32 -o hello2 hello2.o && ./hello2
; 32-bit linux

section .text
global main
extern puts

main:                        ; called by C lib startup code
  push msg                   ; address of string to output
  call puts                  ; puts (msg)
  add esp, 4                 ; update stack pointer (1 argument 4 byte)
  xor eax, eax               ; a faster way of setting eax to zero
  ret                        ; return from main back into C library wrapper

msg: db "hello world", 0     ; note strings must be terminated with 0 in C
