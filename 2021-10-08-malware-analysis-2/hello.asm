; hello.asm: writes "hello world" to the console.
; author:    @cocomelonc
; run:
; nasm -f elf32 -o hello.o hello.asm
; ld -m elf_i386 -o hello hello.o && ./hello
; 32-bit linux

section .text
  global _start

_start:
  mov eax, 0x4              ; system call for write
  mov ebx, 1                ; file handle 1 is stdout
  mov ecx, msg              ; address of string to output
  mov edx, 12               ; number of bytes
  int 0x80                  ; call kernel

_exit:
  mov eax, 0x1              ; sys_exit system call
  mov ebx, 0                ; exit code 0 successfull exec
  int 0x80                  ; call sys_exit

section .data
  msg: db "hello world", 10 ; note the newline at the end
