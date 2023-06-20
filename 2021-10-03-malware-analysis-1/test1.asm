; first program in asm
; author @cocomelonc

section .data

section .bss

section .text
  global _start   ; must be declared for linker

_start:           ; linker entry point
  mov eax, 100    ; mov 100 into the EAX register

; normal exit
exit:
  mov eax, 1      ; sys_exit system call
  mov ebx, 0      ; exit code 0 successfull execution
  int 0x80        ; call sys_exit
