; example2.asm
; author: @cocomelonc
; run:
; nasm -f elf32 -o example2.o example2.asm
; gcc -static -m32 -o example2 example2.o
; 32-bit linux

section .text
  global main

; make new call frame (addMe)
addMe:
  push ebp              ; save old call frame
  mov  ebp, esp         ; initialize new call frame
  mov  eax, 0           ; move 0 to eax
  mov  edx, [ebp + 8]   ; move second arg to edx
  mov  eax, [ebp + 12]  ; move first arg to eax
  add  eax, edx         ; add to result
  pop  ebp              ; restore call frame
  ret                   ; return (to main)

; make new call frame (main)
main:
  push ebp              ; save old call frame
  mov  ebp, esp         ; initialize new call frame
  push 3                ; push call arguments in reverse
  push 2                ; push 2
  call addMe            ; call function addMe
  xor  eax, eax         ; mov eax, 0

  ; restore old call frame
  ; some compilers may produce a 'leave' instruction instead
  mov  esp, ebp
  pop  ebp             ; restore old call frame
  ret

section .data
