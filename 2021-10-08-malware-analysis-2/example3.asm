; example2.asm
; author: @cocomelonc
; run:
; nasm -f elf32 -o example3.o example3.asm
; gcc -static -m32 -o example3 example3.o
; 32-bit linux

section .text
  global main

; make new call frame (addMe)
addMe:
  push  ebp              ; save old call frame
  mov   ebp, esp         ; initialize new call frame
  mov   eax, [ebp + 8]   ; move a to eax
  imul  edx, eax, 42     ; calculate result
  mov   eax, [ebp + 12]  ; move second arg to eax
  add   eax, edx         ; add to result
  pop   ebp              ; restore call frame
  ret                   ; return (to main)

; make new call frame (main)
main:
  push ebp              ; save old call frame
  mov  ebp, esp         ; initialize new call frame
  push 3                ; push call arguments in reverse
  push 2                ; push 2
  call addMe            ; call function addMe
  mov  [ebp + 8], eax   ; move result to c
  xor  eax, eax         ; mov eax, 0

  ; restore old call frame
  ; some compilers may produce a 'leave' instruction instead
  mov  esp, ebp
  pop  ebp             ; restore old call frame
  ret

section .data
