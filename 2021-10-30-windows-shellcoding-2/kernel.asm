; find kernel32
; author @cocomelonc
; nasm -f win32 -o kernel.o kernel.asm
; ld -m i386pe -o kernel.exe kernel.o
; 32-bit windows

section .data

section .bss

section .text
  global _start               ; must be declared for linker

_start:
  xor ecx, ecx
  mov eax, [fs:ecx + 0x30]    ; offset to the PEB struct
  mov eax, [eax + 0xc]        ; offset to LDR within PEB
  mov eax, [eax + 0x14]       ; offset to InMemoryOrderModuleList
  mov eax, [eax]              ; kernel.exe address loaded in eax (1st)
  mov eax, [eax]              ; ntdll.dll address loaded (2nd)
  mov eax, [eax + 0x10]       ; kernel32.dll address loaded (3rd module)
