; hello3.asm: pop-up "hello world" to the window by using win32 API.
; author:    @cocomelonc
; run:
; nasm -f win32 -o hello3.o hello3.asm
; i686-w64-mingw32-ld -o hello3.exe hello3.o -lkernel32 -luser32
; 32-bit windows

[BITS 32]

section .text
global  _start
extern _MessageBoxA@16
extern  _ExitProcess@4

_start:

  ; MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
  push dword 0            ; push arguments reverse: 0
  push caption            ; push arguments reverse: caption
  push msg                ; push arguments reverse: msg
  push dword 0            ; push arguments reverse: hWnd
  call _MessageBoxA@16    ; call MessageBoxA

  ; ExitProcess(0)
  push dword 0            ; push arguments: 0
  call _ExitProcess@4     ; call ExitProcess

section .data:
  msg: db "hello world", 0
  caption: db "hello", 0
