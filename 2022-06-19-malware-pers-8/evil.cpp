/*
evil.cpp
simple DLL for port monitor persistence
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2022/06/19/malware-pers-8.html
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

extern "C" __declspec(dllexport) DWORD InitHelperDll(DWORD dwNetshVersion, PVOID pReserved) {
  MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
  return 0;
}
