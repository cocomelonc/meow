/*
pet.dll - DLL example for LoadLibrary
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
  }
  return TRUE;
}

__declspec(dllexport) int _cdecl Cat() {
  MessageBox(NULL, "meow-meow", "=^..^=", MB_OK);
  return 1;
}

__declspec(dllexport) int _cdecl Mouse() {
  MessageBox(NULL, "squeak-squeak", "<:3()~", MB_OK);
  return 1;
}