/*
pet.dll - for testing how to enumerate exported functions
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)  {
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

extern "C" __declspec(dllexport) VOID _cdecl Cat(void) {
  MessageBox(NULL, "Meow-meow", "=^..^=", MB_OK);
}

extern "C" __declspec(dllexport) VOID _cdecl Bird(void) {
  MessageBox(NULL, "Tweet-tweet", ">(')", MB_OK);
}

extern "C" __declspec(dllexport) VOID _cdecl Mouse(void) {
  MessageBox(NULL, "Squeak-squeak", "<:3 )~~~", MB_OK);
}
