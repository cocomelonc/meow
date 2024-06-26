/*
* hack.c
* "malware" for testing VirusTotal API
* author: @cocomelonc
* https://cocomelonc.github.io/malware/2024/06/25/malware-trick-41.html
*/
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
  MessageBox(NULL, "Meow-meow!", "=^..^=", MB_OK);
  return 0;
}
