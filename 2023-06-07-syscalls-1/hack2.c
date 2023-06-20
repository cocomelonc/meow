/*
hack2.c
print syscall ID from stub
author: @cocomelonc
https://cocomelonc.github.io/malware/2023/06/07/syscalls-1.html
*/
#include <windows.h>
#include <stdio.h>

void printSyscallStub(char* funcName) {
  HMODULE ntdll = LoadLibraryExA("ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

  if (ntdll == NULL) {
    printf("failed to load ntdll.dll\n");
    return;
  }

  FARPROC funcAddress = GetProcAddress(ntdll, funcName);

  if (funcAddress == NULL) {
    printf("failed to get address of %s\n", funcName);
    FreeLibrary(ntdll);
    return;
  }

  printf("address of %s: 0x%p\n", funcName, funcAddress);

  // print the first 23 bytes of the stub
  BYTE* bytes = (BYTE*)funcAddress;
  for (int i = 0; i < 23; i++) {
    printf("%02X ", bytes[i]);
  }
  printf("\n");

  FreeLibrary(ntdll);
}

int main() {
  printSyscallStub("NtAllocateVirtualMemory");
  return 0;
}
