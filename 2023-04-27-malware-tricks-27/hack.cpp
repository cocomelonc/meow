/*
 * hack.c - LoadLibrary implementation. C++ implementation
 * @cocomelonc
 * https://cocomelonc.github.io/tutorial/2023/04/27/malware-tricks-27.html
*/
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

typedef int (__cdecl *CatProc)();
typedef int (__cdecl *MouseProc)();

typedef NTSTATUS(NTAPI *pLdrLoadDll) (
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
);

typedef VOID (NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

HMODULE MyLoadLibrary(LPCWSTR lpFileName) {
    UNICODE_STRING ustrModule;
    HANDLE hModule = NULL;

    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    RtlInitUnicodeString(&ustrModule, lpFileName);

    pLdrLoadDll myLdrLoadDll = (pLdrLoadDll)GetProcAddress(GetModuleHandle("ntdll.dll"), "LdrLoadDll");
    if (!myLdrLoadDll) {
        return NULL;
    }

    NTSTATUS status = myLdrLoadDll(NULL, 0, &ustrModule, &hModule);
    return (HMODULE)hModule;
}

int main() {
    HMODULE petDll = MyLoadLibrary(L"pet.dll");
    if (petDll) {
        CatProc catFunc = (CatProc) GetProcAddress(petDll, "Cat");
        MouseProc mouseFunc = (MouseProc) GetProcAddress(petDll, "Mouse");
        if ((catFunc != NULL) && (mouseFunc != NULL)) {
            (catFunc) ();
            (mouseFunc) ();
        }
        FreeLibrary(petDll);
    } else {
        printf("failed to load library :(\n");
    }
    return 0;
}
