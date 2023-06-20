/*
 * hack.cpp - Find function from DLL via ordinal. C++ implementation
 * @cocomelonc
 * https://cocomelonc.github.io/tutorial/2022/03/18/simple-malware-av-evasion-4.html
*/
#include <stdio.h>
#include "windows.h"

typedef UINT(CALLBACK* fnMessageBoxA)(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

// encrypted function name (MessageBoxA)
unsigned char s_mb[] = { 0x20, 0x1c, 0x0, 0x6, 0x11, 0x2, 0x17, 0x31, 0xa, 0x1b, 0x33 };

// encrypted module name (user32.dll)
unsigned char s_dll[] = { 0x18, 0xa, 0x16, 0x7, 0x43, 0x57, 0x5c, 0x17, 0x9, 0xf };

// key
char s_key[] = "mysupersecretkey";

// XOR decrypt
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
  int j;
  j = 0;
  for (int i = 0; i < data_len; i++) {
    if (j == key_len - 1) j = 0;
    data[i] = data[i] ^ key[j];
    j++;
  }
}

// binary search
DWORD findFuncB(PDWORD npt, DWORD size, PBYTE base, LPCSTR proc) {
  INT   cmp;
  DWORD max;
  DWORD mid;
  DWORD min;

  min = 0;
  max = size - 1;

  while (min <= max) {
    mid = (min + max) >> 1;
    cmp = strcmp((LPCSTR)(npt[mid] + base), proc);
    // printf("check API name %s on %d\n", (LPCSTR)(npt[mid] + base), mid);

    if (cmp < 0) {
      min = mid + 1;
    } else if (cmp > 0) {
      max = mid - 1;
    } else {
      return mid;
    }
  }
  return -1;
}

// get export directory table
PIMAGE_EXPORT_DIRECTORY getEDT(HMODULE module) {
  PBYTE           base; // base address of module
  PIMAGE_FILE_HEADER    img_file_header;  // COFF file header
  PIMAGE_EXPORT_DIRECTORY edt;  // export directory table (EDT)
  DWORD           rva;  // relative virtual address of EDT
  PIMAGE_DOS_HEADER     img_dos_header;  // MS-DOS stub
  PIMAGE_OPTIONAL_HEADER  img_opt_header;   // so-called "optional" header
  PDWORD          sig;  // PE signature

  // Start at the base of the module. The MS-DOS stub begins there.
  base = (PBYTE)module;
  img_dos_header = (PIMAGE_DOS_HEADER)module;

  // Get the PE signature and verify it.
  sig = (DWORD*)(base + img_dos_header->e_lfanew);
  if (IMAGE_NT_SIGNATURE != *sig) {
    // Bad signature -- invalid image or module handle
    return NULL;
  }

  // Get the COFF file header.
  img_file_header = (PIMAGE_FILE_HEADER)(sig + 1);

  // Get the "optional" header (it's not actually optional for executables).
  img_opt_header = (PIMAGE_OPTIONAL_HEADER)(img_file_header + 1);

  // Finally, get the export directory table.
  if (IMAGE_DIRECTORY_ENTRY_EXPORT >= img_opt_header->NumberOfRvaAndSizes) {
    // This image doesn't have an export directory table.
    return NULL;
  }
  rva = img_opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  edt = (PIMAGE_EXPORT_DIRECTORY)(base + rva);

  return edt;
}

// get func ordinal
DWORD getFuncOrd(HMODULE module, LPCSTR proc) {
  PBYTE           base; // module base address
  PIMAGE_EXPORT_DIRECTORY edt;  // export directory table (EDT)
  PWORD           eot;  // export ordinal table (EOT)
  DWORD           i;  // index into NPT and/or EOT
  PDWORD          npt;  // name pointer table (NPT)

  base = (PBYTE)module;

  // Get the export directory table, from which we can find the name pointer
  // table and export ordinal table.
  edt = getEDT(module);

  // Get the name pointer table and search it for the named procedure.
  npt = (DWORD*)(base + edt->AddressOfNames);
  i = findFuncB(npt, edt->NumberOfNames, base, proc);
  if (-1 == i) {
    // The procedure was not found in the module's name pointer table.
    return -1;
  }

  // Get the export ordinal table.
  eot = (WORD*)(base + edt->AddressOfNameOrdinals);

  // Actual ordinal is ordinal from EOT plus "ordinal base" from EDT.
  return eot[i] + edt->Base;
}

int main(int argc, char* argv[]) {
  XOR((char *) s_dll, sizeof(s_dll), s_key, sizeof(s_key));
  XOR((char *) s_mb, sizeof(s_mb), s_key, sizeof(s_key));

  if (NULL == LoadLibrary((LPCSTR) s_dll)) {
    printf("failed to load library :( %s\n", s_dll);
    return -2;
  }

  HMODULE module = GetModuleHandle((LPCSTR) s_dll);
  if (NULL == module) {
    printf("failed to get a handle to %s\n", s_dll);
    return -2;
  }

  DWORD ord = getFuncOrd(module, (LPCSTR) s_mb);
  if (-1 == ord) {
    printf("failed to find ordinal %s\n", s_mb);
    return -2;
  }
  //printf("MessageBoxA ordinal is %d\n", ord);

  fnMessageBoxA myMessageBoxA = (fnMessageBoxA)GetProcAddress(module, MAKEINTRESOURCE(ord));
  myMessageBoxA(NULL, "Meow-meow!","=^..^=", MB_OK);
  return 0;
}
