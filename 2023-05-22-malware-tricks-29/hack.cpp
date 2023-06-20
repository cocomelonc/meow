/*
 * hack.cpp - store binary data in registry. C++ implementation
 * @cocomelonc
 * https://cocomelonc.github.io/malware/2023/05/22/malware-tricks-29.html
*/
#include <windows.h>
#include <stdio.h>
#include <iostream>

void registryStore() {
  HKEY hkey;
  BYTE data[] = {0x6d, 0x65, 0x6f, 0x77, 0x6d, 0x65, 0x6f, 0x77};

  DWORD d;
  const char* secret = "Software\\meowApp";

  LSTATUS res = RegCreateKeyEx(HKEY_CURRENT_USER, (LPCSTR) secret, 0, NULL, 0, KEY_WRITE, NULL, &hkey, &d);
  printf (res != ERROR_SUCCESS ? "failed to create reg key :(\n" : "successfully create key :)\n");

  res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR) secret, 0, KEY_WRITE, &hkey);
  printf (res != ERROR_SUCCESS ? "failed open registry key :(\n" : "successfully open registry key :)\n");

  res = RegSetValueEx(hkey, (LPCSTR)"secretMeow", 0, REG_BINARY, data, sizeof(data));
  printf(res != ERROR_SUCCESS ? "failed to set registry value :(\n" : "successfully set registry value :)\n");

  RegCloseKey(hkey);
}

void registryGetData() {
  HKEY hkey;
  DWORD size = 0;
  const char* secret = "Software\\meowApp";

  LSTATUS res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)secret, 0, KEY_READ, &hkey);
  printf(res != ERROR_SUCCESS ? "failed to open reg key :(\n" : "successfully open reg key:)\n");

  res = RegQueryValueEx(hkey, (LPCSTR)"secretMeow", nullptr, nullptr, nullptr, &size);
  printf(res != ERROR_SUCCESS ? "failed to query data size :(\n" : "successfully get binary data size:)\n");

  // allocate memory for the data
  BYTE *data = new BYTE[size];

  res = RegQueryValueEx(hkey, (LPCSTR)"secretMeow", nullptr, nullptr, data, &size);
  printf(res != ERROR_SUCCESS ? "failed to query data :(\n" : "successfully get binary data:)\n");

  printf("data:\n");
  for (int i = 0; i < size; i++) {
    printf("\\x%02x", static_cast<int>(data[i]));
  }
  printf("\n\n");

  RegCloseKey(hkey);
  delete[] data;
}

int main(void) {
  registryStore();
  registryGetData();
  return 0;
}