/*
Victim process example for DLL injection via NtCreateThreadEx
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/12/06/malware-injection-9.html
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

int main() {
  MessageBox(NULL, "Squeak-squeak!", "<:( )~~", MB_OK);
    return 0;
}
