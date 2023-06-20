/*
cartoon.cpp - victim program example 1
DLL hijacking with exported functions example
author: @cocomelonc
*/
#include <windows.h>
#include <cstdio>

typedef VOID (__cdecl *CatProc)(); // cat
typedef VOID (__cdecl *BirdProc)(); // bird
typedef VOID (__cdecl *MouseProc)(); // mouse

int main(void) {

  // main dll with exported functions
  HINSTANCE petDll;

  // pets
  CatProc catFunc;
  BirdProc birdFunc;
  MouseProc mouseFunc;

  // free memory
  BOOL freeRes;

  // load pet.dll
  petDll = LoadLibrary(TEXT("pet.dll"));

  if (petDll != NULL) {
    catFunc = (CatProc) GetProcAddress(petDll, "Cat");
    birdFunc = (BirdProc) GetProcAddress(petDll, "Bird");
    mouseFunc = (MouseProc) GetProcAddress(petDll, "Mouse");
    if (catFunc != NULL) {
      (catFunc) ();
    }
    if (birdFunc != NULL) {
      (birdFunc) ();
    }
    if (mouseFunc != NULL) {
      (mouseFunc) ();
    }
    freeRes = FreeLibrary(petDll);
  }

  return 0;
}
