/*
 * hack2.cpp - get UID via CRC32 as REvil ransomware. C++ implementation
 * @cocomelonc
 * https://cocomelonc.github.io/malware/2023/02/02/malware-analysis-7.html
*/
#include <stdio.h>
#include <windows.h>
#include <intrin.h>
#include <wincrypt.h>

DWORD crc32(DWORD crc, const BYTE *buf, DWORD len) {
  DWORD table[256];
  DWORD i, j, c;
  for (i = 0; i < 256; i++) {
    c = i;
    for (j = 0; j < 8; j++) {
      if (c & 1)
        c = 0xEDB88320 ^ (c >> 1);
      else
        c = c >> 1;
    }
    table[i] = c;
  }

  crc = ~crc;
  while (len--)
    crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);

  return ~crc;
}

int main(void) {
  DWORD volumeSerial, cpuidHash, uid, i;
  char volumePath[MAX_PATH];
  BYTE cpuidData[16];
  DWORD cpuidDataSize = sizeof(cpuidData);
  DWORD hashBuffer[4];
  HCRYPTPROV hCryptProv;

  if (!GetVolumeInformation(NULL, NULL, 0, &volumeSerial, NULL, NULL, NULL, 0)) {
    printf("failed to get the volume serial number.\n");
    return 1;
  }

  volumeSerial = crc32(0x539, (BYTE *)&volumeSerial, sizeof(volumeSerial));

  __cpuid(hashBuffer, 0);
  for (i = 0; i < 4; i++)
    cpuidData[i] = (BYTE)(hashBuffer[i] & 0xff);
  __cpuid(hashBuffer, 1);
  for (i = 0; i < 4; i++)
    cpuidData[4 + i] = (BYTE)(hashBuffer[i] & 0xff);
  cpuidHash = crc32(volumeSerial, cpuidData, cpuidDataSize);

  uid = volumeSerial;
  uid = (uid << 32) | cpuidHash;

  printf("UID: %llx\n", uid);

  return 0;
}
