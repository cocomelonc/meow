/*
 * unaot.c
 * part 1: WAMR .aot container parser (header, sections, TARGET_INFO).
 * author: cocomelonc
 * https://cocomelonc.github.io/reverse/2026/09/30/wasm-aot-reversing-1.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "reader.h"

#define AOT_MAGIC 0x746f6100u   /* "\0aot" */

enum { SEC_TARGET_INFO=0, SEC_INIT_DATA=1, SEC_TEXT=2, SEC_FUNCTION=3,
       SEC_EXPORT=4, SEC_RELOCATION=5, SEC_SIGNATURE=6, SEC_CUSTOM=100 };

static const char *sec_name(uint32_t t) {
  switch (t) {
    case SEC_TARGET_INFO: return "TARGET_INFO"; case SEC_INIT_DATA: return "INIT_DATA";
    case SEC_TEXT: return "TEXT (native code)"; case SEC_FUNCTION: return "FUNCTION";
    case SEC_EXPORT: return "EXPORT"; case SEC_RELOCATION: return "RELOCATION";
    case SEC_SIGNATURE: return "SIGNATURE"; case SEC_CUSTOM: return "CUSTOM";
    default: return "<unknown>";
  }
}
static const char *machine_name(uint16_t m) {
  switch (m) {
    case 0x3e: return "x86_64"; case 0xb7: return "AArch64"; case 0xf3: return "RISC-V";
    case 0x28: return "ARM"; case 0x03: return "x86"; case 0xdc: return "Xtensa (ESP32)";
    default: return "<other>";
  }
}
static size_t align_up(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }

static void decode_target_info(reader_t *r, size_t body, uint32_t size) {
  if (size < 48) { printf("      <target_info too small>\n"); return; }
  uint16_t bin_type  = rd_u16_at(r, body + 0);
  uint16_t e_machine = rd_u16_at(r, body + 6);
  uint32_t e_version = rd_u32_at(r, body + 8);
  char arch[17] = {0};
  for (int i = 0; i < 16; i++) arch[i] = (char) rd_u8_at(r, body + 32 + i);
  printf("      %s, %s  machine=0x%02x (%s)  arch=\"%s\"  e_version=%u\n",
         (bin_type & 1) ? "big-endian" : "little-endian",
         (bin_type & 2) ? "64-bit" : "32-bit",
         e_machine, machine_name(e_machine), arch, e_version);
}

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) { perror(path); return NULL; }
  fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
  uint8_t *buf = malloc(sz > 0 ? sz : 1);
  *out_len = fread(buf, 1, (size_t) sz, fp);
  fclose(fp);
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <file.aot>\n", argv[0]); return 2; }
  size_t len = 0;
  uint8_t *buf = read_file(argv[1], &len);
  if (!buf) return 1;

  reader_t r; rd_init(&r, buf, len);
  uint32_t magic = rd_u32_at(&r, 0), version = rd_u32_at(&r, 4);

  printf("== unaot: %s (%zu bytes) ==\n", argv[1], len);
  printf("magic    : 0x%08x %s\n", magic,
         magic == AOT_MAGIC ? "(\\0aot ok)" : "(BAD - not a WAMR .aot)");
  printf("version  : %u\n\n", version);
  if (magic != AOT_MAGIC) { free(buf); return 1; }

  size_t p = 8; int n = 0;
  while (1) {
    p = align_up(p, 4);                 /* every section header is 4-aligned */
    if (p + 8 > len) break;
    uint32_t type = rd_u32_at(&r, p), size = rd_u32_at(&r, p + 4);
    if (r.err) break;
    size_t body = p + 8;
    if (size > len - body) { printf("[%d] %s <truncated>\n", n, sec_name(type)); break; }

    printf("[%d] section %-18s type=%u  off=0x%zx  size=%u\n",
           n, sec_name(type), type, body, size);
    if (type == SEC_TARGET_INFO) decode_target_info(&r, body, size);
    else if (type == SEC_TEXT)
      printf("      -> native machine code blob (%u bytes)\n", size);

    p = body + size; n++;
  }
  printf("\n%d sections.\n", n);
  free(buf);
  return 0;
}
