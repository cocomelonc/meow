/*
 * unaot.c
 * part 2: WAMR .aot -> symbolized function table (EXPORT + FUNCTION) + color.
 * author: cocomelonc
 * https://cocomelonc.github.io/reverse/2026/10/14/wasm-aot-reversing-2.html
 */
#define _POSIX_C_SOURCE 200809L  /* isatty / fileno under -std=c11 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "reader.h"

#define AOT_MAGIC 0x746f6100u    /* "\0aot" */

enum {
  AOT_SEC_TARGET_INFO = 0, AOT_SEC_INIT_DATA = 1, AOT_SEC_TEXT = 2,
  AOT_SEC_FUNCTION = 3, AOT_SEC_EXPORT = 4, AOT_SEC_RELOCATION = 5,
  AOT_SEC_SIGNATURE = 6, AOT_SEC_CUSTOM = 100,
};

/* ------------------------------- color ---------------------------------- */
static int g_color = 0;
#define CC(s) (g_color ? (s) : "")
#define RST   CC("\x1b[0m")
#define BOLD  CC("\x1b[1m")
#define DIM   CC("\x1b[2m")
#define TITLE CC("\x1b[1;36m")   /* bold cyan    */
#define SEC   CC("\x1b[1;33m")   /* bold yellow  */
#define NUM   CC("\x1b[32m")     /* green        */
#define SYM   CC("\x1b[1;35m")   /* bold magenta */
#define ARCH  CC("\x1b[1;34m")   /* bold blue    */
#define OKC   CC("\x1b[32m")
#define BADC  CC("\x1b[1;31m")

/* ---------------------------- collected state --------------------------- */
#define MAXF 8192
static int      g_is64 = 1;       /* target word size, from TARGET_INFO */
static uint16_t g_machine = 0;    /* ELF e_machine, from TARGET_INFO    */
static uint32_t g_text_foff = 0;  /* file offset of TEXT body           */
static uint32_t g_code_size = 0;  /* TEXT size                          */
static uint64_t g_foff[MAXF];     /* per-func TEXT offset               */
static uint32_t g_ftype[MAXF];    /* per-func type index                */
static uint32_t g_fcount = 0;
struct expfn { uint32_t index; char name[96]; };
static struct expfn g_exp[MAXF];  /* exported functions (kind=func)     */
static uint32_t g_expn = 0;

static const char *sec_name(uint32_t t) {
  switch (t) {
    case AOT_SEC_TARGET_INFO: return "TARGET_INFO";
    case AOT_SEC_INIT_DATA:   return "INIT_DATA";
    case AOT_SEC_TEXT:        return "TEXT (native code)";
    case AOT_SEC_FUNCTION:    return "FUNCTION";
    case AOT_SEC_EXPORT:      return "EXPORT";
    case AOT_SEC_RELOCATION:  return "RELOCATION";
    case AOT_SEC_SIGNATURE:   return "SIGNATURE";
    case AOT_SEC_CUSTOM:      return "CUSTOM";
    default:                  return "<unknown>";
  }
}
static const char *machine_name(uint16_t m) {
  switch (m) {
    case 0x03: return "x86 (i386)"; case 0x3e: return "x86_64";
    case 0x28: return "ARM (32)";   case 0xb7: return "AArch64";
    case 0xf3: return "RISC-V";     case 0x08: return "MIPS";
    case 0xdc: return "Xtensa (ESP32)"; default: return "<other>";
  }
}
static const char *export_kind_name(uint8_t k) {
  switch (k) { case 0: return "func"; case 1: return "table"; case 2: return "memory";
               case 3: return "global"; case 4: return "tag"; default: return "?"; }
}
static size_t align_up(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }

/* look up an exported name for defined function index i (assumes
 * import_func_count == 0, which holds for self-contained modules). */
static const char *func_export_name(uint32_t i) {
  for (uint32_t k = 0; k < g_expn; k++) if (g_exp[k].index == i) return g_exp[k].name;
  return NULL;
}

static void decode_target_info(reader_t *r, size_t body, uint32_t size) {
  if (size < 48) { printf("      %s<target_info too small>%s\n", BADC, RST); return; }
  uint16_t bin_type = rd_u16_at(r, body + 0);
  uint16_t abi_type = rd_u16_at(r, body + 2);
  uint16_t e_type   = rd_u16_at(r, body + 4);
  uint16_t e_machine= rd_u16_at(r, body + 6);
  uint32_t e_version= rd_u32_at(r, body + 8);
  uint32_t e_flags  = rd_u32_at(r, body + 12);
  uint64_t feats    = rd_u64_at(r, body + 16);
  char arch[17]; memset(arch, 0, sizeof(arch));
  for (int i = 0; i < 16; i++) arch[i] = (char) rd_u8_at(r, body + 32 + i);
  g_is64 = (bin_type & 2) ? 1 : 0;
  g_machine = e_machine;
  printf("      %s%s%s, %s%s%s  abi=%u  e_type=%u  machine=%s0x%02x (%s)%s\n",
         BOLD, (bin_type & 1) ? "big-endian" : "little-endian", RST,
         BOLD, g_is64 ? "64-bit" : "32-bit", RST, abi_type, e_type,
         ARCH, e_machine, machine_name(e_machine), RST);
  printf("      e_version=%s%u%s  e_flags=0x%x  features=0x%016llx  arch=%s\"%s\"%s\n",
         NUM, e_version, RST, e_flags, (unsigned long long) feats, ARCH, arch, RST);
}

/* EXPORT: u32 count, then { u32 index(align4), u8 kind, string name }.
 * string = u16 len(align2) + len bytes (trailing '\0' counted in len). */
static void decode_export(reader_t *r, size_t body, uint32_t size) {
  size_t end = body + size, pos = body;
  uint32_t count = rd_u32_at(r, pos); pos += 4;
  if (r->err) { printf("      %s<export truncated>%s\n", BADC, RST); return; }
  printf("      %s%u%s export(s):\n", NUM, count, RST);
  for (uint32_t i = 0; i < count; i++) {
    pos = align_up(pos, 4);
    uint32_t index = rd_u32_at(r, pos); pos += 4;
    uint8_t  kind  = rd_u8_at(r, pos);  pos += 1;
    pos = align_up(pos, 2);
    uint16_t slen  = rd_u16_at(r, pos); pos += 2;
    if (r->err || pos + slen > end) { printf("        %s<export %u truncated>%s\n", BADC, i, RST); break; }
    char name[96];
    size_t n = slen < sizeof(name) ? slen : sizeof(name) - 1;
    for (size_t j = 0; j < n; j++) name[j] = (char) rd_u8_at(r, pos + j);
    name[n ? n - 1 : 0] = 0;   /* drop the counted trailing '\0' */
    pos += slen;
    printf("        [%u] %s%-6s%s index=%-3u  %s\"%s\"%s\n",
           i, DIM, export_kind_name(kind), RST, index, SYM, name, RST);
    if (kind == 0 && g_expn < MAXF) {   /* remember func names for symbolization */
      g_exp[g_expn].index = index;
      snprintf(g_exp[g_expn].name, sizeof(g_exp[g_expn].name), "%s", name);
      g_expn++;
    }
  }
}

/* try to read the FUNCTION section assuming `extra` bytes of per-func trailing
 * arrays (0 = no stack-frame info). returns func_count on success, else 0. */
static uint32_t try_func_layout(reader_t *r, size_t body, uint32_t size, uint32_t extra) {
  uint32_t wsz = g_is64 ? 8 : 4;
  uint32_t entry = wsz + 4 + extra;
  if (entry == 0 || size % entry != 0) return 0;
  uint32_t fc = size / entry;
  if (fc == 0 || fc > MAXF) return 0;
  uint64_t prev = 0;
  for (uint32_t i = 0; i < fc; i++) {
    uint64_t o = g_is64 ? rd_u64_at(r, body + (size_t) i * 8)
                        : rd_u32_at(r, body + (size_t) i * 4);
    if (r->err || o >= g_code_size || (i > 0 && o < prev)) return 0; /* sorted, in-range */
    prev = o;
  }
  return fc;
}

/* FUNCTION: text_offsets[fc] (u64 on 64-bit target, else u32) then
 * func_type_indexes[fc] (u32). fc is not in this section (it lives in
 * INIT_DATA), so derive it from the section size + validate the offsets. */
static void decode_function(reader_t *r, size_t body, uint32_t size) {
  if (g_code_size == 0) { printf("      %s<no TEXT seen yet>%s\n", BADC, RST); return; }
  uint32_t wsz = g_is64 ? 8 : 4;
  uint32_t fc = try_func_layout(r, body, size, 0);   /* no stack-frame info     */
  if (!fc) fc = try_func_layout(r, body, size, 8);    /* + 2 u32 frame arrays    */
  if (!fc) { printf("      %s<could not determine func_count>%s\n", BADC, RST); return; }

  for (uint32_t i = 0; i < fc; i++)
    g_foff[i] = g_is64 ? rd_u64_at(r, body + (size_t) i * 8)
                       : rd_u32_at(r, body + (size_t) i * 4);
  size_t tbase = body + (size_t) fc * wsz;
  for (uint32_t i = 0; i < fc; i++) g_ftype[i] = rd_u32_at(r, tbase + (size_t) i * 4);
  g_fcount = fc;
  printf("      %s%u%s function(s) (func index -> TEXT offset)\n", NUM, fc, RST);
}

static void print_symbol_table(void) {
  if (g_fcount == 0) return;
  printf("\n%s== functions (symbolized) ==%s   %s(text @ file 0x%x, assuming import_func_count=0)%s\n",
         TITLE, RST, DIM, g_text_foff, RST);
  for (uint32_t i = 0; i < g_fcount; i++) {
    uint64_t foff = g_foff[i];
    uint64_t fend = (i + 1 < g_fcount) ? g_foff[i + 1] : g_code_size;
    uint64_t fsz  = fend > foff ? fend - foff : 0;
    uint64_t file_off = (uint64_t) g_text_foff + foff;
    const char *nm = func_export_name(i);
    printf("  %s[%2u]%s text+0x%s%-6llx%s  file@0x%s%-6llx%s  size=%s%-4llu%s  type=%u  %s%s%s\n",
           DIM, i, RST,
           NUM, (unsigned long long) foff, RST,
           NUM, (unsigned long long) file_off, RST,
           NUM, (unsigned long long) fsz, RST, g_ftype[i],
           SYM, nm ? nm : "", RST);
  }
}

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) { perror(path); return NULL; }
  fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
  if (sz < 0) { fclose(fp); return NULL; }
  uint8_t *buf = malloc((size_t) sz ? (size_t) sz : 1);
  if (!buf) { fclose(fp); return NULL; }
  *out_len = fread(buf, 1, (size_t) sz, fp);
  fclose(fp);
  return buf;
}

int main(int argc, char **argv) {
  const char *path = NULL;
  int force_color = 0, no_color = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--color")) force_color = 1;
    else if (!strcmp(argv[i], "--no-color")) no_color = 1;
    else path = argv[i];
  }
  if (!path) { fprintf(stderr, "usage: %s [--color|--no-color] <file.aot>\n", argv[0]); return 2; }
  g_color = !no_color && (force_color || (isatty(fileno(stdout)) && !getenv("NO_COLOR")));

  size_t len = 0;
  uint8_t *buf = read_file(path, &len);
  if (!buf) return 1;
  reader_t r; rd_init(&r, buf, len);

  uint32_t magic = rd_u32_at(&r, 0), version = rd_u32_at(&r, 4);
  printf("%s== unaot: %s %s(%zu bytes)%s ==\n", TITLE, path, DIM, len, RST);
  printf("magic    : 0x%08x %s%s%s\n", magic,
         magic == AOT_MAGIC ? OKC : BADC,
         magic == AOT_MAGIC ? "(\\0aot ok)" : "(BAD - not a WAMR .aot)", RST);
  printf("version  : %s%u%s\n", NUM, version, RST);
  if (magic != AOT_MAGIC) { free(buf); return 1; }

  size_t p = 8; int n = 0;
  while (1) {
    p = align_up(p, 4);
    if (p + 8 > len) break;
    uint32_t type = rd_u32_at(&r, p), size = rd_u32_at(&r, p + 4);
    if (r.err) break;
    size_t body = p + 8;
    if (size > len - body) {
      printf("\n[%d] %s%s%s  %s<TRUNCATED>%s\n", n, SEC, sec_name(type), RST, BADC, RST);
      break;
    }
    printf("\n%s[%d]%s section %s%-18s%s type=%u  off=0x%s%zx%s  size=%s%u%s\n",
           DIM, n, RST, SEC, sec_name(type), RST, type, NUM, body, RST, NUM, size, RST);
    switch (type) {
      case AOT_SEC_TARGET_INFO: decode_target_info(&r, body, size); break;
      case AOT_SEC_TEXT:
        g_text_foff = (uint32_t) body; g_code_size = size;
        printf("      -> %snative machine code%s (%u bytes); disassemble per arch\n", BOLD, RST, size);
        break;
      case AOT_SEC_FUNCTION: decode_function(&r, body, size); break;
      case AOT_SEC_EXPORT:   decode_export(&r, body, size);   break;
      default: break;   /* RELOCATION: part 3 */
    }
    p = body + size; n++;
  }
  printf("\n%d sections.\n", n);
  print_symbol_table();
  free(buf);
  return 0;
}
