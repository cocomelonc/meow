/*
 * unaot.c - part 3: WAMR AOT v5 relocations and native-code xrefs.
 * author: cocomelonc
 * https://cocomelonc.github.io/reverse/2026/10/20/wasm-aot-reversing-3.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include "reader.h"

#define MAXF 8192
#define COLOR(s) (g_color ? (s) : "")
#define RESET COLOR("\x1b[0m")
#define TITLE COLOR("\x1b[1;36m")
#define SYMBOL COLOR("\x1b[1;35m")
static int g_color, g_is64, g_imports_known;
static uint16_t g_machine;
static uint32_t g_imports, g_fcount, g_expn;
static size_t g_code_file, g_code_size;
static uint64_t g_foff[MAXF];
static uint32_t g_ftype[MAXF];
static struct { uint32_t index; const char *name; } g_exp[MAXF];
typedef struct { size_t body; uint32_t size; int seen; } section_t;

/* All sequential reads are confined to the current section. */
static size_t take(reader_t *r, size_t n, size_t alignment) {
  size_t pad = (alignment - r->pos % alignment) % alignment;
  if (r->err || !rd_ok(r, r->pos, pad)) { r->err = 1; return 0; }
  r->pos += pad;
  if (!rd_ok(r, r->pos, n)) { r->err = 1; return 0; }
  size_t at = r->pos;
  r->pos += n;
  return at;
}
static uint16_t u16(reader_t *r) {
  size_t p = take(r, 2, 2);
  return r->err ? 0 : rd_u16_at(r, p);
}
static uint32_t u32(reader_t *r) {
  size_t p = take(r, 4, 4);
  return r->err ? 0 : rd_u32_at(r, p);
}
static uint64_t word(reader_t *r) {
  size_t p = take(r, g_is64 ? 8 : 4, 4); /* u64 is only 4-aligned! */
  if (r->err) return 0;
  return g_is64 ? rd_u64_at(r, p) : rd_u32_at(r, p);
}
static const char *string(reader_t *r) {
  uint16_t n = u16(r);
  size_t p = take(r, n, 1);
  if (r->err || n == 0) { r->err = 1; return NULL; }
  const char *s = (const char *)r->base + p;
  if (s[n - 1] != '\0' || memchr(s, '\0', n - 1)) {
    r->err = 1; return NULL;
  }
  return s;
}

static const char *function_name(uint32_t i, char fallback[32]) {
  if (g_imports_known)
    for (uint32_t k = 0; k < g_expn; k++)
      if (g_exp[k].index >= g_imports && g_exp[k].index - g_imports == i)
        return g_exp[k].name;
  snprintf(fallback, 32, "aot_func#%u", i);
  return fallback;
}
static int func_at(uint64_t off) {
  for (uint32_t i = 0; i < g_fcount; i++) {
    uint64_t end = i + 1 < g_fcount ? g_foff[i + 1] : g_code_size;
    if (off >= g_foff[i] && off < end) return (int)i;
  }
  return -1;
}
static int defined_symbol(const char *s) {
  const char *prefix = "aot_func#";
  if (strncmp(s, prefix, strlen(prefix))) return -1;
  s += strlen(prefix);
  if (*s < '0' || *s > '9') return -1;
  uint32_t n = 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9') return -1;
    uint32_t digit = (uint32_t)(*s - '0');
    if (n > (UINT32_MAX - digit) / 10) return -1;
    n = n * 10 + digit;
  }
  return n < g_fcount ? (int)n : -1;
}
static const char *reloc_type(uint32_t t) {
  if (g_machine == 3) switch (t) {
    case 1: return "R_386_32";
    case 2: return "R_386_PC32";
    case 4: return "R_386_PLT32";
  }
  if (g_machine == 0x3e) switch (t) {
    case 1: return "R_X86_64_64";
    case 2: return "R_X86_64_PC32";
    case 4: return "R_X86_64_PLT32";
    case 9: return "R_X86_64_GOTPCREL";
    case 41: return "R_X86_64_GOTPCRELX";
    case 42: return "R_X86_64_REX_GOTPCRELX";
  }
  if (g_machine == 0xb7) switch (t) {
    case 257: return "R_AARCH64_ABS64";
    case 275: return "R_AARCH64_ADR_PREL_PG_HI21";
    case 277: return "R_AARCH64_ADD_ABS_LO12_NC";
    case 282: return "R_AARCH64_JUMP26";
    case 283: return "R_AARCH64_CALL26";
  }
  if (g_machine == 0xf3) switch (t) {
    case 2: return "R_RISCV_64";
    case 18: return "R_RISCV_CALL";
    case 19: return "R_RISCV_CALL_PLT";
    case 23: return "R_RISCV_PCREL_HI20";
    case 24: return "R_RISCV_PCREL_LO12_I";
  }
  return "unknown relocation";
}

static int decode_target(reader_t *r) {
  if (r->len < 48) return 0;
  uint16_t bin = rd_u16_at(r, 0), type = rd_u16_at(r, 4);
  if ((bin != 0 && bin != 2) || type != 1) {
    fputs("need a little-endian ELF relocatable AOT target\n", stderr);
    return 0;
  }
  g_is64 = (bin == 2);
  g_machine = rd_u16_at(r, 6);
  printf("target: %.*s, %u-bit, machine=0x%x\n", 16,
         (const char *)r->base + 32, g_is64 ? 64 : 32, g_machine);
  return !r->err;
}
static int decode_text(reader_t *r, size_t body) {
  uint32_t literals = u32(r);
  take(r, literals, 1);
  if (r->err) return 0;
  g_code_file = body + r->pos;
  g_code_size = r->len - r->pos;
  printf("TEXT: body@0x%zx, literal_size=%u, code@0x%zx, code span=%zu\n",
         body, literals, g_code_file, g_code_size);
  return 1;
}
static uint32_t try_functions(reader_t *r, uint32_t extra) {
  uint32_t wsz = g_is64 ? 8 : 4;
  if (r->len % (wsz + 4 + extra)) return 0;
  size_t count = r->len / (wsz + 4 + extra);
  if (count == 0 || count > MAXF) return 0;
  uint64_t previous = 0;
  for (size_t i = 0; i < count; i++) {
    uint64_t off = g_is64 ? rd_u64_at(r, i * wsz) : rd_u32_at(r, i * wsz);
    if (r->err || off >= g_code_size || (i && off < previous)) return 0;
    previous = off;
  }
  return (uint32_t)count;
}
static int decode_functions(reader_t *r) {
  if (r->len == 0) { g_fcount = 0; return 1; }
  uint32_t basic = try_functions(r, 0), frames = try_functions(r, 8);
  if ((!basic && !frames) || (basic && frames)) {
    fputs("unsupported or ambiguous FUNCTION layout\n", stderr); return 0;
  }
  g_fcount = basic ? basic : frames;
  for (uint32_t i = 0; i < g_fcount; i++) g_foff[i] = word(r);
  for (uint32_t i = 0; i < g_fcount; i++) g_ftype[i] = u32(r);
  if (frames) take(r, (size_t)g_fcount * 8, 4);
  return !r->err && r->pos == r->len;
}
static int decode_exports(reader_t *r) {
  uint32_t count = u32(r);
  if (r->err || count > r->len / 8) return 0;
  for (uint32_t i = 0; i < count; i++) {
    uint32_t index = u32(r);
    size_t p = take(r, 1, 1);
    uint8_t kind = r->err ? 0 : rd_u8_at(r, p);
    const char *name = string(r);
    if (r->err) return 0;
    if (kind == 0) {
      if (g_expn == MAXF) return 0;
      g_exp[g_expn].index = index;
      g_exp[g_expn++].name = name;
    }
  }
  return 1;
}
static void print_functions(void) {
  printf("\n%s== defined functions ==%s\n", TITLE, RESET);
  if (!g_imports_known) puts("export names unresolved: supply --imports N if known");
  for (uint32_t i = 0; i < g_fcount; i++) {
    char buf[32];
    uint64_t end = i + 1 < g_fcount ? g_foff[i + 1] : g_code_size;
    printf("[%u] code+0x%" PRIx64 " file@0x%" PRIx64
           " span=%" PRIu64 " type=%u %s%s%s\n", i, g_foff[i],
           (uint64_t)g_code_file + g_foff[i], end - g_foff[i], g_ftype[i],
           SYMBOL, function_name(i, buf), RESET);
  }
}

static const char *reloc_symbol(reader_t *r, size_t offsets,
                                reader_t strings, uint32_t count, uint32_t idx) {
  if (idx >= count) { r->err = 1; return NULL; }
  uint32_t off = rd_u32_at(r, offsets + (size_t)idx * 4);
  if (r->err || off % 2 || !rd_ok(&strings, off, 2)) {
    r->err = 1; return NULL;
  }
  strings.pos = off;
  const char *s = string(&strings);
  if (strings.err) r->err = 1;
  return r->err ? NULL : s;
}
static int decode_relocations(reader_t *r) {
  uint32_t count = u32(r);
  if (r->err || count > r->len / 4) return 0;
  size_t offsets = take(r, (size_t)count * 4, 4);
  uint32_t total = u32(r);
  size_t start = take(r, total, 1);
  if (r->err) return 0;
  reader_t strings;
  rd_init(&strings, r->base + start, total);
  for (uint32_t i = 0; i < count; i++)
    if (!reloc_symbol(r, offsets, strings, count, i)) return 0;
  uint32_t groups = u32(r);
  if (r->err || groups > (r->len - r->pos) / 8) return 0;
  printf("\n%s== relocations ==%s\n%u symbols, %u group(s)\n",
         TITLE, RESET, count, groups);
  for (uint32_t i = 0; i < groups; i++) {
    uint32_t name_idx = u32(r), n = u32(r);
    const char *group = reloc_symbol(r, offsets, strings, count, name_idx);
    size_t entry = g_is64 ? 24 : 16;
    if (r->err || n > (r->len - r->pos) / entry) return 0;
    int text = !strcmp(group, ".text") || !strcmp(group, ".rel.text")
               || !strcmp(group, ".rela.text");
    printf("group %s: %u relocation(s)\n", group, n);
    for (uint32_t j = 0; j < n; j++) {
      uint64_t off = word(r), raw_addend = word(r);
      uint32_t type = u32(r), idx = u32(r);
      const char *name = reloc_symbol(r, offsets, strings, count, idx);
      if (r->err || (text && off >= g_code_size)) return 0;
      unsigned bits = g_is64 ? 64 : 32;
      uint64_t sign = UINT64_C(1) << (bits - 1);
      uint64_t mask = g_is64 ? UINT64_MAX : UINT32_MAX;
      int negative = (raw_addend & sign) != 0;
      uint64_t magnitude = negative ? ((~raw_addend + 1) & mask) : raw_addend;
      printf("  off=0x%" PRIx64 " %s(%u) -> %s%s%s add=%s%" PRIu64,
             off, reloc_type(type), type, SYMBOL, name, RESET,
             negative ? "-" : "", magnitude);
      int from = text ? func_at(off) : -1;
      int to = defined_symbol(name);
      if (text) printf(" file@0x%" PRIx64, (uint64_t)g_code_file + off);
      if (from >= 0) {
        char a[32], b[32];
        printf(" | %s+0x%" PRIx64 " -> %s",
               function_name((uint32_t)from, a), off - g_foff[from],
               to >= 0 ? function_name((uint32_t)to, b) : name);
        if (to >= 0)
          printf(" [target file@0x%" PRIx64 "]", (uint64_t)g_code_file + g_foff[to]);
      }
      putchar('\n');
    }
  }
  return !r->err && r->pos == r->len;
}

static uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); return NULL; }
  if (fseek(f, 0, SEEK_END)) { fclose(f); return NULL; }
  long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET)) { fclose(f); return NULL; }
  uint8_t *buf = malloc(n ? (size_t)n : 1);
  if (!buf) { fclose(f); return NULL; }
  *len = fread(buf, 1, (size_t)n, f);
  int good = *len == (size_t)n && !ferror(f);
  fclose(f);
  if (!good) { free(buf); return NULL; }
  return buf;
}
int main(int argc, char **argv) {
  const char *path = NULL;
  g_color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--no-color")) g_color = 0;
    else if (!strcmp(argv[i], "--color")) g_color = 1;
    else if (!strcmp(argv[i], "--imports") && i + 1 < argc) {
      const char *s = argv[++i];
      if (!*s) return 1;
      uint32_t n = 0;
      for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (UINT32_MAX - (uint32_t)(*s - '0')) / 10)
          return 1;
        n = n * 10 + (uint32_t)(*s - '0');
      }
      g_imports = n; g_imports_known = 1;
    } else if (argv[i][0] == '-' || path) return 1;
    else path = argv[i];
  }
  if (!path) {
    fprintf(stderr, "usage: %s [--no-color|--color] [--imports N] file.aot\n", argv[0]);
    return 1;
  }
  size_t len;
  uint8_t *buf = read_file(path, &len);
  if (!buf) return 1;
  reader_t file;
  rd_init(&file, buf, len);
  section_t sec[6] = {0};
  int ok = 0;
  if (u32(&file) != 0x746f6100u || u32(&file) != 5 || file.err) {
    fputs("need a WAMR AOT version 5 file\n", stderr); goto done;
  }
  while (file.pos < file.len) {
    uint32_t type = u32(&file), size = u32(&file);
    size_t body = take(&file, size, 1);
    if (file.err) goto done;
    if (type < 6) {
      if (sec[type].seen) goto done;
      sec[type] = (section_t){body, size, 1};
    }
  }
  reader_t r[6];
  for (int i = 0; i < 6; i++) {
    if (!sec[i].seen) goto done;
    rd_init(&r[i], buf + sec[i].body, sec[i].size);
  }
  if (!decode_target(&r[0]) || !decode_text(&r[2], sec[2].body)
      || !decode_functions(&r[3]) || !decode_exports(&r[4])) goto done;
  print_functions();
  ok = decode_relocations(&r[5]);
done:
  if (!ok) fputs("invalid, truncated, or unsupported AOT input\n", stderr);
  free(buf);
  return ok ? 0 : 1;
}
