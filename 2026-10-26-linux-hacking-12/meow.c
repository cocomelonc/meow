/*
 * meow.c
 * lists the contents of a directory
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : ".";
  DIR *dir = opendir(path);
  if (dir == NULL) {
    perror("opendir");
    return 1;
  }

  int result = 0;
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(dir);
    if (entry == NULL) {
      if (errno != 0) {
        perror("readdir");
        result = 1;
      }
      break;
    }

    printf("%s\n", entry->d_name);
  }

  if (closedir(dir) != 0) {
    perror("closedir");
    result = 1;
  }

  return result;
}
