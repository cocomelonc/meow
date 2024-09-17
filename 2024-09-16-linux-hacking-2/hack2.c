/*
 * hack2.c
 * linux hacking part 2: 
 * find processes ID by name
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2024/09/16/linux-hacking-2.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

void find_processes_by_name(const char *proc_name) {
  DIR *dir;
  struct dirent *entry;
  int found = 0;

  dir = opendir("/proc");
  if (dir == NULL) {
    perror("opendir /proc failed");
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (isdigit(*entry->d_name)) {
      char path[512];
      snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);

      FILE *fp = fopen(path, "r");
      if (fp) {
        char cmdline[512];
        if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
          // command line arguments are separated by '\0', we only need the first argument (the program name)
          cmdline[strcspn(cmdline, "\0")] = 0;

          // perform case-insensitive comparison of the base process name
          const char *base_name = strrchr(cmdline, '/');
          base_name = base_name ? base_name + 1 : cmdline;

          if (strcasecmp(base_name, proc_name) == 0) {
            printf("found process: %s with PID: %s\n", base_name, entry->d_name);
            found = 1;
          }
        }
        fclose(fp);
      }
    }
  }

  if (!found) {
    printf("no processes found with the name '%s'.\n", proc_name);
  }

  closedir(dir);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <process_name>\n", argv[0]);
    return 1;
  }

  find_processes_by_name(argv[1]);

  return 0;
}
