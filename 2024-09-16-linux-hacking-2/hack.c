/*
 * hack.c
 * linux hacking part 2: 
 * find process ID by name
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2024/09/16/linux-hacking-2.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

int find_process_by_name(const char *proc_name) {
  DIR *dir;
  struct dirent *entry;
  int pid = -1; 

  dir = opendir("/proc");
  if (dir == NULL) {
    perror("opendir /proc failed"); 
    return -1;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (isdigit(*entry->d_name)) { 
      char path[512];
      snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name); 

      FILE *fp = fopen(path, "r");
      if (fp) {
        char comm[512];
        if (fgets(comm, sizeof(comm), fp) != NULL) {
          // remove trailing newline from comm
          comm[strcspn(comm, "\r\n")] = 0; 
          if (strcmp(comm, proc_name) == 0) {
            pid = atoi(entry->d_name); 
            fclose(fp);
            break;
          }
        }
        fclose(fp);
      }
    }
  }

  closedir(dir);
  return pid;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <process_name>\n", argv[0]);
    return 1;
  }

  int pid = find_process_by_name(argv[1]);
  if (pid != -1) {
    printf("found pid: %d\n", pid);
  } else {
    printf("process '%s' not found.\n", argv[1]);
  }

  return 0;
}