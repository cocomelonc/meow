#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>

char *shell[2];
int main(void) {
  shell[0] = "/bin/sh";
  shell[1] = NULL;
  execve(shell[0], shell, NULL);
  exit(0);
}
