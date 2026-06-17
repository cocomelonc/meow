/*
 * meow.c
 * simple target process for GOT/PLT hijacking demo
 * author: @cocomelonc
 * https://cocomelonc.github.io/linux/2026/06/17/linux-hacking-11.html
 */
#include <stdio.h>
#include <unistd.h>

int main(void) {
  printf("victim pid: %d\n", getpid());
  while (1) {
    puts("meow");
    sleep(2);
  }
  return 0;
}