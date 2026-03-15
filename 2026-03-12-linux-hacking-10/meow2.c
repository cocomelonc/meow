/*
 * meow2.c
 * victim process that depends on libcat.so
 * author: @cocomelonc
 */
#include <stdio.h>
#include <unistd.h>

// forward declaration of the library function
extern void meow_sound();

int main() {
  printf("victim process started. pid: %d\n", getpid());
  while(1) {
    meow_sound();
    sleep(5);
  }
  return 0;
}