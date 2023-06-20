#include <stdlib.h>
#include <stdio.h>

int addMe(int a, int b) {
  return 42 * a + b;
}

int main(void) {
  int c;
  c = addMe(3, 5);
  return 0;
}
