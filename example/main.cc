#include "utils.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (!InitChallenge(5000)) {
    return -1;
  }

  printf(" Hello, world!\n");

  return 0;
}