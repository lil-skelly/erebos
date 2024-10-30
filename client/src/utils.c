#include "../include/utils.h"
#include "../include/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void print_hex(const unsigned char *data, size_t size) {
  if (data == NULL) {
    log_error("Null data pointer\n"); // had to learn the hard f way
    return;
  }
  for (size_t i = 0; i < size; i++) {
    if (i%20==0) puts("");
    printf("%02X ", data[i]);

  }
  printf("\n");
}

void init_random(void) {
  FILE *random_device;
  unsigned int seed;
  int ret;

  random_device = fopen("/dev/urandom", "r");

  if (random_device == NULL) {
    log_error("Could not open /dev/urandom: using time as seed");
    srand(time(NULL));
    return;
  }

  ret = fread(&seed, sizeof(seed), 1, random_device);
  if (ret != 1) {
    log_error("Could not read from /dev/urandom: using time as seed");
    srand(time(NULL));
    fclose(random_device);
    return;
  }

  log_debug("Read seed %u from /dev/urandom", seed);

  fclose(random_device);
  srand(seed);
}

#define MIN_RANDOM_STR_LEN 5
#define MAX_RANDOM_STR_LEN 10

static inline int rand_range(int min, int max) {
  return rand() % (max + 1 - min) + min;
}

char *generate_random_string(void) {
  size_t len;
  char *s;

  len = rand_range(MIN_RANDOM_STR_LEN, MAX_RANDOM_STR_LEN);
  s = malloc(len * sizeof(char) + 1);

  for (size_t i = 0; i < len; i++) {
    s[i] = 'a' + rand_range(0, 25);
  }

  // null terminator
  s[len] = 0x0; 

  return s;
}
