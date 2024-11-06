#ifndef LOAD_H
#define LOAD_H

#include <stdint.h>

#include "../include/cipher.h"
#include "../include/log.h"

int decrypt_lkm(fraction_t *fractions, int fractions_count, unsigned char *key);
int load_lkm(int fd);

#endif
