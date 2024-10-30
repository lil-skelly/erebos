#ifndef LOAD_H
#define LOAD_H

#include <stdint.h>

#include "../include/cipher.h"
#include "../include/log.h"

uint8_t *decrypt_lkm(fraction_t *fractions, int fractions_count, ssize_t *len, unsigned char *key);
int load_lkm(const uint8_t *lkm, ssize_t total_size);

#endif
