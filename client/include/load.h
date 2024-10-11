#include <stdint.h>
#define _GNU_SOURCE
#include <linux/module.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

#include "../include/cipher.h"
#include "../include/log.h"

uint8_t *decrypt_lkm(fraction_t *fractions, int fractions_count, ssize_t *len);
int load_lkm(const uint8_t *lkm, ssize_t total_size);
