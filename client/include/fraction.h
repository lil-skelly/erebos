#ifndef fractions_h
#define fractions_h

#include <stdint.h>
#include "http.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <endian.h>

#define MAGIC 0xdeadbeef

typedef struct {
    uint32_t magic;
    uint32_t index;
    char iv[16];
    uint32_t crc;

    char *data;
} fraction_t;

int download_fraction(int sfd, char *url, fraction_t *fraction);
int fraction_parse(char *data, size_t size, fraction_t *fraction); 
int check_magic(uint32_t data);
void print_fraction(fraction_t fraction);
void fraction_free(fraction_t *fraction);
int compare_fractions(const void* a, const void* b);
#endif
