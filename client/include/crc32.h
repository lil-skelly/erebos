#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>
#include <stdlib.h>
#include "fraction.h"

extern const uint32_t crc32_tab[];
uint32_t crc32(const void *buf, size_t size);
#endif // CRC32_H
