#include "../include/fraction.h"
#include "../include/crc32.h"

int download_fraction(int sfd, fraction_t *fraction) {
  http_res_t res;
  fraction_t downloaded_fraction = {};

  // Perform the HTTP GET request
  if (http_get(sfd, "/stream", &res) != HTTP_SUCCESS) {
    return 1;
  }

  // Parse the downloaded data into a fraction
  if (fraction_parse(res.data, res.size, &downloaded_fraction) != 0) {
    http_free(&res);
    return 1;
  }

  *fraction = downloaded_fraction;


  // Cleanup
  http_free(&res);

  return 0;
}

int fraction_parse(char *data, size_t size, fraction_t *fraction) {
  int calc_crc(fraction_t *frac);
  const size_t UINT32_SIZE = sizeof(uint32_t);
  const size_t IV_SIZE = 16; // 16 bytes for the IV
  const size_t MAGIC_SIZE = UINT32_SIZE;
  const size_t INDEX_SIZE = UINT32_SIZE;
  const size_t CRC_SIZE = UINT32_SIZE;
  const size_t HEADER_SIZE = MAGIC_SIZE + INDEX_SIZE + IV_SIZE + CRC_SIZE;
  size_t data_size;

  // Ensure the data size is sufficient
  if (size < HEADER_SIZE) {
    log_error("Insufficient size: %lu", size);
    return 1;

  }

    // Extract fields from data buffer with endianess handling
    uint32_t magic, index, crc;
    memcpy(&magic, data, MAGIC_SIZE);
    memcpy(&index, data + MAGIC_SIZE, INDEX_SIZE);
    memcpy(fraction->iv, data + MAGIC_SIZE + INDEX_SIZE, IV_SIZE);
    memcpy(&crc, data + MAGIC_SIZE + INDEX_SIZE + IV_SIZE, CRC_SIZE);

    // Check the magic number
    if (!check_magic(magic)) {
      log_error("Wrong magic number: %02x", magic);
      return 1;
    }

    // Allocate memory for fraction data
    data_size = size - HEADER_SIZE;
    fraction->data = malloc(data_size);
    if (!fraction->data) {
      log_error("Failed to allocate data for fraction");
      return 1;
    }
    // Set the extracted values in the fraction structure
    fraction->magic = magic;
    fraction->index = index;
    fraction->crc = crc;
    fraction->data_size = data_size;
    memcpy(fraction->data, data + HEADER_SIZE, data_size);

    return calc_crc(fraction);
}

int check_magic(uint32_t magic) {
  return magic == MAGIC;
}

// Function used by qsort() to compare the index of our fractions
int compare_fractions(const void *a, const void *b) {
  const fraction_t *frac_a = (const fraction_t *)a;
  const fraction_t *frac_b = (const fraction_t *)b;

  return frac_a->index - frac_b->index;
}

void print_fraction(fraction_t fraction) {
    log_debug("Magic: 0x%08x", fraction.magic);
    log_debug("Index: %u", fraction.index);
    if (log_get_level() == LOG_DEBUG) {
      char iv_str[sizeof(fraction.iv) * 3] = {
          0}; // 2 characters for hex + 1 for space
      for (size_t i = 0; i < sizeof(fraction.iv); i++) {
        snprintf(iv_str + i * 3, 4, "%02x ", (unsigned char)fraction.iv[i]);
      }
      log_debug("IV: %s", iv_str);
    }

    log_debug("CRC-32: 0x%08x", fraction.crc);
    log_debug("Data size: %lu", fraction.data_size);
}

int calc_crc(fraction_t *frac){
  bool result;
  uint8_t buffer[sizeof(frac->magic) + sizeof(frac->index) + sizeof(frac->iv) +
                 frac->data_size];
  size_t offset = 0;

  memcpy(buffer + offset, &frac->magic, sizeof(frac->magic));
  offset += sizeof(frac->magic);

  memcpy(buffer + offset, &frac->index, sizeof(frac->index));
  offset += sizeof(frac->index);

  memcpy(buffer + offset, frac->iv, sizeof(frac->iv));
  offset += sizeof(frac->iv);

  memcpy(buffer + offset, frac->data, frac->data_size);
  offset += frac->data_size;

  uint32_t calculated_crc = crc32(buffer, offset);
  result = calculated_crc != frac->crc;

  if (result) {
    log_warn("Checksum incorrect");
    log_warn("Checksum generated: %08X", calculated_crc);
    log_warn("Checksum from fraction: %08X\n", frac->crc);
  } else {
      log_debug("[%i] Checksum correct", frac->index);
  }
  return result;
}

void fraction_free(fraction_t *fraction) {
  if (fraction == NULL) return;
  free(fraction->data);
  fraction->magic = 0;
  fraction->index = 0;
  fraction->crc = 0;
}


