#include "../include/fraction.h"
#include <stdint.h>


// Change the return type to int to indicate success or failure
int download_fraction(int sfd, char *url, fraction_t *fraction) {
  char *path = NULL;
  http_res_t res;
  fraction_t downloaded_fraction = {}; // Initialize to zero in case of failure

  // Parse the URL to get the path
  path = get_path_from_url(url);
  if (!path) {
    fprintf(stderr, "Invalid URL: %s\n", url);
    return 1; // Return failure
  }

  // Perform the HTTP GET request
  if (http_get(sfd, path, &res) != HTTP_SUCCESS) {
    fprintf(stderr, "Failed to download: %s\n", url);
    return 1;   // Return failure
  }

  // Parse the downloaded data into a fraction
  if (fraction_parse(res.data, res.size, &downloaded_fraction) != 0) {
    http_free(&res); // Free HTTP response
    return 1;        // Return failure
  }

  // If the user provided a fraction pointer, copy the result
  if (fraction) {
    *fraction = downloaded_fraction;
  }

  // Cleanup
  http_free(&res);

  return 0; // Return success
}

int fraction_parse(char *data, size_t size, fraction_t *fraction) {
  const size_t IV_SIZE = 16; // 16 bytes for the IV
  const size_t MAGIC_SIZE = sizeof(uint32_t);
  const size_t INDEX_SIZE = sizeof(uint32_t);
  const size_t CRC_SIZE = sizeof(uint32_t);
  const size_t HEADER_SIZE = MAGIC_SIZE + INDEX_SIZE + IV_SIZE + CRC_SIZE;

  // Ensure the data size is sufficient
  if (size < HEADER_SIZE) {
    return 1; // Failure: data size is too small
    }

    // Extract fields from data buffer with endianess handling
    uint32_t magic, index, crc;
    memcpy(&magic, data, MAGIC_SIZE);
    memcpy(&index, data + MAGIC_SIZE, INDEX_SIZE);
    memcpy(fraction->iv, data + MAGIC_SIZE + INDEX_SIZE, IV_SIZE);
    memcpy(&crc, data + MAGIC_SIZE + INDEX_SIZE + IV_SIZE, CRC_SIZE);

    // Convert from little-endian to host byte order if needed (for
    // little-endian systems, this is usually not required)
    magic = __bswap_32(magic);
    index = __bswap_32(index);
    crc = __bswap_32(crc);

    // Set the extracted values in the fraction structure
    fraction->magic = magic;
    fraction->index = index;
    fraction->crc = crc;

    // Check the magic number
    if (!check_magic(fraction->magic)) {
      return 1; // Failure: magic number does not match
    }

    // Allocate memory for fraction data
    size_t data_size = size - HEADER_SIZE;
    fraction->data = malloc(data_size);
    if (!fraction->data) {
      return 1; // Failure: memory allocation error
    }

    // Copy the remaining data
    memcpy(fraction->data, data + HEADER_SIZE, data_size);

    return 0; // Success
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
  printf("Magic: 0x%08x\n", fraction.magic);
  printf("Index: %u\n", fraction.index);
  printf("CRC: 0x%08x\n", fraction.crc);
  printf("IV: ");
  for (size_t i = 0; i < sizeof(fraction.iv); i++) {
    printf("%02x ", (unsigned char)fraction.iv[i]);
  }
  printf("\n\n");
}

void fraction_free(fraction_t *fraction) {
  free(fraction->data);
  fraction->magic = 0;
  fraction->index = 0;
  fraction->crc = 0;
}
