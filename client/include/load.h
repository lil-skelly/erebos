#define _GNU_SOURCE
#include <linux/module.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>

#include <dirent.h>
#include <string.h>
#include <stdlib.h>

#include "../include/log.h"


int load_lkm(const unsigned char* lkm, ssize_t total_size);
int is_lkm_loaded(const char *name);
int remove_lkm();

