#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/* Helper to count new line characters in a string */
static inline int count_lines(const char *str) {
  int count = 0;
  while (*str) {
    if (*str == '\n') count++;
    str++;
  }
  return count;
}

static inline char *get_path_from_url(const char *url) {
  const char *path_start = strstr(url, "://");

  // If "://" is not found, return NULL
  if (!path_start)
    return NULL;

  path_start += 3; // Skip past "://"

  // Find the first '/' after the host part
  const char *path = strchr(path_start, '/');

  // If no path is found, return NULL
  return path ? (char *)path : NULL;
}

int split_fraction_links(char *data, char *data_arr[], int maxlines);
void print_hex(char *str);

#endif // UTILS_H
