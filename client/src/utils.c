#include "../include/utils.h"
#include "../include/log.h"

// if this dont work Skelly is to blame ;)
int split_fraction_links(char *data, char *data_arr[], int maxlines) {
  int lines_read = 0;
  char *line;

  // Use the input `data` directly, no need for strdup
  line = strtok(data, "\n");
  while (line != NULL && lines_read < maxlines) {
    data_arr[lines_read] = strdup(line);
    if (data_arr[lines_read] == NULL) {
      log_error("strdup failed to allocate memory");
      // Free previously allocated lines in case of failure
      for (int i = 0; i < lines_read; i++) {
        free(data_arr[i]);
      }
      return -1;
    }
    lines_read++;
    line = strtok(NULL, "\n");
  }
  return lines_read;
}

void print_hex(const unsigned char *data, size_t size) {
  if (data == NULL) {
    log_error("Null data pointer\n"); // had to learn the hard f way
    return;
  }
  for (size_t i = 0; i < size; i++) {
    if (i%20==0) puts("");
    printf("%02X ", data[i]);

  }
  printf("\n");
}
