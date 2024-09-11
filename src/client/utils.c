#include "utils.h"

// if this dont work Skelly is to blame ;)
int split_fraction_links(char *data, char *data_arr[], int maxlines) {
  int lines_read = 0;
  char *line;

  // Use the input `data` directly, no need for strdup
  line = strtok(data, "\n");
  while (line != NULL && lines_read < maxlines) {
    data_arr[lines_read] = strdup(line);
    if (data_arr[lines_read] == NULL) {
      fprintf(stderr, "strdup failed to allocate memory\n");
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


char *get_path_from_url(const char *url) {
    const char *path_start = strstr(url, "://");
    if (!path_start) {
        perror("There was a error with the URL");
        return NULL;
    }

    path_start += 3; // Skip past "://"

    // Find the first '/' after the host part
    char *path = strchr(path_start, '/');
    if (!path) {
        perror("No string found!");
        return "";
    }

    return path;
}
