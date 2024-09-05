#include "utils.h"

// if this dont work DeLuks is to blame :) - it worked, kinda (skelly) :D
int split_fraction_links(char *data, char *data_arr[], int maxlines) {
  int lines_read = 0;
  char *line;

  char *tmp_str = strdup(data);
  if (tmp_str == NULL) {
    fprintf(stderr, "strdup failed to allocate memory\n");
    return -1;
  }

  line = strtok(tmp_str, "\n");
  while (line != NULL && lines_read < maxlines) {
    data_arr[lines_read] = malloc(strlen(line) + 1);
    if (data_arr[lines_read] == NULL) {
      fprintf(stderr, "malloc failed to allocate memory for data array\n");
      free(tmp_str);
      // Free previously allocated memory in case of failure
      for (int i = 0; i < lines_read; i++) {
        free(data_arr[i]);
      }
      return -1;
    }

    strcpy(data_arr[lines_read], line);
    line = strtok(NULL, "\n");
    lines_read++;
  }

  free(tmp_str);
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
