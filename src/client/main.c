#include <sys/types.h>
#include <stdlib.h>

#include "sock.h"
/* Networking constants */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"
#define MAX_LINKS 32

typedef struct {
  char **links;
  size_t count;
} LinkArray;

/* Parse an HTTP response to extract <a href=""> links */
LinkArray get_index_files(const char *response) {
  const char *start;
  const char *end;

  LinkArray linkarr;
  linkarr.links = malloc(MAX_LINKS * sizeof(char *));
  if (linkarr.links == NULL) {
    perror("Failed to allocate memory for links");
    exit(EXIT_FAILURE);
  }
  linkarr.count = 0;

  start = strstr(response, "<a href=\"");
  while (start != NULL) {
    start += strlen("<a href=\"");
    end = strchr(start, '"');

    if (end != NULL) {
      ssize_t size = end - start;
      if (size > 0 && start[size - 1] == '/') {
        start = strchr(end, '<');
        if (start != NULL) {
          start = strstr(start, "<a href=\"");
        }
        continue;
      }

      if (linkarr.count >= MAX_LINKS) {
        size_t new_size = MAX_LINKS * 2;
        linkarr.links = realloc(linkarr.links, new_size * sizeof(char *));
        if (linkarr.links == NULL) {
          perror("Failed to reallocate memory for links");
          exit(EXIT_FAILURE);
        }
        // Initialize new pointers to NULL
        for (size_t i = MAX_LINKS; i < new_size; i++) {
          linkarr.links[i] = NULL;
        }
      }

      linkarr.links[linkarr.count] = malloc(size + 1);
      if (linkarr.links[linkarr.count] == NULL) {
        perror("Failed to allocate memory for link");
        exit(EXIT_FAILURE);
      }
      strncpy(linkarr.links[linkarr.count], start, size);
      linkarr.links[linkarr.count][size] = '\0';

      printf("Found link %s\n", linkarr.links[linkarr.count]);
      linkarr.count++;
    }

    start = strchr(end, '<');
    if (start != NULL) {
      start = strstr(start, "<a href=\"");
    } else {
      break;
    }
  }

  return linkarr;
}

/* Parse http headers to figure out the responses content length */
int find_content_length(const char *response) {
  const char *content_length_s = strstr(response, "Content-Length:");
  if (content_length_s == NULL) return 0;
  return strtol(content_length_s + strlen("Content-Length: "), NULL, 10);
}


void request_download(int sfd) {
  char header_buffer[256];
  // INDEX REQUEST FOR FILE DOWNLOAD

  char *index = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
  puts("Sending hello HTTP request");
  if (send_request (sfd, index) == -1) {
    perror("Error sending request");
    goto error;
  }

  puts("Receiving headers");
  if (recv_response(sfd, header_buffer, sizeof(header_buffer)) <= 0) {
    perror("Error receiving response");
    goto error;
  }
  
  int content_length = find_content_length(header_buffer);
  if (content_length == 0) {
    perror("Failed to find Content-Length in response\n");
    goto error;
  }
  char *buffer = (char *)malloc(content_length);
  if (buffer == NULL) {
    perror("Failed to allocate memory for response buffer");
    exit(1);
  }
  puts("Receiving response");

  if (recv_response(sfd, buffer, strlen(buffer)) <= 0) {
    perror("Error receiving response");
    free(buffer);
    goto error;
  }
  get_index_files(buffer);

  // IMPLEMENT DOWNLOADING THE FILES
  free(buffer);

error:
  close(sfd);
  return;
}

int main() {
  struct addrinfo hints, *res;
  int sfd; // socket file descriptor

  setup_hints(&hints);

  if (h_getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &res) != 0) {
    return EXIT_FAILURE;
  }
  sfd = create_sock_and_conn(res);
  if (sfd == -1) {
    return EXIT_FAILURE;
  }

  request_download(sfd);

  return EXIT_SUCCESS;
}
