#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

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

/* Wrapper for getaddrinfo, handles error */
int h_getaddrinfo(const char* ip, const char* port, struct addrinfo *hints, struct addrinfo **res) {
  int error;
  error = getaddrinfo(ip, port, hints, res);
  
  if (error != 0) {
    fprintf(stderr, "Error getting addrinfo: %s\n", gai_strerror(error));
    return error;
  }
  return 0;
}

/* Create a socket and return the socket file descriptor */
int create_socket(struct addrinfo *res) {
  int sfd;
  sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sfd == -1) {
    perror("Error creating socket");
    return -1;
  }
  return sfd;
}

/* Connect the socket to the server */
int sock_connect(int sfd, struct addrinfo *res) {
  if (connect(sfd, res->ai_addr, res->ai_addrlen) == -1) {
    perror("Error connecting socket");
    close(sfd);
    return -1;
  }
  return 0;
}

/* Wrapper for `send` to simplify sending requests */
ssize_t send_request(int sfd, const char *request) {
  return send(sfd, request, strlen(request), 0);
}

/* Receive response by using consecutive recv calls to fill the buffer.
 * Returns the bytes read */
ssize_t recv_response(int sfd, char *buffer, size_t buffer_size) {
  ssize_t total_bytes, bytes_recv;
  total_bytes = 0;
  
  while ((bytes_recv = recv(sfd, buffer + total_bytes,
                            buffer_size - total_bytes - 1, 0)) > 0) {
    total_bytes += bytes_recv;
    if (total_bytes >= (ssize_t)buffer_size - 1)
      break; // avoid buffer overflow :P
  }
  if (bytes_recv == -1) {
    perror("Error receiving response");
  }
  buffer[total_bytes] = '\0'; // Null-terminate the response
  return total_bytes;
}

/* Setup hints */
void setup_hints(struct addrinfo *hints) {
  memset(hints, 0, sizeof(*hints));
  hints->ai_family = AF_INET;
  hints->ai_socktype = SOCK_STREAM;
}

int create_sock_and_conn(struct addrinfo *res) {
  int sfd;

  sfd = create_socket(res);
  if (sfd == -1) {
    freeaddrinfo(res);
    return -1;
  }
  if (sock_connect(sfd, res) == -1) {
    freeaddrinfo(res);
    close(sfd); // close socket fd
    return -1;
  }

  return sfd;
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
  freeaddrinfo(res);
  if (sfd == -1) {
    return EXIT_FAILURE;
  }

  request_download(sfd);

  return EXIT_SUCCESS;
}
