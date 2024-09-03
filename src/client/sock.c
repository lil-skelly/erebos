#include "sock.h"
#include <netdb.h>
#include <stdlib.h>

/* Wrapper for getaddrinfo, handles error */
int h_getaddrinfo(const char *ip, const char *port, struct addrinfo *hints,
                  struct addrinfo **res) {
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
                            buffer_size - total_bytes, 0)) > 0) {
    total_bytes += bytes_recv;
    if (total_bytes >= (ssize_t)buffer_size)
      break; // avoid buffer overflow :P
  }
  if (bytes_recv == -1) {
    perror("Error receiving response");
  }
  return total_bytes;
}

/* Setup hints */
void setup_hints(struct addrinfo *hints) {
  memset(hints, 0, sizeof(*hints));
  hints->ai_family = AF_INET;
  hints->ai_socktype = SOCK_STREAM;
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

int create_sock_and_conn(struct addrinfo *res) {
  int sfd;

  sfd = create_socket(res);
  if (sfd == -1) {
    freeaddrinfo(res);
    return -1;
  }
  if (sock_connect(sfd, res) == -1) {
    freeaddrinfo(res);
    return -1;
  }

  return sfd;
}
