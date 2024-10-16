#include "../include/sock.h"
#include "../include/log.h"

/* Wrapper for getaddrinfo, handles error */
int h_getaddrinfo(const char *ip, const char *port, struct addrinfo *hints,
                  struct addrinfo **ainfo) {
  int res;
  res = getaddrinfo(ip, port, hints, ainfo);

  if (res != 0) {
    log_error("Error: getaddrinfo: %s", gai_strerror(res));
    return res;
  }
  return 0;
}

/* Create a socket and return the socket file descriptor */
int create_socket(struct addrinfo *ainfo) {
  int sfd;
  sfd = socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
  if (sfd == -1) {
    log_error("Error creating socket");
    return -1;
  }
  return sfd;
}


/* Wrapper for `send` to simplify sending requests */
ssize_t sock_send_string(int sfd, const char *request) {
  return send(sfd, request, strlen(request), 0);
}

/* Receive response by using consecutive recv calls to fill the buffer.
 * Returns the bytes read */
ssize_t sock_recv_bytes(int sfd, char *buffer, size_t buffer_size) {
  ssize_t total_bytes, bytes_recv;
  total_bytes = 0;

  while ((bytes_recv = recv(sfd, buffer + total_bytes,
                            buffer_size - total_bytes, 0)) > 0) {
    total_bytes += bytes_recv;
    if (total_bytes >= (ssize_t)buffer_size)
      break; // avoid buffer overflow :P
  }
  if (bytes_recv == -1) {
    log_error("Error receiving response");
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
int sock_connect(int sfd, struct addrinfo *ainfo) {
  if (connect(sfd, ainfo->ai_addr, ainfo->ai_addrlen) == -1) {
    log_error("Error connecting socket");
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
