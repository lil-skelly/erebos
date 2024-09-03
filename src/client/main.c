#include <sys/types.h>
#include <stdlib.h>

#include "sock.h"
/* Networking constants */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

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
