#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include "sock.h"
#include "http.h"

/* Networking constants */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

int main() {
  struct addrinfo hints, *ainfo;
  int sfd; // socket file descriptor
  http_res_t response;

  setup_hints(&hints);

  if (h_getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &ainfo) != 0) {
    return EXIT_FAILURE;
  }
  sfd = create_sock_and_conn(ainfo);
  if (sfd == -1) {
    return EXIT_FAILURE;
  }

  // make multuple requests using the same connection
  for (int i = 0; i < 10; ++i) {
    if (HTTP_SUCCESS != http_get(sfd, "/hello", &response)) {
      return EXIT_FAILURE;  
    }
    write(1, response.data, response.size);
    http_free(&response);
  }

  close(sfd);
  

  return EXIT_SUCCESS;
}
