#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include "sock.h"
#include "http.h"

/* Networking constants */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

// int get_fraction_links(int sfd, const char *path, char **fraction_links) {
//   http_res_t res;
//   int error;

//   error = http_get(sfd, "/", &res);
//   if (error != HTTP_SUCCESS) {
//     return error;
//   }
  


//   http_free(&res);
//   return 0;
// }

int main() {
  struct addrinfo hints, *ainfo;
  int sfd; // socket file descriptor

  char hostname[NI_MAXHOST];

  setup_hints(&hints);

  if (h_getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &ainfo) != 0) {
    return EXIT_FAILURE;
  }
  if (h_getnameinfo(ainfo, hostname, sizeof(hostname)) != 0) {
    return EXIT_FAILURE;
  }
  printf("Connecting to %s\n", hostname);

  sfd = create_sock_and_conn(ainfo);
  if (sfd == -1) {
    return EXIT_FAILURE;
  }

  http_download_data_to_file(sfd, "/", "resp.txt");

  close(sfd);
  freeaddrinfo(ainfo);
  return EXIT_SUCCESS;
}
