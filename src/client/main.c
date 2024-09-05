#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "http.h"
#include "sock.h"
#include "utils.h"

/* Networking constants */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

int main() {
  struct addrinfo hints, *ainfo;
  int sfd; // socket file descriptor
  char hostname[NI_MAXHOST];
  http_res_t http_fraction_res;

  /* Setup socket and initiate connection with the server */
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

  /* Get the fraction links */
  // http_init(&http_fraction_res);
  if (http_get(sfd, "/", &http_fraction_res) != HTTP_SUCCESS) {
    return EXIT_FAILURE;
  }
  // Count number of links
  int num_links = count_lines(http_fraction_res.data) + 1; // +1 for the last line if not ending with \n

  // Allocate memory for fraction links
  char **fraction_links = malloc(num_links * sizeof(char *));
  if (fraction_links == NULL) {
    fprintf(stderr, "malloc failed to allocate memory for fraction links\n");
    close(sfd);
    http_free(&http_fraction_res);
    return EXIT_FAILURE;
  }

  // Split the response data into lines
  int lines_read =
      split_fraction_links(http_fraction_res.data, fraction_links, num_links);
  if (lines_read < 0) {
    http_free(&http_fraction_res);
    free(fraction_links);
    close(sfd);
    return EXIT_FAILURE;
  }

  // Print the fraction links
  // TODO: Download each link to a file
  for (int i = 0; i < lines_read; i++) {
    printf("%s\n", fraction_links[i]);
    free(fraction_links[i]); // Free allocated memory for each line
  }

  /* Cleanup */
  freeaddrinfo(ainfo);
  close(sfd);
  http_free(&http_fraction_res);
  free(fraction_links);

  return EXIT_SUCCESS;
}
