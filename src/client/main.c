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
  http_res_t http_post_res;

  /* Setup socket and initiate connection with the server */
  setup_hints(&hints);

  if (h_getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &ainfo) != 0) {
    return EXIT_FAILURE;
  }
  if (h_getnameinfo(ainfo, hostname, sizeof(hostname)) != 0) {
    return EXIT_FAILURE;
  }
  printf("Connecting to: %s\n", hostname);
  sfd = create_sock_and_conn(ainfo);
  if (sfd == -1) {
    return EXIT_FAILURE;
  }
  freeaddrinfo(ainfo); // we don't need these anymore

  /* Get the fraction links */
  if (http_get(sfd, "/", &http_fraction_res) != HTTP_SUCCESS) {
    goto err;
  }
  // Count number of links
  int num_links = count_lines(http_fraction_res.data) + 1; // +1 for the last line if not ending with \n
  
  // Allocate memory for fraction links
  char **fraction_links = malloc(num_links * sizeof(char *));
  if (fraction_links == NULL) {
    fprintf(stderr, "malloc failed to allocate memory for fraction links\n");
    http_free(&http_fraction_res);
    goto err;
  }

  // Split the response data into lines
  int lines_read =
      split_fraction_links(http_fraction_res.data, fraction_links, num_links);
  if (lines_read < 0) {
    http_free(&http_fraction_res);
    free(fraction_links);
    goto err;
  }

  // Print the fraction links
  // TODO: Download each link to a file
  for (int i = 0; i < lines_read; i++) {
    printf("%s\n", fraction_links[i]);
    free(fraction_links[i]); // Free allocated memory for each line
  }

  /* Tell the server that we successfully downloaded the fractions */
  if (http_post(sfd, "/deadbeef", "plain/text", "{'downloaded':true}", &http_post_res) != HTTP_SUCCESS) {
    http_free(&http_fraction_res);
    http_free(&http_post_res);

    free(fraction_links);
    
    goto err;
  }

  /* Cleanup */
  http_free(&http_fraction_res);
  http_free(&http_post_res);

  free(fraction_links);

  close(sfd);
  return EXIT_SUCCESS;

err:
  close(sfd);
  return EXIT_FAILURE;
}
