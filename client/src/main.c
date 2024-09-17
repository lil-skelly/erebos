#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/fraction.h"
#include "../include/http.h"
#include "../include/sock.h"
#include "../include/utils.h"

/* Networking constants */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

int main(void) {
  struct addrinfo hints, *ainfo;
  int sfd; // socket file descriptor
  http_res_t http_fraction_res, http_post_res;

  /* Setup socket and initiate connection with the server */
  setup_hints(&hints);

  if (h_getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &ainfo) != 0) {
    fprintf(stderr, "Failed to resolve server address\n");
    return EXIT_FAILURE;
  }


  printf("Connecting to: %s:%s\n", SERVER_IP, SERVER_PORT);
  sfd = create_sock_and_conn(ainfo);
  if (sfd == -1) {
    fprintf(stderr, "Failed to create socket and connect\n");
    return EXIT_FAILURE;
  }
  freeaddrinfo(ainfo); // ainfo no longer needed

  /* Get the fraction links */
  if (http_get(sfd, "/", &http_fraction_res) != HTTP_SUCCESS) {
    fprintf(stderr, "Failed to retrieve fraction links\n");
    goto cleanup_socket;
  }

  // Count number of links
  int num_links = count_lines(http_fraction_res.data) + 1;

  // Allocate memory for fraction links
  char **fraction_links = malloc(num_links * sizeof(char *));
  if (!fraction_links) {
    fprintf(stderr, "Failed to allocate memory for fraction links\n");
    http_free(&http_fraction_res);
    goto cleanup_socket;
  }

  // Split the response data into lines
  int lines_read =
      split_fraction_links(http_fraction_res.data, fraction_links, num_links);
  if (lines_read < 0) {
    fprintf(stderr, "Failed to split fraction links\n");
    free(fraction_links);
    http_free(&http_fraction_res);
    goto cleanup_socket;
  }

  // Storing the fractions in a array
  fraction_t *fractions = malloc(lines_read * sizeof(fraction_t));
  if (fractions == NULL) {
    fprintf(stderr, "Failed to malloc memory for fractions\n");
  }

  for (int i=0; i<lines_read; i++) {
    if (download_fraction(sfd, fraction_links[i], &fractions[i]) != 0) {
      fprintf(stderr, "Failed to parse fraction\n");
    }
  }

  // Sort the fractions based on index
  qsort(fractions, lines_read, sizeof(fraction_t), compare_fractions);
  for (int i = 0; i < lines_read; i++) {
    print_fraction(fractions[i]);
  }

  /* Notify the server that we successfully downloaded the fractions */
  if (http_post(sfd, "/deadbeef", "plain/text", "{'downloaded':true}",
                &http_post_res) != HTTP_SUCCESS) {
    fprintf(stderr, "Failed to send POST request\n");
    free(fraction_links);
    http_free(&http_fraction_res);
    http_free(&http_post_res);
    goto cleanup_socket;
  }

  /* Cleanup */
  http_free(&http_fraction_res);
  http_free(&http_post_res);

  // Free fractions and links
  for (int i = 0; i < lines_read; i++) {
    free(fraction_links[i]);
    fraction_free(&fractions[i]);
  }
  free(fraction_links);
  free(fractions);

  close(sfd);
  return EXIT_SUCCESS;

cleanup_socket:
  close(sfd);
  return EXIT_FAILURE;
}
