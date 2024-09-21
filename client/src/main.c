#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/fraction.h"
#include "../include/http.h"
#include "../include/sock.h"
#include "../include/utils.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

/* Helper functions to assist with cleanup, I hate cleanup */
static void cleanup_char_array(char **array, int n_elem) {
  for (int i = 0; i < n_elem; i++) {
    free(array[i]);
  }
  free(array);
}

static void cleanup_fraction_array(fraction_t *array, int n_elem) {
  for (int i = 0; i < n_elem; i++) {
    fraction_free(&array[i]);
  }
  free(array);
}

int main(void) {
  struct addrinfo hints, *ainfo;
  int sfd = -1; // to be extra professional
  http_res_t http_fraction_res, http_post_res;
  char **fraction_links = NULL;
  fraction_t *fractions = NULL;

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
  freeaddrinfo(ainfo);

  if (http_get(sfd, "/", &http_fraction_res) != HTTP_SUCCESS) {
    fprintf(stderr, "Failed to retrieve fraction links\n");
    goto cleanup;
  }

  int num_links = count_lines(http_fraction_res.data) + 1;
  fraction_links = malloc(num_links * sizeof(char *));
  if (!fraction_links) {
    fprintf(stderr, "Failed to allocate memory for fraction links\n");
    http_free(&http_fraction_res);
    goto cleanup;
  }

  int lines_read =
      split_fraction_links(http_fraction_res.data, fraction_links, num_links);
  if (lines_read < 0) {
    fprintf(stderr, "Failed to split fraction links\n");
    cleanup_char_array(fraction_links, num_links);
    http_free(&http_fraction_res);
    goto cleanup;
  }


  fractions = malloc(lines_read * sizeof(fraction_t));
  if (!fractions) {
    fprintf(stderr, "Failed to allocate memory for fractions\n");
    cleanup_char_array(fraction_links, num_links);
    http_free(&http_fraction_res);
    http_free(&http_post_res);
    goto cleanup;
  }

  for (int i = 0; i < lines_read; i++) {
    if (download_fraction(sfd, fraction_links[i], &fractions[i]) != 0) {
      fprintf(stderr, "Failed to download fraction\n");
    }
  }
  puts("Downloaded fractions");
  
  qsort(fractions, lines_read, sizeof(fraction_t), compare_fractions);

  if (check_fractions(fractions, lines_read)) { // if this works, s0s4 and skelly is to blame!
    fprintf(stderr, "Fractions check failed\n");
    cleanup_char_array(fraction_links, num_links);
    cleanup_fraction_array(fractions, lines_read);
    http_free(&http_fraction_res);
    http_free(&http_post_res);
    goto cleanup;
  }
  puts("Verified fractions");
  
  if (http_post(sfd, "/deadbeef", "plain/text", "{'downloaded':true}",
                &http_post_res) != HTTP_SUCCESS) {
    fprintf(stderr, "Failed to send POST request\n");
    cleanup_char_array(fraction_links, num_links);
    http_free(&http_fraction_res);
    goto cleanup;
  }

  http_free(&http_fraction_res);
  http_free(&http_post_res);
  cleanup_char_array(fraction_links, num_links);
  cleanup_fraction_array(fractions, lines_read);

  close(sfd);
  return EXIT_SUCCESS;

/* There's nothing to see here, move on*/
cleanup: // we accept NO comments on this. have a !nice day
  if (sfd != -1) {
    close(sfd);
  }
  if (fraction_links) {
    cleanup_char_array(fraction_links, num_links);
  }
  if (fractions) {
    cleanup_fraction_array(fractions, num_links);
  }
  if (http_fraction_res.data) {
    http_free(&http_fraction_res);
  }
  if (http_post_res.data) {
    http_free(&http_post_res);
  }
  return EXIT_FAILURE;
}
