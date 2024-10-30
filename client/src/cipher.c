#include "../include/cipher.h"
#include "../include/fraction.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <string.h>

static void print_errors(void) { ERR_print_errors_fp(stderr); }

int base64_decode(const char *b64_input, unsigned char **output,
                  size_t *output_len) {
  BIO *bio, *b64;
  int decode_len;
  size_t len = strlen(b64_input);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(b64_input, len);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  *output = (unsigned char *)malloc(len);
  if (*output == NULL) {
    return -1;
  }

  decode_len = BIO_read(bio, *output, len);
  if (decode_len < 0) {
    free(*output);
    return -1;
  }

  *output_len = decode_len;
  BIO_free_all(bio);

  return 0;
}

ssize_t aes_decrypt(uint8_t *ciphertext, size_t ciphertext_len, uint8_t *key,
                       uint8_t *iv, uint8_t *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    print_errors();
    return -1;
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    print_errors();
    return -1;
  }

  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    print_errors();
    return -1;
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    print_errors();
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

EVP_PKEY *generate_rsa_private_key(void) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;

  pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (pctx == NULL) {
    print_errors();
    return NULL;
  }
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    print_errors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
    print_errors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
    print_errors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  EVP_PKEY_CTX_free(pctx);
  return pkey;
}

char *write_rsa_public_key(EVP_PKEY *pkey) {
  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    print_errors();
    return NULL;
  }

  if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
    print_errors();
    BIO_free(bio);
    return NULL;
  }

  char *pem_key = NULL;
  long pem_len = BIO_get_mem_data(bio, &pem_key);

  char *copy = malloc(pem_len + 1);
  if (copy == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    BIO_free(bio);
    return NULL;
  }

  memcpy(copy, pem_key, pem_len);
  copy[pem_len] = '\0';

  BIO_free(bio);
  return copy;
}

unsigned char *decrypt_rsa_oaep_evp(EVP_PKEY *pkey,
                                    const unsigned char *encrypted_data,
                                    size_t encrypted_data_len,
                                    size_t *decrypted_data_len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx) {
    print_errors();
    return NULL;
  }

  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    print_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Set RSA OAEP padding
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    print_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Set the OAEP label hashing algorithm to SHA-256
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
    print_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Determine buffer length for decrypted data
  if (EVP_PKEY_decrypt(ctx, NULL, decrypted_data_len, encrypted_data,
                       encrypted_data_len) <= 0) {
    print_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  unsigned char *decrypted_data = malloc(*decrypted_data_len);
  if (!decrypted_data) {
    fprintf(stderr, "Failed to allocate memory for decrypted data\n");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Perform decryption
  if (EVP_PKEY_decrypt(ctx, decrypted_data, decrypted_data_len, encrypted_data,
                       encrypted_data_len) <= 0) {
    print_errors();
    free(decrypted_data);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  return decrypted_data;
}
