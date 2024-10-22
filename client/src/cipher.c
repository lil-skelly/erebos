#include "../include/cipher.h"
#include "../include/fraction.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

static void handle_errors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

static int decrypt(unsigned char *ciphertext, int ciphertext_len,
                   unsigned char *key, unsigned char *iv,
                   unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handle_errors();

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handle_errors();

  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handle_errors();
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handle_errors();
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

decrypted_t *decrypt_fraction(fraction_t *fraction,unsigned char *key ) {

  size_t decrypted_size;

//    unsigned char key[32] = {0x6d, 0x46, 0x75, 0x32, 0x4c, 0x2f, 0x69, 0x34,
//    0x78, 0x65, 0x76, 0x4a, 0x34, 0x4e, 0x33, 0x36,
//    0x72, 0x44, 0x74, 0x35, 0x35, 0x5a, 0x4f, 0x34,
//    0x35, 0x4b, 0x63, 0x72, 0x6e, 0x30, 0x75, 0x57};

  unsigned char *decrypted_text = malloc(fraction->data_size);

  if (decrypted_text == NULL) {
    log_error("Cannot assign memory for the decrypted text");
    return NULL;
  }

  decrypted_size = decrypt((unsigned char *)fraction->data, fraction->data_size,
                           key, (unsigned char *)fraction->iv, decrypted_text);

  decrypted_t *decr = malloc(sizeof(decrypted_t));

  if (decr == NULL) {
    log_error("Could not allocate memory for decrypted struct");
    free(decrypted_text);
    return NULL;
  }

  decr->decrypted_text = decrypted_text;
  decr->text_size = decrypted_size;

  return decr;
}

void decrypted_free(decrypted_t *decrypted) {
  free(decrypted->decrypted_text);
  free(decrypted);
}

EVP_PKEY *generate_keypair(void) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;

  pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (pctx == NULL) {
    handle_errors();
    return NULL;
  }
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    handle_errors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
    handle_errors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
    handle_errors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  EVP_PKEY_CTX_free(pctx);
  return pkey;
}

char *write_public_key(EVP_PKEY *pkey) {
  BIO *bio = BIO_new(BIO_s_mem());
  if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
    handle_errors();
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return NULL;
  }

  char *pem_key = NULL;
  long pem_len = BIO_get_mem_data(bio, &pem_key);
  char *copy = malloc(pem_len + 1);
  memcpy(copy, pem_key, pem_len);
  copy[pem_len] = '\0';

  BIO_free(bio);
  return copy;
}

unsigned char *decrypt_msg(EVP_PKEY *pkey, unsigned char *in) {

  EVP_PKEY_CTX *ctx;
  ENGINE *eng;
  unsigned char *out;
  size_t outlen, inlen;
  EVP_PKEY *key;

  inlen = strlen((char *) in);

  ctx = EVP_PKEY_CTX_new(pkey, eng);
  if (!ctx) {
    handle_errors();
    return NULL;
  }
  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    handle_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    handle_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0) {
    handle_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  out = OPENSSL_malloc(outlen);
  if (!out) {
    handle_errors();
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0) {
    handle_errors();
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(out);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  return out;
}
