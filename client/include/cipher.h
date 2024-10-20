#ifndef CIPHER_H
#define CIPHER_H

#include <stdio.h>
#include <stdint.h>
#define OPENSSL_API_COMPAT 30000

#include "../include/fraction.h"

#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

extern uint8_t aes_key[32];

ssize_t cipher_decrypt(uint8_t *ciphertext, size_t ciphertext_len, uint8_t *key,
                      uint8_t *iv, uint8_t *plaintext);

/* RSA related functions */
EVP_PKEY *generate_rsa_private_key(void);
char *write_rsa_public_key(EVP_PKEY *pkey);
unsigned char *decrypt_rsa_oaep_evp(
    EVP_PKEY *pkey, const unsigned char *encrypted_data,
    size_t encrypted_data_len,
    size_t *decrypted_data_len);

/* Base64 encoding */
int base64_decode(
  const char *b64_input,  
  unsigned char **output,
  size_t *output_len
);
#endif
