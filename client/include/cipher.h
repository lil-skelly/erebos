#ifndef cipher_h
#define cipher_h

#define OPENSSL_API_COMPAT 30000

#include "../include/fraction.h"

#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/pem.h>

typedef struct{
  unsigned char *decrypted_text;
  size_t text_size;
} decrypted_t;

decrypted_t *decrypt_fraction(fraction_t *fraction,unsigned char *key);
void decrypted_free(decrypted_t *decrypted);

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
