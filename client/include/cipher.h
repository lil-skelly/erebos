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
  unsigned char *decryptedtext;
  size_t text_size;
} decrypted;

decrypted *decrypt_fraction(fraction_t *fraction);
char *generate_publickey(void);
#endif
