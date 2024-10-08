#ifndef cipher_h
#define cipher_h

#include "../include/fraction.h"

#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


typedef struct{
  unsigned char *decryptedtext;
  size_t text_size;
} decrypted;

decrypted *decrypt_fraction(fraction_t *fraction);

#endif
