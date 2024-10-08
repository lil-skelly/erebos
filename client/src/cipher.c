#include "../include/cipher.h"
#include "../include/fraction.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>

decrypted decryptedstr;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
decrypted *decrypt_fraction(fraction_t *fraction){

  size_t decrypted_size;

 unsigned char key[32] = {
    0x6d, 0x46, 0x75, 0x32, 0x4c, 0x2f, 0x69, 0x34, 0x78, 0x65, 0x76, 0x4a,
    0x34, 0x4e, 0x33, 0x36, 0x72, 0x44, 0x74, 0x35, 0x35, 0x5a, 0x4f, 0x34,
    0x35, 0x4b, 0x63, 0x72, 0x6e, 0x30, 0x75, 0x57
};

 unsigned char *decryptedtext = malloc(fraction->data_size+1);

  if (decryptedtext == NULL) {
        fprintf(stderr, "Cannot assign memory for the decrypted text.\n");
        return NULL;
    }

    decrypted_size = decrypt((unsigned char*)fraction->data, fraction->data_size, key, (unsigned char*) fraction->iv, decryptedtext);

    decryptedstr.decryptedtext = decryptedtext;
    decryptedstr.text_size = decrypted_size;


    return &decryptedstr;
}

char *generate_publickey(void){

  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;

  pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if(pctx == NULL){
    handleErrors();
    return NULL;
  }
  if(EVP_PKEY_keygen_init(pctx) <= 0){
    handleErrors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  if(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0){
    handleErrors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  if(EVP_PKEY_generate(pctx, &pkey) <= 0){
    handleErrors();
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  EVP_PKEY_CTX_free(pctx);

  BIO *bio = BIO_new(BIO_s_mem());

  if(PEM_write_bio_PUBKEY(bio,pkey) <= 0){
    handleErrors();
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return NULL;
  }

  char *pem_key = NULL;
  long pem_len = BIO_get_mem_data(bio,&pem_key);

  BIO_free(bio);

return pem_key;
}
