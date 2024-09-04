#ifndef HTTP_H
#define HTTP_H

#include <stdlib.h>

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define HTTP_BUFFER_SIZE 1024

// error codes
#define HTTP_SUCCESS 0
#define HTTP_SOCKET_ERR 1
#define HTTP_INVALID_RESPONSE 2
#define HTTP_OOM 3

typedef struct {
    int status_code;
    char *data;
    size_t size;
} http_res_t;

int http_get(int sfd, const char *path, const char hostname[], http_res_t *res);
void http_free(http_res_t *res);

#endif
