#ifndef HTTP_H
#define HTTP_H

#include <stdlib.h>

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

int http_get(const char *ip, const char *port, const char *path, http_res_t *res);
void http_free(http_res_t *res);

#endif