#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sock.h"
#include "utils.h"

#include "log.h"
// error codes
#define HTTP_SUCCESS 0
#define HTTP_SOCKET_ERR -1
#define HTTP_INVALID_RESPONSE -2
#define HTTP_OOM -3
#define HTTP_HEADERS_TOO_LONG -4

typedef struct {
    int status_code;
    char *request; // The actual request (for book keeping)
    char *data;
    size_t size;
} http_res_t;

void http_free(http_res_t *res);

int http_get(int sfd, const char *path, http_res_t *res);
/* Keeping in case we end up using it sometime */
int http_post(int sfd, const char* path, const char *content_type, const char* body, http_res_t *res);
  
#endif // HTTP_H
