#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sock.h"

// error codes
#define HTTP_SUCCESS 0
#define HTTP_SOCKET_ERR -1
#define HTTP_INVALID_RESPONSE -2
#define HTTP_OOM -3
#define HTTP_HEADERS_TOO_LONG -4

#define HTTP_VERBOSE 1

typedef struct {
    int status_code;
    char *request; // The actual request (for book keeping)
    char *data;
    size_t size;
} http_res_t;

void  http_free(http_res_t *res);

int   http_get(int sfd, const char *path, http_res_t *res);
int   http_post(int sfd,const char* path,const char *content_type, const char* parameters, http_res_t *res);

int   download_to_memory(int sfd,char **links,int n_links,char **bytes_array);

long  parse_http_status_code(const char *buf);
long  parse_http_content_length(const char *buf);
  
#endif // HTTP_H
