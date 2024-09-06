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

#define HTTP_VERBOSE 0

typedef struct {
    int status_code;
    char *request; // The actual request (for book keeping)
    char *data;
    size_t size;
} http_res_t;

int   http_get(int sfd, const char *path, http_res_t *res);
void  http_free(http_res_t *res);
int   http_download_data_to_file(int sfd, const char *path, const char *f_path);
int   http_split_data(char* data, char* data_arr[], int maxlines);
int   http_post(int sfd,const char* path,const char *host,const char *content_type, const char* parameters, http_res_t *res);
int download_to_memory(int sfd,char **links,int n_links,char **bytes_array);
#endif
