#include "http.h"
#include "sock.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define HTTP_BUFFER_SIZE 1024

const char *CONTENT_LENGTH = "Content-Length: ";
const char *GET_REQ_TEMPLATE = "GET %s HTTP/1.1\r\n\r\n";

int http_get(const char *ip, const char *port, const char *path, http_res_t *res) {
  struct addrinfo hints, *ainfo;
  int sfd; // socket file descriptor
  char buf[HTTP_BUFFER_SIZE];
  const char *status_code_start, *content_length_start, *body_start;
  int content_length, header_length, received_length, left_length;
  int err;

  buf[HTTP_BUFFER_SIZE - 1] = 0; // ensure buf is null terminated
  sfd = -1;

  setup_hints(&hints);

  if (h_getaddrinfo(ip, port, &hints, &ainfo) != 0) {
    err = HTTP_SOCKET_ERR;
    goto cleanup;
  }
  sfd = create_sock_and_conn(ainfo);
  if (sfd == -1) {
    err = HTTP_SOCKET_ERR;
    goto cleanup;
  }
  snprintf(buf, 1023, GET_REQ_TEMPLATE, path);
  send_request(sfd, buf);

  recv_response(sfd, buf, HTTP_BUFFER_SIZE - 1);

  if (memcmp(buf, "HTTP", 4)) {
    err = HTTP_INVALID_RESPONSE;
    goto cleanup;
  }

  status_code_start = strstr(buf, " ") + 1;
  res->status_code = strtol(status_code_start, NULL, 10);

  content_length_start = strstr(buf, CONTENT_LENGTH) + strlen(CONTENT_LENGTH);
  content_length = strtol(content_length_start, NULL, 10);

  res->size = content_length;
  res->data = malloc(content_length);
  if (NULL == res->data) {
    err = HTTP_OOM;
    goto cleanup;
  }

  body_start = strstr(buf, "\r\n\r\n") + 4;
  header_length = body_start - buf;
  received_length = MIN(HTTP_BUFFER_SIZE - header_length, content_length);

  memcpy(res->data, body_start, received_length);

  if (header_length + content_length > HTTP_BUFFER_SIZE) {
    left_length = content_length - received_length;
    recv_response(sfd, res->data + received_length, left_length);
  }

  close(sfd);
  return HTTP_SUCCESS;

cleanup:
  if (sfd != -1) close(sfd);
  return err;
}

void http_free(http_res_t *res) {
    free(res->data);
}
