#include "http.h"
#include "sock.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

const char *CONTENT_LENGTH = "Content-Length: ";
const char *GET_REQ_TEMPLATE =
    "GET %s HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";

int http_get(int sfd, const char *path, http_res_t *res) {
  char buf[HTTP_BUFFER_SIZE];
  const char *status_code_start, *content_length_start, *body_start;
  size_t total_bytes;
  int bytes_read;
  size_t content_length, header_length, received_length, left_length;

  buf[HTTP_BUFFER_SIZE - 1] = 0; // ensure buf is null terminated
  
  snprintf(buf, HTTP_BUFFER_SIZE-1, GET_REQ_TEMPLATE, path);
  send_request(sfd, buf);

  total_bytes = 0;
  while ((bytes_read = recv(sfd, buf + total_bytes, HTTP_BUFFER_SIZE - 1 - total_bytes, 0)) > 0) {
    total_bytes += bytes_read;
    // add temporary null terminator
    buf[total_bytes] = 0;
    if (NULL != strstr(buf + total_bytes - bytes_read, "\r\n\r\n")) {
      // if we read all headers stop reading
      break;
    }

    if (total_bytes >= HTTP_BUFFER_SIZE - 1) break;
  }

  if (memcmp(buf, "HTTP", 4)) {
    return HTTP_INVALID_RESPONSE;
  }

  status_code_start = strstr(buf, " ") + 1;
  res->status_code = strtol(status_code_start, NULL, 10);

  content_length_start = strstr(buf, CONTENT_LENGTH) + strlen(CONTENT_LENGTH);
  content_length = strtol(content_length_start, NULL, 10);

  res->size = content_length;
  res->data = malloc(content_length);
  if (NULL == res->data) {
    return HTTP_OOM;
  }

  body_start = strstr(buf, "\r\n\r\n") + 4;
  header_length = body_start - buf;
  received_length = MIN(total_bytes - header_length, content_length);
  memcpy(res->data, body_start, received_length);

  if (total_bytes == header_length + content_length) puts("ah");
  if (header_length + content_length > total_bytes) {
    left_length = content_length - received_length;
    recv_response(sfd, res->data + received_length, left_length);
  }

  return HTTP_SUCCESS;
}

void http_free(http_res_t *res) {
    free(res->data);
    res->data = NULL;
    res->size = 0;
    res->status_code = 0;
}
