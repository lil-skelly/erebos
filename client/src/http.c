#include "../include/http.h"
#include <stddef.h>

#define HTTP_BUFFER_SIZE 1024

const char *CONTENT_LENGTH_HEADER = "Content-Length: ";
const char *GET_REQ_TEMPLATE =
    "GET %s HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
const char *POST_REQ_TEMPLATE =
    "POST %s HTTP/1.1\r\n"
    "Host: localhost\r\n" // Add the host
    "Content-Type: %s\r\n"
    "Content-Length: %d\r\n"
    "Connection: Keep-Alive\r\n" // Optionally, close connection after request
    "\r\n%s";               // Ensure the body follows after \r\n\r\n

// forward declare helper functions and leave them at the end
static long parse_http_status_code(const char *buf);
static long parse_http_content_length(const char *buf);
static int recv_http_body(int sfd, const char *src, char *dest,
                          long content_length, long total_bytes);
static size_t recv_headers(int sfd, char *buf, size_t buf_size);
static int process_response_headers(int sfd, const char *buf,
                                    size_t total_bytes, http_res_t *res);
static int do_request(int sfd, const char *request_buf, http_res_t *res);

int http_post(int sfd, const char *path, const char *content_type,
              const char *body, http_res_t *res) {
  char req_buffer[HTTP_BUFFER_SIZE];

  snprintf(req_buffer, HTTP_BUFFER_SIZE, POST_REQ_TEMPLATE, path, content_type,
           strlen(body), body);

  return do_request(sfd, req_buffer, res);
}

int http_get(int sfd, const char *path, http_res_t *res) {
  char request_buf[HTTP_BUFFER_SIZE]; // use separate buffer for the request
  
  snprintf(request_buf, HTTP_BUFFER_SIZE, GET_REQ_TEMPLATE, path);
  
  return do_request(sfd, request_buf, res);
}

/* Properly free a http_res_t structure */
void http_free(http_res_t *res) {
  free(res->data);
  res->data = NULL;
  free(res->request);
  res->request = NULL;

  res->size = 0;
  res->status_code = 0;
}

/* Parse HTTP status code */
static long parse_http_status_code(const char *buf) {
  const char *status_code_start;
  char *endptr;
  long status_code;

  status_code_start = strstr(buf, " ");
  if (status_code_start == NULL) {
    return HTTP_INVALID_RESPONSE;
  }
  status_code_start +=1;

  status_code = strtol(status_code_start, &endptr, 10);
  if (endptr == status_code_start) {
    return HTTP_INVALID_RESPONSE;
  }
  return status_code;
}

/* Parse HTTP content length header */
static long parse_http_content_length(const char *buf) {
  const char *content_length_start;
  char *endptr;
  long content_length;

  content_length_start = strstr(buf, CONTENT_LENGTH_HEADER);

  if (content_length_start == NULL) {
    return HTTP_INVALID_RESPONSE;
  }

  content_length_start += strlen(CONTENT_LENGTH_HEADER);

  content_length = strtol(content_length_start, &endptr, 10);
  if (endptr == content_length_start) {
    return HTTP_INVALID_RESPONSE;
  }
  return content_length;
}

/* Parse HTTP response body */
static int recv_http_body(int sfd, const char *src, char *dest,
                          long content_length, long total_bytes) {
  const char *body_start;
  long header_length, received_length, left_length;

  body_start = strstr(src, "\r\n\r\n");
  if (body_start == NULL) {
    log_error("Header delimeter not found");
    return HTTP_INVALID_RESPONSE;
  }
  body_start += 4;

  header_length = body_start - src;

  received_length = total_bytes - header_length;

  memcpy(dest, body_start, received_length);

  if (content_length > received_length) {
    left_length = content_length - received_length;
    ssize_t bytes_received =
        sock_recv_bytes(sfd, dest + received_length, left_length);
    if (bytes_received < 0) {
      log_error("Failed to receive left over data");
      return HTTP_SOCKET_ERR;
    }
    received_length += bytes_received;
  }

  dest[received_length] = '\0';
  return HTTP_SUCCESS;
}

static size_t recv_headers(int sfd, char *buf, size_t buf_size) {
  size_t bytes_read;
  size_t total_bytes = 0;
  while ((bytes_read = recv(sfd, buf + total_bytes, buf_size - 1 - total_bytes,
                            0)) > 0) {
    total_bytes += bytes_read;
    // add temporary null terminator to make strstr stop
    buf[total_bytes] = '\0';
    if (strstr(buf + total_bytes - bytes_read, "\r\n\r\n") != NULL) {
      // if we read all headers stop reading
      break;
    }

    if (total_bytes >= buf_size - 1) {
      // if this has happened it means we could not read all headers into buf
      // we should return some error here
      return HTTP_HEADERS_TOO_LONG;
    }
  }

  // by this time buf will be null terminated
  return total_bytes;
}

static int process_response_headers(int sfd, const char *buf,
                                    size_t total_bytes, http_res_t *res) {
  long status_code, content_length;
  int ret;

  /* Check if response starts with "HTTP" */
  if (memcmp(buf, "HTTP", 4)) {
    return HTTP_INVALID_RESPONSE;
  }

  /* Parse status code */
  status_code = parse_http_status_code(buf);
  if (status_code < 0) {
    return HTTP_INVALID_RESPONSE;
  }
  res->status_code = (int)status_code;

  /* Parse content length */
  content_length = parse_http_content_length(buf);
  if (content_length < 0) {
    return HTTP_INVALID_RESPONSE;
  }
  res->size = (size_t)content_length;

  /* Parse the response body */
  // we null terminate data even if not necessary
  // since we have its size
  // this helps using string functions on ASCII data
  res->data = malloc(res->size + 1);
  if (res->data == NULL) {
    return HTTP_OOM;
  }

  ret = recv_http_body(sfd, buf, res->data, content_length, total_bytes);
  if (ret < 0) {
    free(res->data);
    return ret;
  }

  return HTTP_SUCCESS;
}

static int do_request(int sfd, const char *request_buf, http_res_t *res) {
  char buffer[HTTP_BUFFER_SIZE];
  long total_bytes;
  size_t req_buf_len;
  int ret;

  req_buf_len = strlen(request_buf);

  if (sock_send_string(sfd, request_buf) < 0) {
    log_error("Error: failed to send request");
    return HTTP_SOCKET_ERR;
  }

  res->request = malloc(req_buf_len + 1);
  if (res->request == NULL) {
    return HTTP_OOM;
  }
  strncpy(res->request, request_buf, req_buf_len + 1);

  /* Receive response from server */
  total_bytes = recv_headers(sfd, buffer, HTTP_BUFFER_SIZE);
  if (total_bytes < 0) {
    free(res->request);
    return total_bytes;
  }

  ret = process_response_headers(sfd, buffer, total_bytes, res);
  if (ret < 0) {
    free(res->request);
    return ret;
  }

  log_debug("Received body from server");

  return HTTP_SUCCESS;
}
