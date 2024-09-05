#include "http.h"
#include "sock.h"
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <time.h>

const char *CONTENT_LENGTH_HEADER = "Content-Length: ";
const char *GET_REQ_TEMPLATE =
    "GET %s HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";

/* Log a http_res_t */
void print_http_res(const http_res_t res) {
  printf("--[ STATUS CODE: %i ]--\n", res.status_code);
  printf("--[ REQUEST ]--\n%s\n--[ REQUEST ]--\n", res.request);
  printf("%s\n", res.data);
  puts("--[ END ]--");
}

/* Parse HTTP status code */
long parse_http_status_code(const char *buf) {
  const char *status_code_start;
  char *endptr;
  long status_code;

  status_code_start = strstr(buf, " ") + 1;
  if (status_code_start == NULL) {
    return -HTTP_INVALID_RESPONSE;
  }
  status_code = strtol(status_code_start, &endptr, 10);
  if (endptr == status_code_start) {
    return -HTTP_INVALID_RESPONSE;
  }
  return status_code;
}

/* Parse HTTP content length header */
long parse_http_content_length(const char *buf) {
  const char *content_length_start;
  char *endptr;
  long content_length;

  content_length_start =
      strstr(buf, CONTENT_LENGTH_HEADER) + strlen(CONTENT_LENGTH_HEADER);

  content_length = strtol(content_length_start, &endptr, 10);
  if (endptr == content_length_start) {
    return -HTTP_INVALID_RESPONSE;
  }
  return content_length;
}

int http_get(int sfd, const char *path, http_res_t *res) {
  char request_buf[HTTP_BUFFER_SIZE]; // use separate buffer for the request
  char buf[HTTP_BUFFER_SIZE];

  const char *body_start;
  int bytes_read;
  long total_bytes, status_code, header_length, content_length, received_length,
      left_length;
  size_t req_buf_len;

  /* send request */
  snprintf(request_buf, HTTP_BUFFER_SIZE - 1, GET_REQ_TEMPLATE, path);
  req_buf_len = strlen(request_buf);

  if (send_request(sfd, request_buf) < 0) {
    perror("Error: failed to send request\n");
    return -HTTP_SOCKET_ERR;
  }
  if (HTTP_VERBOSE)
    puts("Sent GET request");

  /* receive response from server */
  if (HTTP_VERBOSE)
    puts("Receiving data");

  total_bytes = 0;
  while ((bytes_read = recv(sfd, buf + total_bytes,
                            HTTP_BUFFER_SIZE - 1 - total_bytes, 0)) > 0) {
    total_bytes += bytes_read;
    // add temporary null terminator
    buf[total_bytes] = 0;
    if (NULL != strstr(buf + total_bytes - bytes_read, "\r\n\r\n")) {
      // if we read all headers stop reading
      break;
    }

    if (total_bytes >= HTTP_BUFFER_SIZE - 1) {
      buf[HTTP_BUFFER_SIZE - 1] = 0;
      break;
    }
  }
  if (HTTP_VERBOSE)
    puts("Received data from server");

  /* Check if response starts with "HTTP" */
  if (memcmp(buf, "HTTP", 4)) {
    return -HTTP_INVALID_RESPONSE;
  }

  /* Parse status code */
  status_code = parse_http_status_code(buf);
  if (status_code < 0) {
    return -HTTP_INVALID_RESPONSE;
  }
  res->status_code = (int)status_code;

  /* Parse content length */
  content_length = parse_http_content_length(buf);
  if (content_length < 0) {
    return -HTTP_INVALID_RESPONSE;
  }
  res->size = (size_t)content_length;

  /* Parse the response body */
  res->data = malloc(res->size);
  if (res->data == NULL) {
    return -HTTP_OOM;
  }

  body_start = strstr(buf, "\r\n\r\n") + 4;
  header_length = body_start - buf;
  received_length = MIN(total_bytes - header_length, content_length);

  memcpy(res->data, body_start, received_length);

  if (header_length + content_length > total_bytes) {
    if (HTTP_VERBOSE)
      puts("Receiving left over data");
    left_length = content_length - received_length;
    if (recv_response(sfd, res->data + received_length, left_length) < 0) {
      perror("Failed to receive left over data\n");
      free(res->data);
      return -HTTP_SOCKET_ERR;
    }
  }

  res->request = malloc(req_buf_len);
  if (res->request == NULL) {
    free(res->data); // free previously allocated data
    return -HTTP_OOM;
  }
  strncpy(res->request, request_buf, req_buf_len - 1);

  if (HTTP_VERBOSE)
    puts("Parsed response");
  if (HTTP_VERBOSE > 1)
    print_http_res(*res);

  return HTTP_SUCCESS;
}

/* Perform a GET request to path and write the body to the file specified in
 * f_path */
int http_download_data_to_file(int sfd, const char *path, const char *f_path) {
  http_res_t res;
  FILE *file;
  int error;

  error = http_get(sfd, path, &res);
  if (error != HTTP_SUCCESS) {
    return error;
  }

  file = fopen(f_path, "w");
  if (file == NULL) {
    perror("Error: Failed to open file");
    http_free(&res);
    return -1;
  }

  if (fwrite(res.data, sizeof(char), res.size, file) != res.size) {
    perror("Error: Failed to write data to file");
    fclose(file);
    http_free(&res);
    return -2;
  }

  if (fclose(file) != 0) {
    perror("Error: Failed to close file");
    http_free(&res);
    return -3;
  }

  http_free(&res);
  return 0;
}

/* Properly free a http_res_t structure */
void http_free(http_res_t *res) {
  free(res->data);
  res->data = NULL;
  free(res->request);
  res->request = NULL;

  res->size = 0;
  res->status_code = 0;
  return;

}
