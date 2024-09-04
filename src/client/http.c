#include "http.h"
#include "sock.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/file.h>


const char *CONTENT_LENGTH = "Content-Length: ";
const char *GET_REQ_TEMPLATE =
    "GET %s HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
const char *POST_REQ_TEMPLATE =
    "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s\r\n\r\n";

/* Log a http_res_t */
void print_http_res(const http_res_t res) {
  printf("--[ STATUS CODE: %i ]--\n", res.status_code);
  printf("--[ REQUEST ]--\n%s\n--[ REQUEST ]--\n", res.request);
  printf("%s\n", res.data);
  puts("--[ END ]--");
}
int http_post(int sfd,const char* path,const char *host,const char *content_type, const char* parameters, http_res_t *res){

  ssize_t req;
  char buffer[HTTP_BUFFER_SIZE];
  char *http_str;
  const char *content_length_start, *status_code_start, *body_start;
  long content_length, header_length, received_length;


  buffer[HTTP_BUFFER_SIZE -1 ] = '\0';

  snprintf(buffer,1023,POST_REQ_TEMPLATE,path,host,content_type,strlen(parameters),parameters);

  res->request = buffer;

  req = send_request(sfd,buffer);
  if(req < 0){
     return HTTP_SOCKET_ERR;
  }
  ssize_t recv_bytes = recv_response(sfd,buffer,sizeof(buffer));
  if(recv_bytes < 0){
    return HTTP_INVALID_RESPONSE;
  }

    status_code_start = strstr(buffer, " ") + 1;
  res->status_code = strtol(status_code_start, NULL, 10);

  content_length_start = strstr(buffer, CONTENT_LENGTH) + strlen(CONTENT_LENGTH);
  content_length = strtol(content_length_start, NULL, 10);

  res->size = content_length;
  res->data = malloc(content_length);
  if (NULL == res->data) {
    return HTTP_OOM;
  }

  body_start = strstr(buffer, "\r\n\r\n") + 4;
  header_length = body_start - buffer;
  received_length = MIN(recv_bytes - header_length, content_length);
  memcpy(res->data, body_start, received_length);



  if (HTTP_VERBOSE) puts("Parsed response");
  if (HTTP_VERBOSE > 1) print_http_res(*res);

return HTTP_SUCCESS;
}

int http_get(int sfd, const char *path, http_res_t *res) {
  char request_buf[HTTP_BUFFER_SIZE]; // use separate buffer for the request
  char buf[HTTP_BUFFER_SIZE];

  const char *status_code_start, *content_length_start, *body_start;
  int bytes_read;
  long total_bytes, content_length, header_length, received_length, left_length;

  // ensure buffers are null terminated
  buf[HTTP_BUFFER_SIZE - 1] = 0;
  request_buf[HTTP_BUFFER_SIZE -1] = 0;

  // send request
  snprintf(request_buf, HTTP_BUFFER_SIZE-1, GET_REQ_TEMPLATE, path);
  send_request(sfd, request_buf);

  res->request = request_buf;
  if (HTTP_VERBOSE) puts("Sent GET request");

  if (HTTP_VERBOSE) puts("Receiving data");
  // receive response
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
  if (HTTP_VERBOSE) puts("Received data from server");

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

  if (header_length + content_length > total_bytes) {
    if (HTTP_VERBOSE) puts("Receiving left over data");
    left_length = content_length - received_length;
    recv_response(sfd, res->data + received_length, left_length);
  }
  if (HTTP_VERBOSE) puts("Parsed response");
  if (HTTP_VERBOSE > 1) print_http_res(*res);
  return HTTP_SUCCESS;
}


/* Perform a GET request to path and write the body to the file specified in f_path */
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

void http_free(http_res_t *res) {
    free(res->data);
    res->data = NULL;
    res->size = 0;
    res->status_code = 0;
}

// if this dont work DeLuks is to blame :)
int http_split_data(char* data, char* data_arr[], int maxlines) {
  int   lines_read  = 0;
  char* line        = "";
  char* tmp_str     = "";

  tmp_str = strdup(data);
  if (tmp_str == NULL) {
    fprintf(stderr, "[x] strdup failed to allocate memory\n");
    return -1;
  }

  line = strtok(tmp_str, "\n");
  while (line != NULL && lines_read < maxlines) {
    data_arr[lines_read] = malloc(strlen(line)+1);
    if (data_arr[lines_read] == NULL) {
      fprintf(stderr, "[x] malloc failed to allocate memory\n");
      free(tmp_str);
      return -1;
    }

    strcpy(data_arr[lines_read], line);
    line = strtok(NULL, "\n");
    lines_read++;
  }

  free(tmp_str);
  return lines_read;
}
