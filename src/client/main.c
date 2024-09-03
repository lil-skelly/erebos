#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include "http.h"
/* Networking constants */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "8000"

int main() {
  http_res_t response;
  if (HTTP_SUCCESS != http_get(SERVER_IP, SERVER_PORT, "/hello", &response)) {
    return EXIT_FAILURE;  
  }

  write(1, response.data, response.size);
  return EXIT_SUCCESS;
}
