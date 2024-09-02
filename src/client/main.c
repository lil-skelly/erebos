#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#define IP_ADDRESS "127.0.0.1"
#define PORT "8000"
#define MAX_LINKS 32


typedef struct {
    char **links;
    size_t count;
} LinkArray;

LinkArray get_files(const char *response) {
    const char *start;
    const char *end;

    LinkArray linkarr;
    linkarr.links = malloc(MAX_LINKS * sizeof(char *));
    if (linkarr.links == NULL) {
        perror("Failed malloc!");
        exit(EXIT_FAILURE);
    }
    linkarr.count = 0;

    start = strstr(response, "<a href=\"");
    while (start != NULL) {
        start += strlen("<a href=\"");
        end = strchr(start, '"');

        if (end != NULL) {
            ssize_t size = end - start;
            if (size > 0 && start[size - 1] == '/') {
                start = strchr(end, '<');
                if (start != NULL) {
                    start = strstr(start, "<a href=\"");
                }
                continue;
            }

            if (linkarr.count >= MAX_LINKS) {
                size_t new_size = MAX_LINKS * 2;
                linkarr.links = realloc(linkarr.links, new_size * sizeof(char *));
                if (linkarr.links == NULL) {
                    perror("Failed to reallocate memory");
                    exit(EXIT_FAILURE);
                }
                // Initialize new pointers to NULL
                for (size_t i = MAX_LINKS; i < new_size; i++) {
                    linkarr.links[i] = NULL;
                }
            }

            linkarr.links[linkarr.count] = malloc(size + 1);
            if (linkarr.links[linkarr.count] == NULL) {
                perror("Failed to allocate memory for link");
                exit(EXIT_FAILURE);
            }
            strncpy(linkarr.links[linkarr.count], start, size);
            linkarr.links[linkarr.count][size] = '\0';

            printf("Found link %s\n", linkarr.links[linkarr.count]);
            linkarr.count++;
        }

        start = strchr(end, '<');
        if (start != NULL) {
            start = strstr(start, "<a href=\"");
        } else {
            break;
        }
    }

    return linkarr;
}
void download_files(){

 // MAKE THE BUFFER BE DYNAMIC
 struct sockaddr_in sock_addr;
 struct addrinfo hints, *res, *p;
 char buffer[1024];
 char request[1024];

 char *msg = "GET /LICENSE HTTP/1.0\nHost:127.0.0.1\r\n\r\n";
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if(getaddrinfo(IP_ADDRESS,PORT, &hints, &res) != 0){
    perror("Error getting addrinfo");
    return ;
  };

  puts("Creating socket!\n");
  int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if(s == -1){
   perror("Error creating the socket");
   freeaddrinfo(res);
    return ;
  }

  puts("Connecting \n");
  int c = connect(s,res->ai_addr,res->ai_addrlen);

   if(c == -1){
   perror("Error connecting the socket");
   freeaddrinfo(res);
   return;
  }

  // INDEX REQUEST FOR FILE DOWNLOAD

  char *index = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";

  int bytes_send = send(s,index,strlen(index),0);
  int bytes_recv = recv(s,buffer,sizeof(buffer) - 1, 0);

  if(bytes_recv > 0){
      buffer[bytes_recv] = '\0';
  }

  get_files(buffer);

// IMPLEMENT DOWNLOADING THE FILES

  /*
FILE *fp = fopen("LICENSE","wb");
  if(fp == NULL){
  perror("Error opening file!");
  close(s);
  return;
  }



  fwrite(buffer,1,bytes_recv,fp);
 */
  freeaddrinfo(res);
  //fclose(fp);



}

int main(){

 download_files();
return 0;
}
