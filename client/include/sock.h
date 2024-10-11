#ifndef SOCK_H
#define SOCK_H

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int create_sock_and_conn(struct addrinfo *res);
void setup_hints(struct addrinfo *hints);
ssize_t sock_recv_bytes(int sfd, char *buffer, size_t buffer_size);
ssize_t sock_send_string(int sfd, const char *request);
int sock_connect(int sfd, struct addrinfo *res);
int create_socket(struct addrinfo *res);
int h_getaddrinfo(const char *ip, const char *port, struct addrinfo *hints,
                  struct addrinfo **res);
#endif // SOCK_H
