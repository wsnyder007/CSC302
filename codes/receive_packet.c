#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>

void main() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    int clientlen;
    char buf[1500];

    /* create a new socket */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    /* create a data structure containing information about the server to be bound to the socket */
    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(9090);

    if (bind(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }

    /* the server receives and processes UDP packets through the socket */
    while (1) {
        bzero(buf, 1500);        
        recvfrom(sock, buf, 1500-1, 0, 
               (struct sockaddr *) &client, &clientlen);
        printf("%s\n", buf);
    }
    close(sock);
}
