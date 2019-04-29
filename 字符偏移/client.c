#include <unistd.h>
#include <sys/types.h>       /* basic system data types */
#include <sys/socket.h>      /* basic socket definitions */
#include <netinet/in.h>      /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>       /* inet(3) functions */
#include <netdb.h>           /*gethostbyname function */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define MAXLINE 4096

void sockConnect(int connfd);
void handler(char *nptr);

int indx[41] = {17, 34, 35, 119, 124, 141, 147, 156, 197, 223, 240, 247, 285, 309, 311, 338, 370, 383, 404, 408, 445, 466, 483, 495, 498, 609, 615, 723, 736, 757, 784, 785, 858, 893, 900, 907, 917, 929, 940, 951, 981};
int len = 41;

int main(int argc, char **argv)
{
    char * servInetAddr = "172.31.19.13";
    int servPort = 9000;
    char buf[MAXLINE];
    int connfd;
    struct sockaddr_in servaddr;

    connfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(servPort);
    inet_pton(AF_INET, servInetAddr, &servaddr.sin_addr);

    if (connect(connfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("connect error");
        return -1;
    }
    sockConnect(connfd);     /* do it all */
    close(connfd);
    exit(0);
}

void sockConnect(int sockfd)
{
    char sendline[MAXLINE], recvline[MAXLINE];
    int n;
    strcpy(sendline, "Give Me Flag Plz!!!");
    n = write(sockfd, sendline, strlen(sendline));
    n = read(sockfd, recvline, MAXLINE);
    if (n == 0) {
        printf("网络出错，请联系管理区确认\n");
       exit(1); 
    }
    // write(STDOUT_FILENO, recvline, n);
    handler(recvline);
}


void handler(char *nptr){
    int i;
    char flag[60];
    int slen;
    int c = 0;
    slen = strlen(nptr);
    printf("/******************************************************************/\n");
    printf("\tLife is full with error... Just like this program \n");
    printf("\tBut may be you cound find what you want :) Good Luck \n");
    printf("/******************************************************************/\n");
    for(i=0; i<slen; i++){
        fflush(stdout);
        fflush(stderr);
        if (i == indx[c]){
            fprintf(stderr, "%c", nptr[i]);
            c += 1;
        }
        else{
            fprintf(stdout, "%c", nptr[i]);
        }
    }
}