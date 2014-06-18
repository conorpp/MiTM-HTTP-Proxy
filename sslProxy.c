

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utils.h"

SSL_CTX *ctx;
void proxyhttps(int clientfd);

int main(int argc, char* argv[]){
    
    if (argc < 4){
        printf("forgot port, cert, privkey\n");
        return 1;    
    }
    SSL_library_init();
    OpenSSL_add_all_algorithms();   /* load & register cryptos */
    SSL_load_error_strings();     /* load all error messages */
    ctx = SSL_CTX_new( SSLv23_server_method() );         /* create context */

    /* set the local certificate from CertFile */
    SSL_CTX_use_certificate_file(ctx, argv[2], SSL_FILETYPE_PEM);
    /* set the private key from KeyFile */
    SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM);
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) ){
        printf("private keey and cert don\'t match up\n");
        exit(2);
    }

    int sockfd = Listen(NULL,argv[1]);

    int newfd,r;
    while(1){
        int timeToSend = 0, connected = 0;
        printf("waiting for new connection...\n");
        newfd = accept(sockfd, NULL, NULL);
        proxyhttps(newfd);
    }

    return 0;
}




void proxyhttps(int clientfd){
    int timeToSend = 0, connected = 0, r=0;
    char buf[1024];
    char resp[1024];
    strcpy(resp, "<br><h1>Hello world</h1><br>");
    int rs0 = strlen(resp);
    char *resp1 = "HTTP/1.1 200 OK\n";
    int rs1 = strlen(resp1);
    char *resp2 = "Content-Type: text/html; charset=UTF-8\n";
    int rs2 = strlen(resp2);
    char resp3[1024];// = "Content-Length: 0\n";
    sprintf(resp3, "Content-Length: %d\n\n", rs0);
    int rs3 = strlen(resp3);
    
    SSL *ssl = SSL_new(ctx);  /* get new SSL state with context */
    printf("got new connection.  \n");

    int offset = 1;
    printf("%% CLEAR PROXY REQUEST %%\n");
    if( (r = read(clientfd, buf, 1000)) > 0){
        if (offset > 1024){
            printf("payload exceded allocated space\n");
            exit(4);
        }
        buf[r] = '\0';
        offset += r;
        printf("%s", buf);
    }
    if (1){
        printf("Connection Established.\n");
        char *inject = "HTTP/1.0 200 Connection established\r\n\r\n";
        write(clientfd, inject, strlen(inject));

        offset = 0;
        printf("SSL connecting . . .\n");

        SSL_set_fd(ssl, clientfd);    /* set connection to SSL state */
        SSL_accept(ssl);           /* start the handshaking */

        printf("SSL handshake finished. Reading content.\n");
        offset = 1;
        printf("%% SSL REQUEST %%\n");

        if((r = SSL_read(ssl, buf, 1024)) > 0){
            if (offset > 1024){
                printf("payload exceded allocated space\n");
                exit(4);
            }
            printf("%s", buf);
            timeToSend=1;
            /*if (buf[offset-1] == '\n'){
                buf[offset] = '\0';
                printf("    %s", &buf[1]);
                if (strncasecmp(&buf[1], "connect",7) == 0)
                    connected = 1;
                else if (strncasecmp(&buf[1], "get", 3) == 0)
                    timeToSend=1;
                else if ( buf[offset-2] == '\n' || buf[offset-2] == '\r')
                    break;
                offset = 1;
            }*/

        }

        fflush(stdout);
    }
    // send response
    if(timeToSend){
        printf("\nSending SSL Response.\n");
        if ( SSL_write(ssl, resp1, strlen(resp1)) <=0)
            ERR_print_errors_fp(stdout);
        printf("1\n");
        if ( SSL_write(ssl, resp2, strlen(resp2))<=0)
            ERR_print_errors_fp(stdout);
        printf("2\n");
        SSL_write(ssl, resp3, strlen(resp3));
        printf("3\n");
        //SSL_write(ssl, "\n", 1);
        //printf("4\n");
        SSL_write(ssl, resp, strlen(resp));
    }
    printf("closing connection\n");
    SSL_free(ssl);              /* release SSL state */
    close(clientfd);                /* close connection */


}











