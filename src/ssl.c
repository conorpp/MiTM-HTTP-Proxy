#include "ssl.h"
#include "http.h"


void SSL_Init(char *certFile, char* privKeyFile){
    SSL_library_init();
    OpenSSL_add_all_algorithms();   
    SSL_load_error_strings();     
    SSL_SERVER_HANDLE = SSL_CTX_new( SSLv23_server_method() );
    
    if (SSL_SERVER_HANDLE == NULL)
        ERR_print_errors_fp(stderr);

    SSL_CTX_use_certificate_file(SSL_SERVER_HANDLE, certFile,
                                SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(SSL_SERVER_HANDLE, privKeyFile,
                                SSL_FILETYPE_PEM);
      
    if ( !SSL_CTX_check_private_key(SSL_SERVER_HANDLE)){
        printf("Private key %s and CA %s don\'t match up\n",
                            privKeyFile, certFile);
        exit(2);
    }
}

void SSLWrap(void *http, int flags){
    HttpTransaction* T = (HttpTransaction*) http;
    T->is_ssl = 1;    
    if (IS_SSL_ACCEPT(flags)){
        char *connected = "HTTP/1.0 200 Connection established\r\n\r\n";
        write(T->socket, connected, strlen(connected));
        T->SSL = SSL_Accept(T->socket);
    }else{
        T->SSL = SSL_Connect(T->socket);
    }
    T->store = newHttpStore(HTTPS | flags);
}

SSL_Connection* SSL_Connect(int sockfd){
    SSL_Connection* sslcon = malloc(sizeof(SSL_Connection));
    if (sslcon == (SSL_Connection*) 0)
        die("SSL_Connection: malloc returned NULL");
    
    sslcon->handle = SSL_CTX_new(SSLv23_client_method());
    
//    BIO* sbio = BIO_new(BIO_s_socket());

    if (sslcon->handle == (SSL_CTX*) 0)
        ERR_print_errors_fp (stderr);
    
    sslcon->socket = SSL_new(sslcon->handle);
    if (sslcon->socket == (SSL*) 0)
        ERR_print_errors_fp (stderr);
//    
//    if ( BIO_set_fd(sbio, sockfd, BIO_NOCLOSE) != 1 )
//        ERR_print_errors_fp (stderr);
    
//    SSL_set_bio(sslcon->socket, sbio, sbio);

    SSL_set_fd(sslcon->socket, sockfd);

    if (SSL_connect(sslcon->socket) != 1)
        ERR_print_errors_fp (stderr);
    
    return sslcon;
}


SSL_Connection* SSL_Accept(int sockfd){
    SSL_Connection* sslcon = malloc(sizeof(SSL_Connection));
    
    sslcon->handle = SSL_SERVER_HANDLE;
    sslcon->socket = SSL_new(sslcon->handle);
//    BIO* sbio=BIO_new(BIO_s_socket());   
    
    if (sslcon->socket == (SSL*) 0)
        ERR_print_errors_fp (stderr);
    
//    if ( BIO_set_fd(sbio, sockfd, BIO_NOCLOSE) != 1 )
//        ERR_print_errors_fp (stderr);

//    SSL_set_bio(sslcon->socket, sbio, sbio);
    SSL_set_fd(sslcon->socket, sockfd);

    if (SSL_accept(sslcon->socket) != 1)
        ERR_print_errors_fp (stderr);

    return sslcon;
}


void SSL_Close(SSL_Connection* sslcon){
    if (sslcon != (SSL_Connection*) 0){
        SSL_shutdown(sslcon->socket);
        SSL_free(sslcon->socket);
        // The Server handle is reusable.
        if (sslcon->handle != SSL_SERVER_HANDLE)
            SSL_CTX_free(sslcon->handle);
        free(sslcon);
    }
}




