#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"
int checkCertificate(SSL* ssl);
void serverShutdown(int sock, int s, SSL *ssl, SSL_CTX *ctxSSL);

int main(int argc, char **argv) {
    int s, sock, port = PORT;
    struct sockaddr_in sin;
    int val = 1;
    pid_t pid;

    /* initialize SSL context */
    char CertFile[] = "568ca.pem";
    char KeyFile[] = "bob.pem";

    // for testing
//    char CertFile[] = "ca_cert.pem";
//    char KeyFile[] = "server_cert.pem";

    const SSL_METHOD *method;
    SSL_CTX *ctx;


    SSL_library_init();
    OpenSSL_add_all_algorithms();

    //Test
    //method =  (SSL_METHOD *)SSLv2_server_method();
    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);


    if (ctx == NULL) {
        fprintf(stderr, "ctx is NULL\n");
        ERR_print_errors_fp(stderr);
        //abort();
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");

    //Test
    //SSL_CTX_set_cipher_list(ctx, "  ALL:!SHA1");

    if (SSL_CTX_load_verify_locations(ctx, CertFile, NULL) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);


    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "certificate file is not correctly set\n");
        ERR_print_errors_fp(stderr);
        //abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "password");
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "Private key file is not correctly set\n");
        ERR_print_errors_fp(stderr);
        //abort();
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        //abort();
    }
    /* End of initialize SSL context*/


    /*Parse command line arguments*/
    switch (argc) {
        case 1:
            break;
        case 2:
            port = atoi(argv[1]);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s port\n", argv[0]);
            exit(0);
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        close(sock);
        exit(0);
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    if (bind(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("bind");
        close(sock);
        exit(0);
    }

    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        exit(0);
    }


    while(1){
        if ((s = accept(sock, NULL, 0)) < 0) {
            perror("accept");
            close(sock);
            close(s);
            exit(0);
        }

        // Fork a child to handle the connection
        if((pid=fork())){
            //Parent Process
            close(s);
        }
        else {
            //initializing SSL Connection
            SSL *ssl;
            ssl = SSL_new(ctx);
            //set BIO
            BIO * bio = BIO_new_socket(s, BIO_NOCLOSE);
            if (bio == NULL){
                printf( "bio = NULL.\n");
                serverShutdown(sock, s, ssl, ctx);
            }
            SSL_set_bio(ssl, bio, bio);

            //Handshake
            int sslAccept = SSL_accept(ssl);
            if (  sslAccept <= 0 ) {
                // if handshake failed
                printf("handshake failed\n");
                printf(FMT_ACCEPT_ERR);
                ERR_print_errors_fp(stdout);
                serverShutdown(sock,s, ssl, ctx);
            }
            else{
                // handshake successful
                printf("connected\n");

                //check certificate and print out the required information
                checkCertificate(ssl);

                char buf[256];
                //try to read the content from client
                if (SSL_read(ssl, &buf, 255) <=0){
                    // if read failed
                    if (SSL_get_error(ssl, sslAccept) == SSL_ERROR_SYSCALL){
                        printf(FMT_INCOMPLETE_CLOSE);
                    }
                    else if (SSL_get_error(ssl, sslAccept) == SSL_ERROR_ZERO_RETURN){
                        printf( FMT_INCOMPLETE_CLOSE);
                    }
                    else {
                        printf("read check\n");
                        printf(FMT_INCOMPLETE_CLOSE);
                    }
                    serverShutdown(sock,s, ssl, ctx);
                }
//testing
//                while(1){
//
//                }
                //try to write the content to client
                char *answer = "42";
                if (SSL_write(ssl, answer, strlen(answer)) <= 0){
                    //if write failed
                    if (SSL_get_error(ssl, sslAccept) == SSL_ERROR_SYSCALL){
                        printf(FMT_INCOMPLETE_CLOSE);}
                    else if (SSL_get_error(ssl, sslAccept) == SSL_ERROR_ZERO_RETURN){
                        printf( FMT_INCOMPLETE_CLOSE);
                    }
                    else {
                        printf("write check\n");
                        printf(FMT_INCOMPLETE_CLOSE);
                    }
                    serverShutdown(sock, s, ssl, ctx);
                }
                else{
                    //if write  success, close the connection
                    fprintf(stdout, FMT_OUTPUT, buf, answer);
                    serverShutdown(sock, s, ssl, ctx);
                }
            }
        }
    }
    return 0;
}


int checkCertificate(SSL* ssl)
{
    X509 *cert;
    char *line1 = malloc(256);
    char *line2 = malloc(256);
    X509_NAME *subjectName;
    char  subjectCn[256];
    int result = 1;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    subjectName = X509_get_subject_name(cert);


    if ( cert != NULL && SSL_get_verify_result(ssl) ==  X509_V_OK )
    {
        /* getting common name  tested */
        X509_NAME_get_text_by_NID(
                subjectName, NID_commonName, subjectCn, sizeof(subjectCn));
        memcpy(line1,subjectCn,256);

        /* getting email name  tested */
        int nid_email = OBJ_txt2nid("emailAddress");
        X509_NAME_get_text_by_NID(
                subjectName, nid_email, subjectCn, sizeof(subjectCn));
        memcpy(line2,subjectCn,256);

        printf(FMT_CLIENT_INFO, line1, line2);


    }
    else {
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
        result = 0;
    }
    X509_free (cert);
    free(line1);
    free(line2);
    return result;
}

void serverShutdown(int sock, int s, SSL *ssl, SSL_CTX *ctx){
    if(ssl != NULL){

        if (SSL_shutdown(ssl) == -1){
            //if it failed
            //printf("error\n");
            fprintf(stdout, FMT_INCOMPLETE_CLOSE);
        }
        if(SSL_shutdown(ssl) == 0){
            // The shutdown is not finished, call again
            //printf("waiting\n");
            shutdown(s, SHUT_WR);
            if (SSL_shutdown(ssl) == -1) fprintf(stdout, FMT_INCOMPLETE_CLOSE);

        }
        if(SSL_shutdown(ssl) == 1) printf("connection shut down\n");
        SSL_free(ssl);
    }
    else{
        printf("debug\n");
    }

    if (sock != -1){
        close(sock);
    }

    if (s != -1){
        close(s);
    }

    if (ctx != NULL){
        SSL_CTX_free(ctx);
    }

    exit (0);
}