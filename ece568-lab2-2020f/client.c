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
#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"
int checkCertificate(SSL* ssl);
void client_shutdown(SSL* ssl, int sock);

int main(int argc, char **argv)
{
    int len, sock, port=PORT;
    char *host=HOST;
    struct sockaddr_in addr;
    struct hostent *host_entry;
    char buf[256];
    char *secret = "What's the question?";

    /*Parse command line arguments*/

    switch(argc){
        case 1:
            break;
        case 3:
            host = argv[1];
            port=atoi(argv[2]);
            if (port<1||port>65535){
                fprintf(stderr,"invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s server port\n", argv[0]);
            exit(0);
    }

    /* initialize the file name of key pair file */
    char CertFile[] = "568ca.pem";
    char KeyFile[] = "alice.pem";

    /* initialzing ssl context and method */
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);

    /* configuring SSL context */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    // removing ssv2 from options
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    if (ctx == NULL) {
        fprintf(stderr, "ctx is NULL\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_cipher_list(ctx, "SHA1");

    if (SSL_CTX_load_verify_locations(ctx, CertFile, NULL) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);
    //End new lines

    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "certificate file is not correctly set\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "password");
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "Private key file is not correctly set\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

    /*get ip address of the host*/

    host_entry = gethostbyname(host);

    if (!host_entry){
        fprintf(stderr,"Couldn't resolve host");
        exit(0);
    }

    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

    if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
        perror("socket");
    if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
        perror("connect");

    /*open socket*/
    SSL *ssl;
    ssl = SSL_new(ctx);
    BIO * bio = BIO_new_socket(sock, BIO_NOCLOSE);
    if (bio == NULL){
        fprintf(stderr, "Client: Fatal - Failure creating BIO for new socket connection.\nServer Exit...\n");
        //server_shut_down(sock, s, ssl, ctxSSL, NULL);
    }
    SSL_set_bio(ssl, bio, bio);
    if (SSL_connect(ssl) <= 0){
        printf("handshake failed\n");
        printf(FMT_CONNECT_ERR);
        ERR_print_errors_fp(stdout);
        client_shutdown(ssl,sock);

    }

    if (checkCertificate(ssl) == 0){
        //shut down the service
    }
    SSL_write(ssl,secret,256); // change later
    int lenRead = SSL_read(ssl, &buf, 255);
    printf("%s\n", buf); // printing out the result from server
    client_shutdown(ssl,sock);

    return 1;
}

int checkCertificate(SSL* ssl)
{
    X509 *cert;
    char *line = malloc(256);
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
        char* CN = "Bob's Server";
        memcpy(line,subjectCn,256);
        if (*CN != *line){
            printf(FMT_CN_MISMATCH);
            result = 0;
        }

        /* getting email name  tested */
        char* email = "ece568bob@ecf.utoronto.ca";
        int nid_email = OBJ_txt2nid("emailAddress");
        X509_NAME_get_text_by_NID(
                subjectName, nid_email, subjectCn, sizeof(subjectCn));
        memcpy(line,subjectCn,256);
        if (*email != *line){
            printf(FMT_EMAIL_MISMATCH);
            result = 0;
        }

        if (result == 1){
            line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
            printf(FMT_SERVER_INFO, CN,email, line);
        }

    }
    else {
        printf(FMT_NO_VERIFY);
        result = 0;

    }
    return result;
}

void client_shutdown(SSL* ssl, int sock){
    int result = SSL_shutdown(ssl);
    if(result == 0){
        result = SSL_shutdown(ssl);
    }
    if(result < 0){
        printf(FMT_INCORRECT_CLOSE);
    }

    close(sock);
    exit(0);
}