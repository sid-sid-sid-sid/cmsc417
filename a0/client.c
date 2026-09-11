

#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MSG_INIT     1  
#define MSG_ACK      2 
#define MSG_HASHREQ  3  
#define MSG_HASHRESP 4  

#define HASH_SIZE 32    

static int send_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    char *p = buf;
    size_t got = 0;

    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

struct client_arguments {
    char ip_address[64];
    int port;
    int port_set;
    int hashnum;
    int hashnum_set;
    long smin;
    int smin_set;
    long smax;
    int smax_set;
    char *filename;
};

static error_t client_parser(int key, char *arg, struct argp_state *state) {
    struct client_arguments *args = state->input;
    char *end;
    long val;

    switch (key) {
    case 'a':
        strncpy(args->ip_address, arg, sizeof(args->ip_address) - 1);
        args->ip_address[sizeof(args->ip_address) - 1] = '\0';
        break;
    case 'p':
        val = strtol(arg, &end, 10);
        if (*end != '\0' || val <= 0 || val > 65535) {
            argp_error(state, "Invalid port");
        }
        args->port = (int)val;
        args->port_set = 1;
        break;
    case 'n':
        val = strtol(arg, &end, 10);
        if (*end != '\0' || val < 0) {
            argp_error(state, "Invalid hash request count, must be >= 0");
        }
        args->hashnum = (int)val;
        args->hashnum_set = 1;
        break;
    case 300: /* --smin */
        val = strtol(arg, &end, 10);
        if (*end != '\0' || val < 1) {
            argp_error(state, "Invalid smin, must be >= 1");
        }
        args->smin = val;
        args->smin_set = 1;
        break;
    case 301: /* --smax */
        val = strtol(arg, &end, 10);
        if (*end != '\0' || val > (1L << 24)) {
            argp_error(state, "Invalid smax, must be <= 2^24");
        }
        args->smax = val;
        args->smax_set = 1;
        break;
    case 'f': {
        size_t len = strlen(arg);
        args->filename = malloc(len + 1);
        if (args->filename == NULL) {
            argp_failure(state, 1, errno, "malloc failed");
        }
        strcpy(args->filename, arg);
        break;
    }
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp_option options[] = {
    { "addr", 'a', "addr", 0, "The IP address the server is listening at", 0 },
    { "port", 'p', "port", 0, "The port the server is listening on", 0 },
    { "hashreq", 'n', "hashreq", 0, "The number of hash requests to send", 0 },
    { "smin", 300, "minsize", 0, "Minimum size of each request's data payload", 0 },
    { "smax", 301, "maxsize", 0, "Maximum size of each request's data payload", 0 },
    { "file", 'f', "file", 0, "File to read request data from", 0 },
    { 0 }
};

static void print_hash_response(uint32_t index, const uint8_t *hash) {
    printf("%u: 0x", index);
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    struct client_arguments args;
    bzero(&args, sizeof(args));

    struct argp argp_settings = { options, client_parser, 0, 0, 0, 0, 0 };
    if (argp_parse(&argp_settings, argc, argv, 0, NULL, &args) != 0) {
        fprintf(stderr, "Error parsing arguments\n");
        return 1;
    }

    if (args.ip_address[0] == '\0' || !args.port_set || !args.hashnum_set ||
        !args.smin_set || !args.smax_set || args.filename == NULL) {
        fprintf(stderr,
                "Usage: %s -a <addr> -p <port> -n <hashreq> --smin=<min> "
                "--smax=<max> -f <file>\n", argv[0]);
        return 1;
    }
    if (args.smin > args.smax) {
        fprintf(stderr, "smin must be <= smax\n");
        free(args.filename);
        return 1;
    }

    FILE *fp = fopen(args.filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        free(args.filename);
        return 1;
    }

    struct in_addr addr_bin;
    if (inet_pton(AF_INET, args.ip_address, &addr_bin) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", args.ip_address);
        fclose(fp);
        free(args.filename);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        fclose(fp);
        free(args.filename);
        return 1;
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons((uint16_t)args.port);
    servaddr.sin_addr = addr_bin;

    /* connect(): establish a connection to the server */
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        close(sockfd);
        fclose(fp);
        free(args.filename);
        return 1;
    }

    int status = 0;
    uint8_t *buf = NULL;

    uint32_t inithdr[2];
    inithdr[0] = htonl(MSG_INIT);
    inithdr[1] = htonl((uint32_t)args.hashnum);
    if (send_all(sockfd, inithdr, sizeof(inithdr)) != 0) {
        fprintf(stderr, "Failed to send Initialization\n");
        status = 1;
        goto cleanup;
    }

    uint32_t ackhdr[2];
    if (recv_all(sockfd, ackhdr, sizeof(ackhdr)) != 0) {
        fprintf(stderr, "Failed to receive Acknowledgement\n");
        status = 1;
        goto cleanup;
    }
    if (ntohl(ackhdr[0]) != MSG_ACK) {
        fprintf(stderr, "Expected Acknowledgement (type=%d)\n", MSG_ACK);
        status = 1;
        goto cleanup;
    }

    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    buf = malloc((size_t)args.smax);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate payload buffer\n");
        status = 1;
        goto cleanup;
    }

    for (int i = 0; i < args.hashnum; i++) {
        long range = args.smax - args.smin + 1;
        long l = args.smin + (long)(rand() % range);

        size_t nread = fread(buf, 1, (size_t)l, fp);
        if (nread != (size_t)l) {
            fprintf(stderr, "Not enough data in file for request %d\n", i);
            status = 1;
            goto cleanup;
        }

        uint32_t reqhdr[2];
        reqhdr[0] = htonl(MSG_HASHREQ);
        reqhdr[1] = htonl((uint32_t)l);
        if (send_all(sockfd, reqhdr, sizeof(reqhdr)) != 0 ||
            send_all(sockfd, buf, (size_t)l) != 0) {
            fprintf(stderr, "Failed to send HashRequest %d\n", i);
            status = 1;
            goto cleanup;
        }

        uint32_t resphdr[2];
        if (recv_all(sockfd, resphdr, sizeof(resphdr)) != 0) {
            fprintf(stderr, "Failed to receive HashResponse %d\n", i);
            status = 1;
            goto cleanup;
        }
        if (ntohl(resphdr[0]) != MSG_HASHRESP) {
            fprintf(stderr, "Expected HashResponse (type=%d)\n", MSG_HASHRESP);
            status = 1;
            goto cleanup;
        }
        uint32_t index = ntohl(resphdr[1]);

        uint8_t hash[HASH_SIZE];
        if (recv_all(sockfd, hash, HASH_SIZE) != 0) {
            fprintf(stderr, "Failed to receive hash for HashResponse %d\n", i);
            status = 1;
            goto cleanup;
        }

        print_hash_response(index, hash);
    }

cleanup:
    free(buf);
    close(sockfd);
    fclose(fp);
    free(args.filename);
    return status;
}