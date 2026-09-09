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
#include <unistd.h>

#include "hash.h"

#define LISTEN_BACKLOG 10

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

struct server_arguments {
    int port;
    int port_set;
    char *salt;
    size_t salt_len;
};

static error_t server_parser(int key, char *arg, struct argp_state *state) {
    struct server_arguments *args = state->input;
    char *end;
    long val;

    switch (key) {
    case 'p':
        val = strtol(arg, &end, 10);
        if (*end != '\0' || val <= 1024 || val > 65535) {
            argp_error(state, "Invalid port: must be a number > 1024 and <= 65535");
        }
        args->port = (int)val;
        args->port_set = 1;
        break;
    case 's':
        args->salt_len = strlen(arg);
        args->salt = malloc(args->salt_len + 1);
        if (args->salt == NULL) {
            argp_failure(state, 1, errno, "malloc failed");
        }
        strcpy(args->salt, arg);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp_option options[] = {
    { "port", 'p', "port", 0, "Port to bind and listen on (must be > 1024)", 0 },
    { "salt", 's', "salt", 0, "Optional salt to use when computing hashes", 0 },
    { 0 }
};

static void handle_client(int connfd, const uint8_t *salt, size_t salt_len) {
    uint32_t hdr[2];

    if (recv_all(connfd, hdr, sizeof(hdr)) != 0) {
        fprintf(stderr, "Client disconnected before sending Initialization\n");
        return;
    }
    uint32_t type = ntohl(hdr[0]);
    uint32_t n = ntohl(hdr[1]);
    if (type != MSG_INIT) {
        fprintf(stderr, "Expected Initialization (type=%d), got type %u\n", MSG_INIT, type);
        return;
    }

    uint32_t ack[2];
    ack[0] = htonl(MSG_ACK);
    ack[1] = htonl(40 * n);
    if (send_all(connfd, ack, sizeof(ack)) != 0) {
        fprintf(stderr, "Failed to send Acknowledgement\n");
        return;
    }

    struct checksum_ctx *ctx = checksum_create(salt, salt_len);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create checksum context\n");
        return;
    }

    uint8_t chunk[UPDATE_PAYLOAD_SIZE];

    for (uint32_t i = 0; i < n; i++) {
        uint32_t reqhdr[2];
        if (recv_all(connfd, reqhdr, sizeof(reqhdr)) != 0) {
            fprintf(stderr, "Client disconnected before HashRequest %u\n", i);
            break;
        }
        uint32_t rtype = ntohl(reqhdr[0]);
        uint32_t length = ntohl(reqhdr[1]);
        if (rtype != MSG_HASHREQ) {
            fprintf(stderr, "Expected HashRequest (type=%d), got type %u\n", MSG_HASHREQ, rtype);
            break;
        }

        uint32_t remaining = length;
        int failed = 0;
        while (remaining >= UPDATE_PAYLOAD_SIZE) {
            if (recv_all(connfd, chunk, UPDATE_PAYLOAD_SIZE) != 0) {
                failed = 1;
                break;
            }
            if (checksum_update(ctx, chunk) != 0) {
                failed = 1;
                break;
            }
            remaining -= UPDATE_PAYLOAD_SIZE;
        }
        if (failed) {
            fprintf(stderr, "Error reading/hashing payload for HashRequest %u\n", i);
            break;
        }
        if (remaining > 0) {
            if (recv_all(connfd, chunk, remaining) != 0) {
                fprintf(stderr, "Client disconnected mid-payload on HashRequest %u\n", i);
                break;
            }
        }

        uint8_t hash_out[HASH_SIZE];
        if (checksum_finish(ctx, chunk, remaining, hash_out) != 0) {
            fprintf(stderr, "Failed to finish hash for HashRequest %u\n", i);
            break;
        }
        checksum_reset(ctx);

        uint32_t resphdr[2];
        resphdr[0] = htonl(MSG_HASHRESP);
        resphdr[1] = htonl(i);
        if (send_all(connfd, resphdr, sizeof(resphdr)) != 0 ||
            send_all(connfd, hash_out, HASH_SIZE) != 0) {
            fprintf(stderr, "Failed to send HashResponse %u\n", i);
            break;
        }
    }

    checksum_destroy(ctx);
}

int main(int argc, char *argv[]) {
    struct server_arguments args;
    bzero(&args, sizeof(args));

    struct argp argp_settings = { options, server_parser, 0, 0, 0, 0, 0 };
    if (argp_parse(&argp_settings, argc, argv, 0, NULL, &args) != 0) {
        fprintf(stderr, "Error parsing arguments\n");
        return 1;
    }
    if (!args.port_set) {
        fprintf(stderr, "Usage: %s -p <port> [-s <salt>]\n", argv[0]);
        return 1;
    }

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("socket");
        free(args.salt);
        return 1;
    }

    int reuse = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons((uint16_t)args.port);

    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(listenfd);
        free(args.salt);
        return 1;
    }

    if (listen(listenfd, LISTEN_BACKLOG) < 0) {
        perror("listen");
        close(listenfd);
        free(args.salt);
        return 1;
    }

    fprintf(stderr, "Server listening on port %d\n", args.port);

    for (;;) {
        struct sockaddr_in cliaddr;
        socklen_t clilen = sizeof(cliaddr);

        int connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
        if (connfd < 0) {
            perror("accept");
            continue;
        }

        handle_client(connfd, (uint8_t *)args.salt, args.salt_len);

        close(connfd);
    }

    free(args.salt);
    close(listenfd);
    return 0;
}