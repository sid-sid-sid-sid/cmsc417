
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

#define MSG_INIT 1
#define MSG_ACK 2
#define MSG_HASHREQ 3
#define MSG_HASHRESP 4

#define HASH_SIZE 32

int send_all(int sock, const void *data, size_t len) {
    const char *ptr = data;
    size_t sent_so_far = 0;
    ssize_t n;

    while (sent_so_far < len) {
        n = send(sock, ptr + sent_so_far, len - sent_so_far, 0);
        if (n <= 0) {
            return -1;
        }
        sent_so_far = sent_so_far + (size_t)n;
    }
    return 0;
}

int recv_all(int sock, void *data, size_t len) {
    char *ptr = data;
    size_t got_so_far = 0;
    ssize_t n;

    while (got_so_far < len) {
        n = recv(sock, ptr + got_so_far, len - got_so_far, 0);
        if (n == 0) {
            return -1;
        }
        if (n < 0) {
            return -1;
        }
        got_so_far = got_so_far + (size_t)n;
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

error_t client_parser(int key, char *arg, struct argp_state *state) {
    struct client_arguments *args = state->input;
    char *end;
    long value;

    if (key == 'a') {
        strncpy(args->ip_address, arg, sizeof(args->ip_address) - 1);
        args->ip_address[sizeof(args->ip_address) - 1] = '\0';
        return 0;
    }

    if (key == 'p') {
        value = strtol(arg, &end, 10);
        if (*end != '\0') {
            argp_error(state, "port must be a number");
        }
        if (value <= 0 || value > 65535) {
            argp_error(state, "port must be between 1 and 65535");
        }
        args->port = (int)value;
        args->port_set = 1;
        return 0;
    }

    if (key == 'n') {
        value = strtol(arg, &end, 10);
        if (*end != '\0') {
            argp_error(state, "hashreq must be a number");
        }
        if (value < 0) {
            argp_error(state, "hashreq must be 0 or greater");
        }
        args->hashnum = (int)value;
        args->hashnum_set = 1;
        return 0;
    }

    if (key == 300) {
        value = strtol(arg, &end, 10);
        if (*end != '\0') {
            argp_error(state, "smin must be a number");
        }
        if (value < 1) {
            argp_error(state, "smin must be 1 or greater");
        }
        args->smin = value;
        args->smin_set = 1;
        return 0;
    }

    if (key == 301) { /* --smax */
        value = strtol(arg, &end, 10);
        if (*end != '\0') {
            argp_error(state, "smax must be a number");
        }
        if (value > 16777216) { /* 2^24, per the handout */
            argp_error(state, "smax must be at most 2^24");
        }
        args->smax = value;
        args->smax_set = 1;
        return 0;
    }

    if (key == 'f') {
        size_t len = strlen(arg);
        args->filename = malloc(len + 1);
        if (args->filename == NULL) {
            argp_failure(state, 1, errno, "malloc failed");
        }
        strcpy(args->filename, arg);
        return 0;
    }

    return ARGP_ERR_UNKNOWN;
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

void print_hash_response(uint32_t index, uint8_t *hash) {
    int i;

    printf("%u: 0x", index);
    for (i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    struct client_arguments args;
    struct argp argp_settings;
    FILE *fp;
    struct in_addr addr_bin;
    int sock;
    struct sockaddr_in servaddr;
    uint32_t init_type, init_n;
    uint32_t ack_type, ack_len;
    uint8_t header_buf[8];
    uint8_t *data_buf;
    int i;
    long range;
    long request_len;
    size_t bytes_read;
    uint32_t req_type, req_len;
    uint32_t resp_type, resp_index;
    uint8_t resp_hash[HASH_SIZE];

    bzero(&args, sizeof(args));
    argp_settings.options = options;
    argp_settings.parser = client_parser;
    argp_settings.args_doc = 0;
    argp_settings.doc = 0;
    argp_settings.children = 0;
    argp_settings.help_filter = 0;
    argp_settings.argp_domain = 0;

    if (argp_parse(&argp_settings, argc, argv, 0, NULL, &args) != 0) {
        fprintf(stderr, "Error parsing arguments\n");
        return 1;
    }

    if (args.ip_address[0] == '\0') {
        fprintf(stderr, "You must specify -a <address>\n");
        return 1;
    }
    if (args.port_set == 0) {
        fprintf(stderr, "You must specify -p <port>\n");
        return 1;
    }
    if (args.hashnum_set == 0) {
        fprintf(stderr, "You must specify -n <hashreq>\n");
        return 1;
    }
    if (args.smin_set == 0) {
        fprintf(stderr, "You must specify --smin <minsize>\n");
        return 1;
    }
    if (args.smax_set == 0) {
        fprintf(stderr, "You must specify --smax <maxsize>\n");
        return 1;
    }
    if (args.filename == NULL) {
        fprintf(stderr, "You must specify -f <file>\n");
        return 1;
    }
    if (args.smin > args.smax) {
        fprintf(stderr, "smin cannot be greater than smax\n");
        return 1;
    }

    fp = fopen(args.filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    if (inet_pton(AF_INET, args.ip_address, &addr_bin) != 1) {
        fprintf(stderr, "Bad IP address: %s\n", args.ip_address);
        fclose(fp);
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        fclose(fp);
        return 1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons((uint16_t)args.port);
    servaddr.sin_addr = addr_bin;

    /* connect to the server */
    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        close(sock);
        fclose(fp);
        return 1;
    }

    init_type = htonl(MSG_INIT);
    init_n = htonl((uint32_t)args.hashnum);
    memcpy(header_buf, &init_type, 4);
    memcpy(header_buf + 4, &init_n, 4);
    if (send_all(sock, header_buf, 8) != 0) {
        fprintf(stderr, "Failed to send Initialization message\n");
        close(sock);
        fclose(fp);
        return 1;
    }

    if (recv_all(sock, header_buf, 8) != 0) {
        fprintf(stderr, "Failed to receive Acknowledgement message\n");
        close(sock);
        fclose(fp);
        return 1;
    }
    memcpy(&ack_type, header_buf, 4);
    memcpy(&ack_len, header_buf + 4, 4);
    ack_type = ntohl(ack_type);
    ack_len = ntohl(ack_len);
    if (ack_type != MSG_ACK) {
        fprintf(stderr, "Expected an Acknowledgement message\n");
        close(sock);
        fclose(fp);
        return 1;
    }

    srand((unsigned int)time(NULL));

    data_buf = malloc((size_t)args.smax);
    if (data_buf == NULL) {
        fprintf(stderr, "Could not allocate buffer for requests\n");
        close(sock);
        fclose(fp);
        return 1;
    }

    for (i = 0; i < args.hashnum; i++) {

        range = args.smax - args.smin + 1;
        request_len = args.smin + (rand() % range);

        bytes_read = fread(data_buf, 1, (size_t)request_len, fp);
        if (bytes_read != (size_t)request_len) {
            fprintf(stderr, "Ran out of data in the file\n");
            free(data_buf);
            close(sock);
            fclose(fp);
            return 1;
        }

        req_type = htonl(MSG_HASHREQ);
        req_len = htonl((uint32_t)request_len);
        memcpy(header_buf, &req_type, 4);
        memcpy(header_buf + 4, &req_len, 4);

        if (send_all(sock, header_buf, 8) != 0) {
            fprintf(stderr, "Failed to send HashRequest header\n");
            free(data_buf);
            close(sock);
            fclose(fp);
            return 1;
        }
        if (send_all(sock, data_buf, (size_t)request_len) != 0) {
            fprintf(stderr, "Failed to send HashRequest data\n");
            free(data_buf);
            close(sock);
            fclose(fp);
            return 1;
        }

        if (recv_all(sock, header_buf, 8) != 0) {
            fprintf(stderr, "Failed to receive HashResponse header\n");
            free(data_buf);
            close(sock);
            fclose(fp);
            return 1;
        }
        memcpy(&resp_type, header_buf, 4);
        memcpy(&resp_index, header_buf + 4, 4);
        resp_type = ntohl(resp_type);
        resp_index = ntohl(resp_index);
        if (resp_type != MSG_HASHRESP) {
            fprintf(stderr, "Expected a HashResponse message\n");
            free(data_buf);
            close(sock);
            fclose(fp);
            return 1;
        }

        if (recv_all(sock, resp_hash, HASH_SIZE) != 0) {
            fprintf(stderr, "Failed to receive hash bytes\n");
            free(data_buf);
            close(sock);
            fclose(fp);
            return 1;
        }

        print_hash_response(resp_index, resp_hash);
    }

    free(data_buf);
    close(sock);
    fclose(fp);
    free(args.filename);
    return 0;
}