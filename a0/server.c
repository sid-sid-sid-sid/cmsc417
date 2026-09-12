
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "hash/hash.h"

#define MAX_CLIENTS 64
#define LISTEN_BACKLOG 32

#define MSG_INIT 1
#define MSG_ACK 2
#define MSG_HASHREQ 3
#define MSG_HASHRESP 4

#define HASH_SIZE 32     
#define HEADER_SIZE 8    
#define RESPONSE_SIZE 40 



int try_recv_bytes(int sock, uint8_t *buf, size_t *have, size_t target) {
    ssize_t n;

    if (*have >= target) {
        return 1;
    }

    n = recv(sock, buf + *have, target - *have, 0);
    if (n > 0) {
        *have = *have + (size_t)n;
        if (*have >= target) {
            return 1;
        }
        return 0;
    }
    if (n == 0) {
        return -1;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return 0;
    }
    return -1;
}

int try_send_bytes(int sock, uint8_t *buf, size_t *have, size_t target) {
    ssize_t n;

    if (*have >= target) {
        return 1;
    }

    n = send(sock, buf + *have, target - *have, MSG_NOSIGNAL);
    if (n > 0) {
        *have = *have + (size_t)n;
        if (*have >= target) {
            return 1;
        }
        return 0;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
    }
    return -1;
}

void make_socket_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

enum client_state {
    STATE_FREE,               /* this slot is not being used */
    STATE_WAIT_INIT,          /* waiting for the Initialization message */
    STATE_SEND_ACK,           /* sending back the Acknowledgement */
    STATE_WAIT_REQ_HEADER,    /* waiting for a HashRequest header */
    STATE_WAIT_REQ_DATA,      /* waiting for a HashRequest's data */
    STATE_SEND_RESPONSE,      /* sending back a HashResponse */
    STATE_DONE                /* client is finished, close the socket */
};

struct client_conn {
    int sock;
    enum client_state state;
    uint8_t header_buf[HEADER_SIZE];
    size_t header_have;

    uint32_t total_hashes;
    uint32_t hashes_done;  

    uint32_t chunks_left;
    uint32_t last_chunk_size;
    uint8_t chunk_buf[UPDATE_PAYLOAD_SIZE];
    size_t chunk_have;

    struct checksum_ctx *ctx;

    uint8_t out_buf[RESPONSE_SIZE];
    size_t out_have;
    size_t out_len;
};

void start_new_client(struct client_conn *c, int sock, uint8_t *salt, size_t salt_len) {
    c->sock = sock;
    c->state = STATE_WAIT_INIT;
    c->header_have = 0;
    c->total_hashes = 0;
    c->hashes_done = 0;
    c->chunks_left = 0;
    c->last_chunk_size = 0;
    c->chunk_have = 0;
    c->out_have = 0;
    c->out_len = 0;
    c->ctx = checksum_create(salt, salt_len);
}

void close_client(struct client_conn *c) {
    if (c->sock >= 0) {
        close(c->sock);
    }
    checksum_destroy(c->ctx);
    c->sock = -1;
    c->state = STATE_FREE;
}

void handle_client_readable(struct client_conn *c) {
    int result;
    uint32_t msg_type;
    uint32_t msg_field;
    size_t target;
    uint8_t hash_out[HASH_SIZE];

    for (;;) {
        if (c->state == STATE_WAIT_INIT) {
            result = try_recv_bytes(c->sock, c->header_buf, &c->header_have, HEADER_SIZE);
            if (result < 0) {
                c->state = STATE_DONE;
                return;
            }
            if (result == 0) {
                return; 
            }

            memcpy(&msg_type, c->header_buf, 4);
            memcpy(&msg_field, c->header_buf + 4, 4);
            msg_type = ntohl(msg_type);
            msg_field = ntohl(msg_field);

            if (msg_type != MSG_INIT) {
                c->state = STATE_DONE;
                return;
            }

            c->total_hashes = msg_field;
            c->hashes_done = 0;

            msg_type = htonl(MSG_ACK);
            msg_field = htonl(40 * c->total_hashes);
            memcpy(c->out_buf, &msg_type, 4);
            memcpy(c->out_buf + 4, &msg_field, 4);
            c->out_len = HEADER_SIZE;
            c->out_have = 0;
            c->state = STATE_SEND_ACK;
            return; 
        }

        if (c->state == STATE_WAIT_REQ_HEADER) {
            result = try_recv_bytes(c->sock, c->header_buf, &c->header_have, HEADER_SIZE);
            if (result < 0) {
                c->state = STATE_DONE;
                return;
            }
            if (result == 0) {
                return;
            }

            memcpy(&msg_type, c->header_buf, 4);
            memcpy(&msg_field, c->header_buf + 4, 4);
            msg_type = ntohl(msg_type);
            msg_field = ntohl(msg_field);

            if (msg_type != MSG_HASHREQ) {
                c->state = STATE_DONE;
                return;
            }

            c->chunks_left = msg_field / UPDATE_PAYLOAD_SIZE;
            c->last_chunk_size = msg_field % UPDATE_PAYLOAD_SIZE;
            c->chunk_have = 0;
            c->state = STATE_WAIT_REQ_DATA;
            continue; 
        }

        if (c->state == STATE_WAIT_REQ_DATA) {
            if (c->chunks_left > 0) {
                target = UPDATE_PAYLOAD_SIZE;
            } else {
                target = c->last_chunk_size;
            }

            result = try_recv_bytes(c->sock, c->chunk_buf, &c->chunk_have, target);
            if (result < 0) {
                c->state = STATE_DONE;
                return;
            }
            if (result == 0) {
                return;
            }

            if (c->chunks_left > 0) {
                if (checksum_update(c->ctx, c->chunk_buf) != 0) {
                    c->state = STATE_DONE;
                    return;
                }
                c->chunks_left = c->chunks_left - 1;
                c->chunk_have = 0;
                continue;
            }

            if (checksum_finish(c->ctx, c->chunk_buf, c->last_chunk_size, hash_out) != 0) {
                c->state = STATE_DONE;
                return;
            }
            checksum_reset(c->ctx);

            msg_type = htonl(MSG_HASHRESP);
            msg_field = htonl(c->hashes_done);
            memcpy(c->out_buf, &msg_type, 4);
            memcpy(c->out_buf + 4, &msg_field, 4);
            memcpy(c->out_buf + HEADER_SIZE, hash_out, HASH_SIZE);
            c->out_len = RESPONSE_SIZE;
            c->out_have = 0;
            c->hashes_done = c->hashes_done + 1;
            c->state = STATE_SEND_RESPONSE;
            return;
        }
        return;
    }
}

void handle_client_writable(struct client_conn *c) {
    int result;

    if (c->state == STATE_SEND_ACK) {
        result = try_send_bytes(c->sock, c->out_buf, &c->out_have, c->out_len);
        if (result < 0) {
            c->state = STATE_DONE;
            return;
        }
        if (result == 0) {
            return;
        }

        if (c->total_hashes == 0) {
            c->state = STATE_DONE;
            return;
        }
        c->header_have = 0;
        c->state = STATE_WAIT_REQ_HEADER;
        return;
    }

    if (c->state == STATE_SEND_RESPONSE) {
        result = try_send_bytes(c->sock, c->out_buf, &c->out_have, c->out_len);
        if (result < 0) {
            c->state = STATE_DONE;
            return;
        }
        if (result == 0) {
            return;
        }

        if (c->hashes_done >= c->total_hashes) {
            c->state = STATE_DONE;
            return;
        }
        c->header_have = 0;
        c->state = STATE_WAIT_REQ_HEADER;
        return;
    }

}

short events_needed_for_state(enum client_state state) {
    if (state == STATE_WAIT_INIT) {
        return POLLIN;
    }
    if (state == STATE_WAIT_REQ_HEADER) {
        return POLLIN;
    }
    if (state == STATE_WAIT_REQ_DATA) {
        return POLLIN;
    }
    if (state == STATE_SEND_ACK) {
        return POLLOUT;
    }
    if (state == STATE_SEND_RESPONSE) {
        return POLLOUT;
    }
    return 0;
}


struct server_arguments {
    int port;
    int port_set;
    char *salt;
    size_t salt_len;
};

error_t server_parser(int key, char *arg, struct argp_state *state) {
    struct server_arguments *args = state->input;
    char *end;
    long value;

    if (key == 'p') {
        value = strtol(arg, &end, 10);
        if (*end != '\0') {
            argp_error(state, "port must be a number");
        }
        if (value <= 1024 || value > 65535) {
            argp_error(state, "port must be greater than 1024 and at most 65535");
        }
        args->port = (int)value;
        args->port_set = 1;
        return 0;
    }

    if (key == 's') {
        args->salt_len = strlen(arg);
        args->salt = malloc(args->salt_len + 1);
        if (args->salt == NULL) {
            argp_failure(state, 1, errno, "malloc failed");
        }
        strcpy(args->salt, arg);
        return 0;
    }

    return ARGP_ERR_UNKNOWN;
}

static struct argp_option options[] = {
    { "port", 'p', "port", 0, "Port to bind and listen on (must be > 1024)", 0 },
    { "salt", 's', "salt", 0, "Optional salt to use when computing hashes", 0 },
    { 0 }
};

int main(int argc, char *argv[]) {
    struct server_arguments args;
    struct argp argp_settings;
    int listen_sock;
    int reuse;
    struct sockaddr_in servaddr;
    struct client_conn clients[MAX_CLIENTS];
    struct pollfd poll_list[1 + MAX_CLIENTS];
    int i;
    int slot;
    int new_sock;
    short want_events;

    bzero(&args, sizeof(args));
    argp_settings.options = options;
    argp_settings.parser = server_parser;
    argp_settings.args_doc = 0;
    argp_settings.doc = 0;
    argp_settings.children = 0;
    argp_settings.help_filter = 0;
    argp_settings.argp_domain = 0;

    if (argp_parse(&argp_settings, argc, argv, 0, NULL, &args) != 0) {
        fprintf(stderr, "Error parsing arguments\n");
        return 1;
    }
    if (args.port_set == 0) {
        fprintf(stderr, "Usage: %s -p <port> [-s <salt>]\n", argv[0]);
        return 1;
    }

   
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        perror("socket");
        free(args.salt);
        return 1;
    }
    reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    make_socket_nonblocking(listen_sock);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons((uint16_t)args.port);

    if (bind(listen_sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(listen_sock);
        free(args.salt);
        return 1;
    }
    if (listen(listen_sock, LISTEN_BACKLOG) < 0) {
        perror("listen");
        close(listen_sock);
        free(args.salt);
        return 1;
    }

    fprintf(stderr, "Server listening on port %d\n", args.port);

    for (i = 0; i < MAX_CLIENTS; i++) {
        clients[i].sock = -1;
        clients[i].state = STATE_FREE;
    }

    poll_list[0].fd = listen_sock;
    poll_list[0].events = POLLIN;
    for (i = 0; i < MAX_CLIENTS; i++) {
        poll_list[1 + i].fd = -1;
        poll_list[1 + i].events = 0;
    }

    for (;;) {
        if (poll(poll_list, 1 + MAX_CLIENTS, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }

        if (poll_list[0].revents & POLLIN) {
            for (;;) {
                new_sock = accept(listen_sock, NULL, NULL);
                if (new_sock < 0) {
                    break; 
                }

                slot = -1;
                for (i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].sock < 0) {
                        slot = i;
                        break;
                    }
                }

                if (slot < 0) {
                    close(new_sock);
                } else {
                    make_socket_nonblocking(new_sock);
                    start_new_client(&clients[slot], new_sock, (uint8_t *)args.salt, args.salt_len);
                    poll_list[1 + slot].fd = new_sock;
                    poll_list[1 + slot].events = events_needed_for_state(clients[slot].state);
                }
            }
        }

        for (i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].sock < 0) {
                continue;
            }

            if (poll_list[1 + i].revents & (POLLIN | POLLHUP | POLLERR)) {
                handle_client_readable(&clients[i]);
            }

            if (clients[i].state != STATE_DONE) {
                if (poll_list[1 + i].revents & POLLOUT) {
                    handle_client_writable(&clients[i]);
                }
            }

            if (clients[i].state == STATE_DONE) {
                close_client(&clients[i]);
                poll_list[1 + i].fd = -1;
                poll_list[1 + i].events = 0;
            } else {
                want_events = events_needed_for_state(clients[i].state);
                poll_list[1 + i].events = want_events;
            }
        }
    }

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock >= 0) {
            close_client(&clients[i]);
        }
    }
    close(listen_sock);
    free(args.salt);
    return 0;
}