CC := gcc
CFLAGS := -Wall -std=gnu11 -g -Ihash
LDLIBS := -lcrypto

HASH_SRCS := $(wildcard hash/*.c)

.PHONY: all clean

all: server client

server: server.c $(HASH_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

client: client.c $(HASH_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f server client