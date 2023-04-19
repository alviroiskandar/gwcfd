
CC ?= cc
CFLAGS = -Wall -Wextra -O2 -ggdb3 -D_GNU_SOURCE
LDFLAGS = -lcurl -lpthread

all: gwcfd

gwcfd: gwcfd.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f gwcfd

.PHONY: all clean
