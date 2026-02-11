C := gcc
CFLAGS:= -Wall -Wextra -std=c11 -O2
LDFLAGS:=

# Felles
COMMON_SRC := unix_ipc.c
COMMON_OBJ := $(COMMON_SRC:.c=.o)
HDRS := unix_ipc.h mip.h


BIN := mipd ping_client ping_server routingd

all: $(BIN)

mipd: mipd.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ping_client: ping_client.o unix_ipc.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ping_server: ping_server.o unix_ipc.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

routingd: routingd.o unix_ipc.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) *.o

.PHONY: all clean

