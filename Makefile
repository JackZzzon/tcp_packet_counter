CC = gcc
CFLAGS = -Wall -Wextra

all: tcp_packet_counter

tcp_packet_counter: tcp_packet_counter.c
	$(CC) $(CFLAGS) -o tcp_packet_counter tcp_packet_counter.c -lpcap

clean:
	rm -f tcp_packet_counter
