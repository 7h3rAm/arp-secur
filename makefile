#
# makefile for arp-secur v0.3
#

CC=gcc
CFLAGS=-lpcap -lnet
INCLUDES=headers.h pcap-utils.h config.h banners.h
SOURCES=arp-sniffer.c anamoly-detector.c spoof-detector.c main.c
BINARY=arp-secur

all: $(BINARY)


$(BINARY): $(INCLUDES) $(SOURCES)
	$(CC) $(INCLUDES) $(SOURCES) $(CFLAGS) -o $(BINARY) 2>/dev/null
#	$(CC) $(INCLUDES) $(SOURCES) $(CFLAGS) -o $(BINARY)

clean:
	rm -rf $(BINARY)

#EOF
