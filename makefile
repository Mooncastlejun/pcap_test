
CFLAGS = -Wall -I./libnet
LDLIBS += -lpcap -lnet
DEPS = libnet/include/libnet/libnet-headers.h

all: pcap-test

pcap-test: pcap-test.c

clean:
	rm -f pcap-test *.o
