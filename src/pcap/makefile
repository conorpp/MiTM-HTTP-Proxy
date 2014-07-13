

CC=clang
CFLAGS=-c -Wall

LFLAGS=thirdparty/libnet/libnet.a thirdparty/pcap/libpcap.a

INCLUDE=-I thirdparty

EXE=main

all: clean compile

compile: main.o
	$(CC) $^ $(LFLAGS) -o $(EXE)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) $^ -o $@
	
clean:
	rm -rf $(EXE) *.o
	
