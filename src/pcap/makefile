

CC=clang
CFLAGS=-c -Wall


LIBLOC=thirdparty/lib/
LIBS=$(LIBLOC)libnet.a $(LIBLOC)libpcap.a ../utils/build/utils.so
INCLUDE=-I thirdparty -I ../utils

EXE=main

all: clean compile

compile: main.o
	$(CC) $^ $(LIBS) -o $(EXE)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) $^ -o $@
	
clean:
	rm -rf $(EXE) *.o
	
