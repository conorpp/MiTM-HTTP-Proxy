

CC=clang
CFLAGS=-c -Wall


LIBLOC=thirdparty/lib/
LIBS=$(LIBLOC)libnet.a $(LIBLOC)libpcap.a
INCLUDE=-I thirdparty

EXE=main

all: clean compile

compile: main.o
	$(CC) $^ $(LIBS) -o $(EXE)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) $^ -o $@
	
clean:
	rm -rf $(EXE) *.o
	
