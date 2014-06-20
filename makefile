

CC=clang
CFLAGS=-c
LFLAGS=-lssl -lcrypto
EXE=proxy

default: main

main: main.o
	$(CC) $(LFLAGS) main.o -o $(EXE)

main.o: main.c
	$(CC) $(CFLAGS) main.c

test: $(EXE)
	./proxy 9999 cert.pem privkey.pem

clean:
	rm -rf *.o $(EXE)

$(EXE): main

#run: proxy
#    ./proxy 9999 cert.pem privkey.pem
