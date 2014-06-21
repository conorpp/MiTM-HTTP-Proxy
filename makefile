

CC=clang
CFLAGS=-c -Wall
LFLAGS=-lssl -lcrypto
EXE=proxy

default: main

main: utils.o tcp.o http.o main.o
	$(CC) $(LFLAGS) utils.o tcp.o http.o main.o -o $(EXE)

main.o: main.c
	$(CC) $(CFLAGS) main.c

tcp.o: tcp.c
	$(CC) $(CFLAGS) tcp.c

utils.o: utils.c
	$(CC) $(CFLAGS) utils.c

http.o: http.c
	$(CC) $(CFLAGS) http.c

test: $(EXE)
	./proxy 9999 cert.pem privkey.pem

clean:
	rm -rf *.o $(EXE)

$(EXE): clean main

#run: proxy
#    ./proxy 9999 cert.pem privkey.pem
