

#Compiling/linking
CC=clang
CFLAGS=-c -Wall
LFLAGS=-lssl -lcrypto -lz

#Output executable name
EXE=proxy

#Obj files, build location
OBJS=utils.o tcp.o http.o main.o ssl.o string.o \
     regex.o proxy.o commandline.o scenarios.o logger.o
OBJ_DIR=build
OBJS_OUTPUT=$(addprefix $(OBJ_DIR)/,$(OBJS))

#Source file location
SRC_DIR=src

all: $(OBJ_DIR) clean main

main: $(OBJS_OUTPUT)
	$(CC) $(LFLAGS) $^ -o $(EXE)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJ_DIR)/*.o $(EXE)

$(OBJ_DIR):
	mkdir $@

run:
	./proxy -p 9999 -ca data/cert.pem -pk data/privkey.pem

$(EXE): clean main run

$(EXE)D: debug $(EXE)

debug:
	$(eval CFLAGS += -DNOFORK=1)

#run: proxy
#    ./proxy 9999 cert.pem privkey.pem
