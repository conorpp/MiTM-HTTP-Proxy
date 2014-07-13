
LFLAGS=-lssl -lcrypto -lz

#Obj files, build location
OBJFILES=http.o main.o ssl.o string.o \
		regex.o proxy.o commandline.o scenarios.o
OBJS=$(addprefix $(ProxyBuildDir)/,$(OBJFILES))

#dynamic library output
OFLAGS=-shared -o $(ProxySO)

INCLUDE=-I$(SrcDir)/utils

all: $(OBJS)
	$(CC) $(OBJS) $(LFLAGS) $(OFLAGS)

$(ProxyBuildDir)/%.o: $(ProxyDir)/%.c
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@

clean:
	rm -rf $(ProxyBuildDir)/*.o $(ProxyBuildDir)/*.so


