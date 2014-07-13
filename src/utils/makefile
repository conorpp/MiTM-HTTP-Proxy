
LFLAGS=

#Obj files, build location
OBJFILES=utils.o logger.o tcp.o
OBJS=$(addprefix $(UtilsBuildDir)/,$(OBJFILES))

#dynamic library output
OFLAGS=-shared -o $(UtilsSO)

#INCLUDE=-I../utils

all: $(UtilsBuildDir) $(OBJS)
	$(CC) $(OBJS) $(OFLAGS)

$(UtilsBuildDir)/%.o: $(UtilsDir)/%.c
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@

clean:
	rm -rf $(UtilsBuildDir)/*.o $(UtilsBuildDir)/*.so

