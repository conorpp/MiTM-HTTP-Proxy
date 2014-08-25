

UTILS=../../../utils/build/utils.so

INCLUDE=-Ipcap -Ilibnet -I../../../utils
LIB=../../../utils/build/utils.so


route: clean
	clang forwarder.c raw.c pcap.c lib/* $(LIB) $(INCLUDE) -ldnet -o $@

arp: clean
	clang sendarp.c pcap.c raw.c lib/* $(INCLUDE) -ldnet -o $@

all:
	clang *.c lib/* $(INCLUDE) -o router

clean:
	rm -rf route a.out
