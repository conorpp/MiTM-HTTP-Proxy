

UTILS=../../../utils/build/utils.so

INCLUDE=-Ipcap -Ilibnet -I../../../utils

arp:
	clang sendarp.c arp.c pcap.c lib/* $(INCLUDE)

all:
	clang *.c lib/* $(INCLUDE) -o router

