

UTILS=../../../utils/build/utils.so

INCLUDE=-Ipcap -Ilibnet -I../../../utils

arp:
	clang sendarp.c arp.c pcap.c lib/* $(INCLUDE) -ldnet

all:
	clang *.c lib/* $(INCLUDE) -o router

