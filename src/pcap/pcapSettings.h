/* Settings and resusable contexts for packet capture
* */

#ifndef _PCAP_SETTINGS_H_
#define _PCAP_SETTINGS_H_


#include "libnet/libnetcore.h"
#include "pcap/pcap.h"

struct{
    char* dev;
    libnet_t *arpMachine;
    uint8_t* hostHwAddr;
    uint8_t* spoofedHwAddr;
    uint32_t hostIp;
}Settings;



#endif
