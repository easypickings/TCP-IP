#ifndef ETHERFRAME_H
#define ETHERFRAME_H

#include <iostream>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <ifaddrs.h>
#include <netinet/ether.h>
#include <cstring>

#define ETHERTYPE_NRP 0x1106 // EtherFrame type for NRP

std::string mac2str(const u_char *mac);

struct MAC
{
    u_char addr[ETHER_ADDR_LEN];

    MAC()
    {
        for (int i = 0; i < ETHER_ADDR_LEN; ++i)
            addr[i] = 0xff;
    }
    MAC(const u_char *_m) { memcpy(addr, _m, ETHER_ADDR_LEN); }

    const MAC &operator=(const MAC &_m)
    {
        memcpy(addr, _m.addr, ETHER_ADDR_LEN);
        return *this;
    }
    bool operator==(const MAC &_m)
    {
        for (int i = 0; i < ETHER_ADDR_LEN; ++i)
            if (addr[i] != _m.addr[i])
                return false;
        return true;
    }
    std::string str() { return mac2str(addr); }
};

struct EtherFrame
{
    struct
    {
        ether_header header;
        u_char payload[ETH_DATA_LEN];
    } __attribute__((__packed__)) Frame;
    int len;

    EtherFrame() { memset(&Frame, 0, ETH_FRAME_LEN); }
    EtherFrame(const void *buf, int l)
    {
        if (l > ETH_FRAME_LEN)
            len = ETH_FRAME_LEN;
        else
            len = l;
        memcpy(&Frame, buf, len);
    }

    void setHeader(const MAC &srcmac, const MAC &dstmac, uint16_t type)
    {
        memcpy(Frame.header.ether_shost, srcmac.addr, ETHER_ADDR_LEN);
        memcpy(Frame.header.ether_dhost, dstmac.addr, ETHER_ADDR_LEN);
        Frame.header.ether_type = type;
    }

    int setPayload(const void *buf, int l)
    {
        if (l > ETH_DATA_LEN)
        {
            printf("EtherPayload Oversize!\n");
            return -1;
        }
        memcpy(Frame.payload, buf, l);
        len = ETHER_HDR_LEN + l;
        return 0;
    }

    int getPayloadLen() { return len - ETHER_HDR_LEN; }

    void hton() { Frame.header.ether_type = htons(Frame.header.ether_type); }
    void ntoh() { Frame.header.ether_type = ntohs(Frame.header.ether_type); }
};

typedef int (*frameReceiveCallback)(const void *, int, int);

int setFrameReceiveCallback(frameReceiveCallback callback);

int EtherCallback(const void *buf, int len, int id);

const u_char BroadCast[ETHER_ADDR_LEN] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const MAC BroadCastMAC(BroadCast);

#endif
