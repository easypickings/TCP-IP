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
void str2mac(u_char *mac, const char *str);

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
        ether_header hdr;
        u_char payload[ETH_DATA_LEN];
    } __attribute__((__packed__));
    int len;

    EtherFrame() { memset(&hdr, 0, ETH_FRAME_LEN); }
    EtherFrame(const void *buf, int l)
    {
        if (l > ETH_FRAME_LEN)
            len = ETH_FRAME_LEN;
        else
            len = l;
        memcpy(&hdr, buf, len);
    }

    void setHeader(const MAC &srcmac, const MAC &dstmac, uint16_t type)
    {
        memcpy(hdr.ether_shost, srcmac.addr, ETHER_ADDR_LEN);
        memcpy(hdr.ether_dhost, dstmac.addr, ETHER_ADDR_LEN);
        hdr.ether_type = type;
    }

    int setPayload(const void *buf, int l)
    {
        if (l > ETH_DATA_LEN)
        {
            // printf("EtherPayload Oversize!\n");
            return -1;
        }
        memcpy(payload, buf, l);
        len = ETHER_HDR_LEN + l;
        if (len < ETH_ZLEN)
            len = ETH_ZLEN;
        return 0;
    }

    int getPayloadLen() { return len - ETHER_HDR_LEN; }

    void hton() { hdr.ether_type = htons(hdr.ether_type); }
    void ntoh() { hdr.ether_type = ntohs(hdr.ether_type); }

    void print() const
    {
        printf("###### EthernetFrame ######\n");
        printf("src mac: %s\n", mac2str(hdr.ether_shost).c_str());
        printf("dst mac: %s\n", mac2str(hdr.ether_dhost).c_str());
        printf("ether_type: 0x%04x\n", hdr.ether_type);
        printf("len: %d\n", len);
        printf("###########################\n");
    }
};

int EtherCallback(const void *buf, int len, int id);

const u_char BroadCast[ETHER_ADDR_LEN] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const MAC BroadCastMAC(BroadCast);

#endif
