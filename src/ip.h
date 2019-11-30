/** 
 * @file ip.h
 * @brief Library supporting sending/receiving IP packets encapsulated in an 
 * Ethernet II frame.
 */
#ifndef IP_H
#define IP_H

#include <netinet/ip.h>
#include "device.h"
#include <map>

#define IP_DATA_LEN 65515

uint16_t getChecksum(const void *vdata, size_t length);

struct IPPacket
{
    struct
    {
        ip hdr;
        u_char ippayload[IP_DATA_LEN];
    } __attribute__((__packed__));

    IPPacket() { memset(&hdr, 0, sizeof(IPPacket)); }
    IPPacket(const void *buf, int l)
    {
        int len = l;
        if (l > sizeof(IPPacket))
            len = sizeof(IPPacket);
        memcpy(&hdr, buf, len);
    }

    int getPayloadLen() { return hdr.ip_len - hdr.ip_hl * 4; }

    void setHeader(const in_addr &src, const in_addr &dest, int proto)
    {
        hdr.ip_v = 4;
        hdr.ip_hl = 5;
        hdr.ip_src = src;
        hdr.ip_dst = dest;
        hdr.ip_p = proto;
        hdr.ip_off = IP_DF;
        hdr.ip_ttl = 64;
        // hdr.ip_len = hdr.ip_hl * 4;
    }

    int setPayload(const void *buf, int len)
    {
        if (len > IP_DATA_LEN)
        {
            // printf("IPPayload Oversize!\n");
            return -1;
        }
        memcpy(ippayload, buf, len);
        hdr.ip_len = hdr.ip_hl * 4 + len;
        return 0;
    }

    void hton()
    {
        hdr.ip_len = htons(hdr.ip_len);
        hdr.ip_id = htons(hdr.ip_id);
        hdr.ip_off = htons(hdr.ip_off);
        hdr.ip_sum = htons(hdr.ip_sum);
    }

    void ntoh()
    {
        hdr.ip_len = ntohs(hdr.ip_len);
        hdr.ip_id = ntohs(hdr.ip_id);
        hdr.ip_off = ntohs(hdr.ip_off);
        hdr.ip_sum = ntohs(hdr.ip_sum);
    }

    void setChecksum()
    {
        hdr.ip_sum = 0;
        hdr.ip_sum = getChecksum(&hdr, hdr.ip_hl * 4);
    }

    bool chkChecksum()
    {
        auto res = getChecksum(&hdr, hdr.ip_hl * 4);
        return res == 0;
    }

    void print() const
    {
        printf("######## IP Packet ########\n");
        printf("src ip: %s\n", inet_ntoa(hdr.ip_src));
        printf("dst ip: %s\n", inet_ntoa(hdr.ip_dst));
        printf("version: %d\n", hdr.ip_v);
        printf("ihl: %d\n", hdr.ip_hl);
        printf("protocol: 0x%x\n", hdr.ip_p);
        printf("ttl: %d\n", hdr.ip_ttl);
        printf("total len: %d\n", hdr.ip_len);
        printf("###########################\n");
    }
};

/**
 * @brief Send an IP packet to specified host. 
 *
 * @param src Source IP address.
 * @param dest Destination IP address.
 * @param proto Value of `protocol` field in IP header.
 * @param buf pointer to IP payload
 * @param len Length of IP payload
 * @return 0 on success, -1 on error.
 */
int sendIPPacket(const in_addr &src, const in_addr &dest,
                 int proto, const void *buf, int len);

typedef int (*IPPacketReceiveCallback)(const void *buf, int len);

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

/**
 * @brief Manully add an item to routing table. Useful when talking with real 
 * Linux machines.
 * 
 * @param dest The destination IP prefix.
 * @param mask The subnet mask of the destination IP prefix.
 * @param nextHopMAC MAC address of the next hop.
 * @param device Name of device to send packets on.
 * @return 0 on success, -1 on error
 */
int setRoutingTable(const in_addr &dest, const in_addr &mask,
                    const MAC &nextHopMAC, const char *device);

int IPCallback(const void *buf, int len, int id);

#endif