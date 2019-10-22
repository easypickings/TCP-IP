#ifndef ROUTER_H
#define ROUTER_H

#include <netinet/ip.h>
#include "device.h"
#include <map>
#include <set>

struct Routing
{
    in_addr ipprefix;
    in_addr mask;
    uint16_t slash;
    mutable MAC nexthopMAC;
    mutable pDevice pdev;
    mutable int dist;

    Routing(const in_addr &_ip, const in_addr &_mask,
            const MAC &_MAC, pDevice _pdev)
    {
        ipprefix.s_addr = _ip.s_addr & _mask.s_addr;
        mask.s_addr = _mask.s_addr;

        slash = 0;
        uint32_t n = mask.s_addr;
        while (n)
        {
            n = n & (n - 1);
            slash++;
        }
        nexthopMAC = _MAC;
        pdev = _pdev;
    }

    bool includeIP(const in_addr &ip)
    {
        return ((ip.s_addr & mask.s_addr) ==
                (ipprefix.s_addr & mask.s_addr));
    }
};

// overloading < to implement longest prefix matching
bool operator<(const Routing &a, const Routing &b);
in_addr slash2mask(int slash);

struct RoutingTable
{
    std::set<Routing> table;

    std::pair<pDevice, MAC> find(const in_addr &ip)
    {
        pDevice pdev = nullptr;
        MAC nextMAC;
        for (auto routing : table)
            if (routing.includeIP(ip))
            {
                pdev = routing.pdev;
                nextMAC = routing.nexthopMAC;
                break;
            }
        return std::make_pair(pdev, nextMAC);
    }

    void init();

    void print()
    {
        printf("Destination\tNetMask\tNextHopMAC\tDistance\tDevice\n");
        for (auto routing : table)
        {
            std::string ip = inet_ntoa(routing.ipprefix);
            std::string netmask = inet_ntoa(routing.mask);
            printf("%s/%u\t%s\t%s\t%d\t%s\n",
                   ip.c_str(), routing.slash, netmask.c_str(),
                   routing.nexthopMAC.str().c_str(),
                   routing.dist, routing.pdev->name.c_str());
        }
    }
};

extern RoutingTable router;

/**************************
 * Naive Routing Protocol *
 **************************/
#define NRP_MAX_REC 185
#define NRP_HDR_LEN 8
#define NRP_NEW_PKT 1
#define NRP_OLD_PKT 0

struct NRPRecord
{
    in_addr ipprefix;
    uint16_t slash;
    uint16_t dist;
} __attribute__((__packed__));

struct NRPPacket
{
    struct
    {
        // -How many records are there in the packet?
        // -`num`.
        uint8_t num;
        uint8_t flag;
        u_char mac[ETHER_ADDR_LEN];
    } __attribute__((__packed__)) hdr;

    NRPRecord records[NRP_MAX_REC];

    NRPPacket() { memset(&hdr, 0, sizeof(NRPPacket)); }
    NRPPacket(const void *buf, int l)
    {
        int len = l;
        if (l > sizeof(NRPPacket))
            len = sizeof(NRPPacket);
        memcpy(&hdr, buf, len);
    }

    void hton()
    {
        for (int i = 0; i < hdr.num; ++i)
        {
            records[i].slash = htons(records[i].slash);
            records[i].dist = htons(records[i].dist);
        }
    }

    void ntoh()
    {
        for (int i = 0; i < hdr.num; ++i)
        {
            records[i].slash = ntohs(records[i].slash);
            records[i].dist = ntohs(records[i].dist);
        }
    }
};

#endif