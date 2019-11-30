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
    mutable unsigned int dist;

    Routing()
    {
        ipprefix.s_addr = 0;
        mask.s_addr = 0;
        slash = 0;
        pdev = nullptr;
        dist = UINT16_MAX;
    }
    Routing(const in_addr &_ip, const in_addr &_mask, const MAC &_MAC,
            pDevice _pdev, unsigned int _dist = 1)
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
        dist = _dist;
    }

    bool includeIP(const in_addr &ip)
    {
        return ((ip.s_addr & mask.s_addr) ==
                (ipprefix.s_addr & mask.s_addr));
    }
};

// overloading < to implement longest prefix matching
bool operator<(const Routing &a, const Routing &b);
in_addr slash2mask(uint16_t slash);

struct RoutingTable
{
    std::set<Routing> table;

    const Routing find(const in_addr &ip)
    {
        for (auto r : table)
            if (r.includeIP(ip))
                return r;
        Routing none;
        return none;
    }

    void init()
    {
        // Add local routings to routing table
        for (auto &pdev : hub.pdevices)
        {
            Routing r(pdev->ipaddr, pdev->netmask,
                      pdev->macaddr, pdev, 0);
            table.insert(r);
        }
    }

    void route();

    void print()
    {
        printf("Destination     "
               "NetMask         "
               "NextHopMAC          "
               "Device    "
               "Distance\n");
        for (auto routing : table)
        {
            std::string ip = inet_ntoa(routing.ipprefix);
            std::string netmask = inet_ntoa(routing.mask);
            printf("%s/%u\t%s\t%s   %s      %d\n",
                   ip.c_str(), routing.slash, netmask.c_str(),
                   routing.nexthopMAC.str().c_str(),
                   routing.pdev->name.c_str(), routing.dist);
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
    struct
    {
        in_addr ipprefix;
        uint16_t slash;
        uint16_t dist;
    } __attribute__((__packed__));

    NRPRecord() : slash(32), dist(UINT16_MAX) { ipprefix.s_addr = 0; }
    NRPRecord(const in_addr &_ip, const uint16_t _slash,
              const uint16_t _dist)
        : ipprefix(_ip), slash(_slash), dist(_dist) {}
    NRPRecord(const Routing &r)
        : ipprefix(r.ipprefix), slash(r.slash), dist(r.dist) {}

    const NRPRecord &operator=(const NRPRecord &r)
    {
        ipprefix = r.ipprefix;
        slash = r.slash;
        dist = r.dist;
        return *this;
    }

    void print()
    {
        printf("%s/%u: %u\n", inet_ntoa(ipprefix), slash, dist);
    }
};

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

    int getLen() { return sizeof(hdr) + hdr.num * sizeof(NRPRecord); }

    void setHeader(const uint8_t num, const uint8_t flag,
                   const MAC &mac)
    {
        hdr.num = num;
        hdr.flag = flag;
        memcpy(hdr.mac, mac.addr, ETHER_ADDR_LEN);
    }

    int setPayload(const NRPRecord *r, const uint8_t n)
    {
        if (n > NRP_MAX_REC)
        {
            // printf("NRPPayload Oversize!\n");
            return -1;
        }

        for (int i = 0; i < n; ++i)
            records[i] = r[i];
        return 0;
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

    void print()
    {
        printf("######## NRPPacket ########\n");
        printf("num: %u    flag: %u\n"
               "mac: %s\n",
               hdr.num, hdr.flag,
               mac2str(hdr.mac).c_str());

        for (int i = 0; i < hdr.num; ++i)
            records[i].print();
        printf("###########################\n");
    }
};

int sendNRPPacket(const uint8_t num, const uint8_t flag,
                  pDevice pdev, const NRPRecord *records,
                  const MAC &dst = BroadCastMAC);

#endif