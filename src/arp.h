#ifndef ARP_H
#define ARP_H

#include <netinet/ip.h>
#include "device.h"
#include <map>
#include <mutex>
#include <condition_variable>

bool operator<(const in_addr &a, const in_addr &b);

struct ARPFrame
{
    struct
    {
        arphdr hdr;
        u_char srcMAC[ETHER_ADDR_LEN];
        in_addr srcIP;
        u_char dstMAC[ETHER_ADDR_LEN];
        in_addr dstIP;
    } __attribute__((__packed__));

    ARPFrame() { memset(&hdr, 0, sizeof(ARPFrame)); }
    ARPFrame(const void *buf) { memcpy(&hdr, buf, sizeof(ARPFrame)); }
    void setHeader(u_short op)
    {
        hdr.ar_hrd = ARPHRD_ETHER;
        hdr.ar_pro = ETHERTYPE_IP;
        hdr.ar_hln = ETHER_ADDR_LEN;
        hdr.ar_pln = 4;
        hdr.ar_op = op;
    }

    void setPayload(const MAC &smac, const in_addr &sip,
                    const MAC &dmac, const in_addr &dip)
    {
        memcpy(srcMAC, smac.addr, ETHER_ADDR_LEN);
        srcIP = sip;
        memcpy(dstMAC, dmac.addr, ETHER_ADDR_LEN);
        dstIP = dip;
    }

    void hton()
    {
        hdr.ar_hrd = htons(hdr.ar_hrd);
        hdr.ar_pro = htons(hdr.ar_pro);
        hdr.ar_op = htons(hdr.ar_op);
    }

    void ntoh()
    {
        hdr.ar_hrd = ntohs(hdr.ar_hrd);
        hdr.ar_pro = ntohs(hdr.ar_pro);
        hdr.ar_op = ntohs(hdr.ar_op);
    }
};

struct ARPMap
{
    std::map<in_addr, MAC> ip_mac_map;
    // std::condition_variable cv;
    // std::mutex mtx;

    MAC findDestMAC(pDevice pdev, const in_addr &destip);
    int sendARPRequest(pDevice pdev, const in_addr &dest);
    int sendARPReply(pDevice pdev, const in_addr &destip,
                     const MAC &destmac);

    void print()
    {
        printf("IP Address\tMAC Address\n");
        for (auto m : ip_mac_map)
        {
            std::string ip = inet_ntoa(m.first);
            printf("[%s]\t[%s]\n",
                   ip.c_str(), m.second.str().c_str());
        }
    }
};

extern ARPMap arpmap;

int ARPCallback(const void *buf, int len, int id);

#endif