#include "router.h"

RoutingTable router;

bool operator<(const Routing &a, const Routing &b)
{
    if (a.slash > b.slash)
        return true;
    if (a.ipprefix.s_addr < b.ipprefix.s_addr)
        return true;
    return false;
}

in_addr slash2mask(uint16_t slash)
{
    in_addr ip;
    if (slash == 0)
        ip.s_addr = 0;
    else
        ip.s_addr = ntohl(~0 << (32 - slash));
    return ip;
}

void RoutingTable::autoinit()
{
    // Add local routings to routing table
    for (auto &pdev : hub.pdevices)
    {
        Routing r(pdev->ipaddr, pdev->netmask,
                  pdev->macaddr, pdev);
        r.dist = 0;
        table.insert(r);
    }

    // print();

    // Send a "new" NRP packet
    NRPPacket request;
    int rnum = 0;
    for (auto &routing : router.table)
    {
        request.records[rnum].ipprefix = routing.ipprefix;
        request.records[rnum].slash = routing.slash;
        request.records[rnum].dist = routing.dist;
        rnum += 1;
        if (rnum == NRP_MAX_REC) // Can only take NRP_MAX_REC records
            break;
    }
    request.hdr.num = rnum;
    request.hdr.flag = NRP_NEW_PKT;

    for (auto &pdev : hub.pdevices)
    {
        memcpy(request.hdr.mac, pdev->macaddr.addr, ETHER_ADDR_LEN);
        int requestlen = sizeof(request.hdr) +
                         sizeof(NRPRecord) * request.hdr.num;
        request.hton();
        hub.sendFrame(&request, requestlen, ETHERTYPE_NRP, BroadCastMAC, pdev);
    }
}