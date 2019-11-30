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

void RoutingTable::route()
{
    // Encapsulate local routings into NRPRecords
    NRPRecord local[NRP_MAX_REC];
    int num = 0;
    for (auto &r : router.table)
    {
        local[num] = NRPRecord(r);
        num += 1;
        if (num == NRP_MAX_REC)
            break;
    }

    // Broadcast a "new" NRP packet
    for (auto &pdev : hub.pdevices)
        sendNRPPacket(num, NRP_NEW_PKT, pdev, local);
}

int sendNRPPacket(const uint8_t num, const uint8_t flag,
                  pDevice pdev, const NRPRecord *records,
                  const MAC &dst)
{
    NRPPacket nrppacket;
    nrppacket.setHeader(num, flag, pdev->macaddr);
    nrppacket.setPayload(records, num);
    int len = nrppacket.getLen();
    nrppacket.hton();
    int res = hub.sendFrame(&nrppacket, len, ETHERTYPE_NRP, dst, pdev);
    return res;
}