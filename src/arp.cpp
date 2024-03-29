#include "arp.h"

ARPMap arpmap;

bool operator<(const in_addr &a, const in_addr &b)
{
    return a.s_addr < b.s_addr;
}

int ARPCallback(const void *buf, int len, int id)
{
    ARPFrame parp(buf);
    parp.ntoh();

    // parp.print();

    pDevice pdev = hub.getpDevice(id);

    switch (parp.hdr.ar_op)
    {
    case ARPOP_REQUEST:
        if (parp.dstIP.s_addr == pdev->ipaddr.s_addr)
        {
            // printf("ARP Request Received\n");
            MAC srcMAC(parp.srcMAC);
            arpmap.sendARPReply(pdev, parp.srcIP, srcMAC);
        }
        return 0;

    case ARPOP_REPLY:
        // printf("ARP Reply Received\n");
        arpmap.ip_mac_map[parp.srcIP] = MAC(parp.srcMAC);
        return 0;

    default:
        // printf("Arp_Type Unsupported\n");
        return -1;
    }
}

MAC ARPMap::findDestMAC(pDevice pdev, const in_addr &destip)
{
    auto it = ip_mac_map.find(destip);
    if (it != ip_mac_map.end())
        return it->second;

    int res = sendARPRequest(pdev, destip);
    if (res >= 0)
    {
        it = ip_mac_map.find(destip);
        return it->second;
    }
    return BroadCastMAC;
}

int ARPMap::sendARPRequest(pDevice pdev, const in_addr &dest)
{
    std::unique_lock<std::mutex> lck(mtx);

    int found = -1;

    ARPFrame arpframe;
    arpframe.setHeader(ARPOP_REQUEST);
    arpframe.setPayload(pdev->macaddr, pdev->ipaddr, BroadCastMAC, dest);
    arpframe.hton();

    int res = hub.sendFrame(&arpframe, sizeof(ARPFrame),
                            ETHERTYPE_ARP, BroadCastMAC, pdev);

    if (cv.wait_for(lck, std::chrono::seconds(1),
                    [&]() {auto it = ip_mac_map.find(dest);
                    return it != ip_mac_map.end(); }))
    {
        auto it = ip_mac_map.find(dest);
        if (it != ip_mac_map.end())
            found = 0;
    }
    lck.unlock();

    // sleep(1);

    // auto it = ip_mac_map.find(dest);
    // if (it != ip_mac_map.end())
    //     found = 0;
    return found;
}

int ARPMap::sendARPReply(pDevice pdev, const in_addr &destip,
                         const MAC &destmac)
{
    ARPFrame arpframe;
    arpframe.setHeader(ARPOP_REPLY);
    arpframe.setPayload(pdev->macaddr, pdev->ipaddr, destmac, destip);
    arpframe.hton();

    int res = hub.sendFrame(&arpframe, sizeof(ARPFrame),
                            ETHERTYPE_ARP, destmac, pdev);
    // if (res < 0)
    // printf("ARP Reply Failed\n");
    // else
    // printf("ARP Reply Sent\n");
    return res;
}