#include "device.h"

extern int IPCallback(const void *buf, int len, int id);
extern int ARPCallback(const void *buf, int len, int id);
extern int NRPCallback(const void *buf, int len, int id);

std::string mac2str(const u_char *mac)
{
    char cstr[18] = "";
    sprintf(cstr, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    std::string s(cstr);
    return s;
}

void str2mac(u_char *mac, const char *str)
{
    int tmp[6] = {0};
    sscanf(str, "%x:%x:%x:%x:%x:%x",
           &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for (int i = 0; i < 6; ++i)
        mac[i] = static_cast<u_char>(tmp[i]);
}

int EtherCallback(const void *buf, int len, int id)
{
    EtherFrame peth(buf, len);
    peth.ntoh();

    int payloadlen = peth.getPayloadLen();
    if (payloadlen == 0)
        return 0;

    MAC smac(peth.hdr.ether_shost);
    MAC dmac(peth.hdr.ether_dhost);
    uint16_t ether_type = peth.hdr.ether_type;

    pDevice pdev = hub.getpDevice(id);
    MAC SelfMAC = pdev->macaddr;

    if (smac == SelfMAC)
        return 0;

    if (not(dmac == SelfMAC || dmac == BroadCastMAC))
        return 0;

    // peth.print();

    switch (ether_type)
    {
    case ETHERTYPE_IP:
        return IPCallback(peth.payload, payloadlen, id);

    case ETHERTYPE_ARP:
        return ARPCallback(peth.payload, payloadlen, id);

    case ETHERTYPE_NRP:
        return NRPCallback(peth.payload, payloadlen, id);

    default:
        // printf("Ether_Type Unsupported\n");
        return -1;
    }
}