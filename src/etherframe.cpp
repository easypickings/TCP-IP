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

int setFrameReceiveCallback(frameReceiveCallback _callback)
{
    callback = _callback;
    return 0;
}

int EtherCallback(const void *buf, int len, int id)
{
    EtherFrame peth(buf, len);
    peth.ntoh();

    int payloadlen = peth.getPayloadLen();
    if (payloadlen == 0)
        return 0;

    MAC smac(peth.Frame.header.ether_shost);
    MAC dmac(peth.Frame.header.ether_dhost);
    uint16_t ether_type = peth.Frame.header.ether_type;

    pDevice pdev = hub.getpDevice(id);
    MAC SelfMAC = pdev->macaddr;

    if (smac == SelfMAC)
        return 0;

    if (not(dmac == SelfMAC || dmac == BroadCastMAC))
        return 0;

    // printf("\n########EtherFrame#########\n");
    // printf("src mac: %s\n", smac.str().c_str());
    // printf("dst mac: %s\n", dmac.str().c_str());
    // printf("ether_type: 0x%04x\n", ether_type);
    // printf("frame len: %d\n", peth.len);

    switch (ether_type)
    {
    case ETHERTYPE_IP:
        return IPCallback(peth.Frame.payload, payloadlen, id);

    case ETHERTYPE_ARP:
        return ARPCallback(peth.Frame.payload, payloadlen, id);

    case ETHERTYPE_NRP:
        return NRPCallback(peth.Frame.payload, payloadlen, id);

    default:
        // printf("Ether_Type Unsupported\n");
        return -1;
    }
}