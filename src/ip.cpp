#include "ip.h"
#include "arp.h"
#include "router.h"

IPPacketReceiveCallback ipupcallback = nullptr;

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback)
{
    ipupcallback = callback;
    return 0;
}

int IPCallback(const void *buf, int len, int id)
{
    IPPacket ppkt(buf, len);
    // Checksum?
    if (!ppkt.checkChksum())
    {
        printf("Checksum Error\n");
        return -1;
    }
    ppkt.ntoh();

    in_addr srcip = ppkt.hdr.ip_src;
    in_addr destip = ppkt.hdr.ip_dst;

    // Routing...
    if (!hub.haveIP(destip))
    {
        if (ppkt.hdr.ip_ttl == 0)
        {
            printf("TTL=0!\n");
            return -1;
        }
        Routing r = router.find(destip);
        if (!r.pdev)
        {
            printf("Can't Find Routing!\n");
            return -1;
        }
        else
        {
            pDevice pdev = r.pdev;
            MAC destMAC;
            if (r.dist == 0) // MAP<IP, MAC> & ARP
                destMAC = arpmap.findDestMAC(pdev, destip);
            else // Routing
                destMAC = r.nexthopMAC;
            if (destMAC == BroadCastMAC)
            {
                printf("No Destination MAC!\n");
                return -1;
            }
            else
            {
                ppkt.hdr.ip_ttl -= 1;
                int packetlen = ppkt.hdr.ip_len;
                ppkt.hton();
                ppkt.setChksum();
                return hub.sendFrame(&ppkt, packetlen, ETHERTYPE_IP,
                                     destMAC, pdev);
            }
        }
    }

    printf("\n#########IPPacket##########\n");
    printf("src ip: %s\n", inet_ntoa(srcip));
    printf("dst ip: %s\n", inet_ntoa(destip));
    printf("version: %d\n", ppkt.hdr.ip_v);
    printf("ihl: %d\n", ppkt.hdr.ip_hl);
    printf("protocol: 0x%x\n", ppkt.hdr.ip_p);
    printf("ttl: %d\n", ppkt.hdr.ip_ttl);
    printf("total len: %d\n", ppkt.hdr.ip_len);

    if (ipupcallback)
        return ipupcallback(ppkt.ippayload, ppkt.getPayloadLen());
    return 0;
}

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
                 int proto, const void *buf, int len)
{
    if (!hub.haveIP(src))
    {
        printf("Invalid Source IP!\n");
        return -1;
    }

    // find the destination MAC address
    MAC destMAC;
    Routing r = router.find(dest);
    if (!r.pdev)
    {
        printf("Invalid Destination IP!\n");
        return -1;
    }

    pDevice pdev = r.pdev;
    if (r.dist == 0) // MAP<IP, MAC> & ARP
        destMAC = arpmap.findDestMAC(pdev, dest);
    else // Routing
        destMAC = r.nexthopMAC;
    if (destMAC == BroadCastMAC)
    {
        printf("Invalid Destination MAC!\n");
        return -1;
    }

    IPPacket packet;
    packet.setHeader(src, dest, proto);
    if (packet.setPayload(buf, len) < 0)
        return -1;
    int packetlen = packet.hdr.ip_len;
    packet.hton();
    packet.setChksum();

    int res = hub.sendFrame(&packet, packetlen, ETHERTYPE_IP,
                            destMAC, pdev);
    // if (res < 0)
    //     printf("Packet Failed\n");
    // else
    //     printf("Packet Sent\n");
    return res;
}

/**
 * @brief Manully add an item to routing table. 
 * Useful when talking with real Linux machines.
 * 
 * @param dest The destination IP prefix.
 * @param mask The subnet mask of the destination IP prefix.
 * @param nextHopMAC MAC address of the next hop.
 * @param device Name of device to send packets on.
 * @return 0 on success, -1 on error
 */
int setRoutingTable(const in_addr &dest, const in_addr &mask,
                    const MAC &nextHopMAC, const char *device)
{
    pDevice pdev = hub.getpDevice(device);
    Routing r(dest, mask, nextHopMAC, pdev);
    router.table.insert(r);
}

uint16_t getChecksum(const void *vdata, size_t length)
{
    // Cast the data pointer to one that can be indexed.
    char *data = (char *)vdata;

    // Initialise the accumulator.
    uint64_t acc = 0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset = ((uintptr_t)data) & 3;
    if (offset)
    {
        size_t count = 4 - offset;
        if (count > length)
            count = length;
        uint32_t word = 0;
        memcpy(offset + (char *)&word, data, count);
        acc += ntohl(word);
        data += count;
        length -= count;
    }

    // Handle any complete 32-bit blocks.
    char *data_end = data + (length & ~3);
    while (data != data_end)
    {
        uint32_t word;
        memcpy(&word, data, 4);
        acc += ntohl(word);
        data += 4;
    }
    length &= 3;

    // Handle any partial block at the end of the data.
    if (length)
    {
        uint32_t word = 0;
        memcpy(&word, data, length);
        acc += ntohl(word);
    }

    // Handle deferred carries.
    acc = (acc & 0xffffffff) + (acc >> 32);
    while (acc >> 16)
    {
        acc = (acc & 0xffff) + (acc >> 16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset & 1)
    {
        acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

int NRPCallback(const void *buf, int len, int id)
{
    if (len % 8)
    {
        printf("Wrong NRP Size!\n");
        return -1;
    }
    NRPPacket pnrp(buf, len);
    pnrp.ntoh();

    uint8_t num = pnrp.hdr.num;
    MAC mac(pnrp.hdr.mac);
    pDevice pdev = hub.getpDevice(id);

    // Record updated routings
    NRPRecord updated[NRP_MAX_REC];
    uint8_t upnum = 0;

    // Update routing table
    for (int i = 0; i < num; ++i)
    {
        NRPRecord record = pnrp.records[i];
        bool handled = false;
        for (auto &routing : router.table)
        {
            // If there exists a routing with exactly
            // the same address range with the record
            if (record.ipprefix.s_addr == routing.ipprefix.s_addr &&
                record.slash == routing.slash)
            {
                // If the record is a better
                // routing way, update the routing
                if (record.dist + 1 < routing.dist)
                {
                    routing.nexthopMAC = mac;
                    routing.pdev = pdev;
                    routing.dist = record.dist + 1;

                    // Add a updated record
                    if (upnum < NRP_MAX_REC) // Only store first NRP_MAX_REC updates
                    {
                        updated[upnum].ipprefix = routing.ipprefix;
                        updated[upnum].slash = routing.slash;
                        updated[upnum].dist = routing.dist;
                        upnum += 1;
                    }
                }
                handled = true;
                break;
            }
        }

        // If there is no perfectly
        // matching, add a new routing.
        if (!handled)
        {
            in_addr mask = slash2mask(record.slash);
            Routing r(record.ipprefix, mask, mac, pdev);
            r.dist = record.dist + 1;
            router.table.insert(r);

            // Add a updated record
            if (upnum < NRP_MAX_REC) // Only store first NRP_MAX_REC updates
            {
                updated[upnum].ipprefix = r.ipprefix;
                updated[upnum].slash = r.slash;
                updated[upnum].dist = r.dist;
                upnum += 1;
            }
        }
    }

    // Send message after update:
    //      Send all the updated routings to all the neighbors except
    //        those in the same subnet. (neighbors in the same subnet
    //        will receive the same message as this host do at the
    //        same time, because messages are broadcasted.) To exclude
    //        neighbors in the same subnet, just use all the devices
    //        except the device with `id` to send.
    //        (My primitive thought was to send the whole routing table
    //        to save the coding for record update routings, but this
    //        will cause infinitive message sending if there is a cycle
    //        in the topology.)
    //      If received a "new" NRP packet (pnrp.flag == NRP_NEW_PKT),
    //        send the whole updated table back to the sender as well.
    //        (Otherwise, consider when a host is newly added to the
    //        network and it broadcasts its local routing table. If we
    //        don't response to its "new" NRP packet, then when there
    //        is no cycle in the topology, the new host will never get
    //        any other routing information.)
    NRPPacket nrppacket;
    nrppacket.hdr.num = upnum;
    nrppacket.hdr.flag = NRP_OLD_PKT;
    memcpy(nrppacket.records, updated, sizeof(nrppacket.records));

    for (auto &device : hub.pdevices)
        // Exclude the device with `id`
        if (device != pdev)
        {
            memcpy(nrppacket.hdr.mac, device->macaddr.addr, ETHER_ADDR_LEN);
            int nrppacketlen = sizeof(nrppacket.hdr) +
                               sizeof(NRPRecord) * nrppacket.hdr.num;
            nrppacket.hton();
            hub.sendFrame(&nrppacket, nrppacketlen,
                          ETHERTYPE_NRP, BroadCastMAC, device);
        }

    // Response to a "new" NRP packet
    if (pnrp.hdr.flag == NRP_NEW_PKT)
    {
        // Ouch! Have to copy the routing table into a NRPRecord array!
        NRPPacket response;
        int rnum = 0;
        for (auto &routing : router.table)
        {
            response.records[rnum].ipprefix = routing.ipprefix;
            response.records[rnum].slash = routing.slash;
            response.records[rnum].dist = routing.dist;
            rnum += 1;
            if (rnum == NRP_MAX_REC) // Can only take NRP_MAX_REC records
                break;
        }
        response.hdr.num = rnum;
        response.hdr.flag = NRP_OLD_PKT;
        memcpy(response.hdr.mac, pdev->macaddr.addr, ETHER_ADDR_LEN);

        int responselen = sizeof(response.hdr) +
                          sizeof(NRPRecord) * response.hdr.num;
        response.hton();
        hub.sendFrame(&response, responselen, ETHERTYPE_NRP, mac, pdev);
    }
}