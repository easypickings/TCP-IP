#include "ip.h"
#include "arp.h"
#include "router.h"

IPPacketReceiveCallback ipcallback = nullptr;
extern int TCPDispatcher(const void *buf, int len,
                         const in_addr &sip, const in_addr &dip);

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback)
{
    ipcallback = callback;
    return 0;
}

int IPCallback(const void *buf, int len, int id)
{
    IPPacket ppkt(buf, len);
    // Checksum?
    if (!ppkt.chkChecksum())
    {
        // printf("IP Checksum Error\n");
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
            // printf("TTL=0!\n");
            return -1;
        }
        Routing r = router.find(destip);
        if (!r.pdev)
        {
            // printf("Can't Find Routing!\n");
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
                // printf("No Destination MAC!\n");
                return -1;
            }
            else
            {
                // printf("Route a packet...\n");
                // ppkt.print();

                ppkt.hdr.ip_ttl -= 1;
                int packetlen = ppkt.hdr.ip_len;
                ppkt.hton();
                ppkt.setChecksum();
                return hub.sendFrame(&ppkt, packetlen, ETHERTYPE_IP,
                                     destMAC, pdev);
            }
        }
    }

    // ppkt.print();
    return TCPDispatcher(ppkt.ippayload, ppkt.getPayloadLen(),
                         destip, srcip);
    //     if (ipcallback)
    //         return ipcallback(ppkt.ippayload, ppkt.getPayloadLen());
    //     return 0;
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
        // printf("Invalid Source IP!\n");
        return -1;
    }

    // find the destination MAC address
    MAC destMAC;
    Routing r = router.find(dest);
    if (!r.pdev)
    {
        // printf("Invalid Destination IP!\n");
        return -1;
    }

    pDevice pdev = r.pdev;
    if (r.dist == 0) // MAP<IP, MAC> & ARP
        destMAC = arpmap.findDestMAC(pdev, dest);
    else // Routing
        destMAC = r.nexthopMAC;
    if (destMAC == BroadCastMAC)
    {
        // printf("Invalid Destination MAC!\n");
        return -1;
    }

    IPPacket packet;
    packet.setHeader(src, dest, proto);
    if (packet.setPayload(buf, len) < 0)
        return -1;
    int packetlen = packet.hdr.ip_len;
    packet.hton();
    packet.setChecksum();

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
        // printf("Wrong NRP Size!\n");
        return -1;
    }
    NRPPacket pnrp(buf, len);
    pnrp.ntoh();
    // pnrp.print();

    uint8_t num = pnrp.hdr.num;
    MAC mac(pnrp.hdr.mac);
    pDevice pcurdev = hub.getpDevice(id);

    // Record updated routings
    NRPRecord updated[NRP_MAX_REC];
    uint8_t up = 0;

    // Update routing table
    for (int i = 0; i < num; ++i)
    {
        NRPRecord record;
        record = pnrp.records[i];
        bool handled = false;
        for (auto &r : router.table)
            // If there exists a routing with exactly
            // the same address range with the record
            if (record.ipprefix.s_addr == r.ipprefix.s_addr &&
                record.slash == r.slash)
            {
                // If the record is a better
                // routing way, update the routing
                if (record.dist + 1 < r.dist)
                {
                    r.nexthopMAC = mac;
                    r.pdev = pcurdev;
                    r.dist = record.dist + 1;

                    // Add a updated record
                    if (up < NRP_MAX_REC)
                    {
                        updated[up] = NRPRecord(r);
                        up += 1;
                    }
                }
                handled = true;
                break;
            }

        // If there is no perfectly
        // matching, add a new routing.
        if (!handled)
        {
            in_addr mask = slash2mask(record.slash);
            Routing r(record.ipprefix, mask, mac,
                      pcurdev, record.dist + 1);
            router.table.insert(r);

            // Add a updated record
            if (up < NRP_MAX_REC)
            {
                updated[up] = NRPRecord(r);
                up += 1;
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

    for (auto &pdev : hub.pdevices)
        // Exclude the device with `id`
        if (pdev != pcurdev)
            // Broadcast updated messages
            sendNRPPacket(up, NRP_OLD_PKT, pdev, updated);

    // Response to a "new" NRP packet
    if (pnrp.hdr.flag == NRP_NEW_PKT)
    {
        // Ouch! Have to copy routing table into NRPRecords!
        NRPRecord whole[NRP_MAX_REC];
        int n = 0;
        for (auto &r : router.table)
        {
            whole[n] = NRPRecord(r);
            n += 1;
            if (n == NRP_MAX_REC)
                break;
        }
        sendNRPPacket(n, NRP_OLD_PKT, pcurdev, whole, mac);
    }
}