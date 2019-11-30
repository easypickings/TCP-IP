#ifndef TCP_H
#define TCP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "ip.h"
#include "arp.h"
#include "router.h"

#define TCP_DATA_LEN IP_DATA_LEN - sizeof(tcphdr)

struct TCPPacket
{
    struct
    {
        tcphdr hdr;
        u_char payload[TCP_DATA_LEN];
    } __attribute__((__packed__));
    int len;

    TCPPacket() { memset(&hdr, 0, sizeof(TCPPacket)); }
    TCPPacket(const void *buf, int l)
    {
        if (l > sizeof(TCPPacket))
            len = sizeof(TCPPacket);
        else
            len = l;
        memcpy(&hdr, buf, len);
    }

    void setHeader(const uint16_t &sport, const uint16_t &dport,
                   const uint32_t &seq, const uint32_t &ack,
                   const uint8_t &flags)
    {
        hdr.th_sport = sport;
        hdr.th_dport = dport;
        hdr.th_seq = seq;
        hdr.th_ack = ack;
        hdr.th_off = 20U;
        hdr.th_flags = flags;
        hdr.th_win = UINT16_MAX;
    }

    int setPayload(const void *buf = NULL, int l = 0)
    {
        if (l > IP_DATA_LEN - sizeof(hdr))
        {
            printf("TCPPayload Oversize!\n");
            return -1;
        }
        if (buf)
            memcpy(payload, buf, l);
        len = sizeof(hdr) + l;
        return 0;
    }

    int getPayloadLen() { return len - sizeof(hdr); }

    void hton()
    {
        hdr.th_sport = htons(hdr.th_sport);
        hdr.th_dport = htons(hdr.th_dport);
        hdr.th_seq = htonl(hdr.th_seq);
        hdr.th_ack = htonl(hdr.th_ack);
        hdr.th_win = htons(hdr.th_win);
        hdr.th_urp = htons(hdr.th_urp);
    }

    void ntoh()
    {
        hdr.th_sport = ntohs(hdr.th_sport);
        hdr.th_dport = ntohs(hdr.th_dport);
        hdr.th_seq = ntohl(hdr.th_seq);
        hdr.th_ack = ntohl(hdr.th_ack);
        hdr.th_win = ntohs(hdr.th_win);
        hdr.th_urp = ntohs(hdr.th_urp);
    }

    void setChecksum()
    {
        hdr.th_sum = 0;
        hdr.th_sum = getChecksum(&hdr, sizeof(hdr));
    }

    bool chkChecksum()
    {
        auto res = getChecksum(&hdr, sizeof(hdr));
        return res == 0;
    }

    void print() const
    {
        // printf("######## TCPPacket ########\n");
        printf("src port: %u\n", hdr.th_sport);
        printf("dst port: %u\n", hdr.th_dport);
        printf("seq: %u\n", hdr.th_seq);
        printf("ack: %u\n", hdr.th_ack);
        printf("syn: %u ack: %u fin: %u rst: %u\n",
               hdr.syn, hdr.ack, hdr.fin, hdr.rst);
        printf("len: %d\n", len);
        printf("###########################\n\n");
    }
};

#endif