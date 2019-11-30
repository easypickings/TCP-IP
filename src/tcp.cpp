#include "tcp.h"
#include "socket.h"

int TCPDispatcher(const void *buf, int len,
                  const in_addr &sip, const in_addr &dip)
{
    TCPPacket ptcp(buf, len);
    // Checksum?
    if (!ptcp.chkChecksum())
    {
        printf("TCP Checksum Error\n");
        return -1;
    }
    ptcp.ntoh();
    // printf("********** RECV ***********\n");
    // ptcp.print();

    if (ptcp.hdr.th_flags == TH_SYN)
    {
        in_addr any;
        any.s_addr = INADDR_ANY;
        pSocket psock = sockhub.getpSocket(sip, ptcp.hdr.th_dport, any, 0);
        if (!psock || !psock->chk_state(LISTEN))
            return -1;
        return psock->receive(ptcp, dip);
    }
    else
    {
        pSocket psock = sockhub.getpSocket(sip, ptcp.hdr.th_dport,
                                           dip, ptcp.hdr.th_sport);
        if (!psock)
            return -1;
        return psock->receive(ptcp, dip);
    }
}