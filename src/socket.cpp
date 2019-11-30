#include "socket.h"

using namespace std::literals::chrono_literals;

static inline int before(__u32 seq1, __u32 seq2)
{
    return (__s32)(seq1 - seq2) < 0;
}
#define after(seq2, seq1) before(seq1, seq2)

int __real_socket(int domain, int type, int protocol);
int __real_bind(int socket, const struct sockaddr *address,
                socklen_t address_len);
int __real_listen(int socket, int backlog);
int __real_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len);
int __real_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len);
ssize_t __real_read(int fildes, void *buf, size_t nbyte);
ssize_t __real_write(int fildes, const void *buf, size_t nbyte);
int __real_close(int fildes);
int __real_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);
void __real_freeaddrinfo(struct addrinfo *res);

/*****************
 **** Socket ****
*****************/
int Socket::current_fd = INT32_MAX;

// No-reentrance guaranteed
int Socket::send(const TCPPacket &tcppacket)
{
    std::lock_guard<std::mutex> lck(send_mtx);

    // TCPPacket tcp = tcppacket;
    // tcp.ntoh();
    // printf("********** SEND ***********\n");
    // tcp.print();

    int res =
        sendIPPacket(srcIP, dstIP, proto,
                     reinterpret_cast<const void *>(&tcppacket),
                     tcppacket.len);
    if (res < 0)
        printf("SEND TCPPACKET FAILED\n");
    return res;
}

// No-reentrance, in-order transfer guaranteed
int Socket::safe_send(uint8_t flags, const void *buf, uint32_t len)
{
    std::lock_guard<std::mutex> lck(ssend_mtx);
    TCPPacket pkt;
    pkt.setHeader(srcPort, dstPort, seq_send, seq_recv, flags);
    pkt.setPayload(buf, len);
    pkt.hton();
    pkt.setChecksum();

    if (buf)
        add_seq_send(len);
    else if (flags != TH_ACK)
        add_seq_send(1);

    // Timeout and Retransmission
    std::unique_lock<std::mutex> lk(ok_mtx);
    ok = false;      // Not ACKed yet
    retrans = false; // Needn't retransmit yet
    for (int i = 0; i < MAX_RETRY; ++i)
    {
        send(pkt);
        cv_ok.wait_for(lk, std::chrono::seconds(TCP_TIMEOUT),
                       [&]() { return ok || retrans; });
        if (ok)
            break;
    }
    if (!ok)
    {
        lk.unlock();
        return -1;
    }
    else
    {
        lk.unlock();
        return 0;
    }
}

int Socket::receive(TCPPacket &tcppacket, const in_addr &ip)
{
    unsigned int seq = tcppacket.hdr.th_seq,
                 seq_ack = tcppacket.hdr.th_ack;
    uint8_t flag = tcppacket.hdr.th_flags;
    uint16_t sport = tcppacket.hdr.th_sport,
             dport = tcppacket.hdr.th_dport;
    int len = tcppacket.getPayloadLen();

    if (!chk_state(ESTABLISHED))
    {
        switch (state)
        {
        case CLOSED:
            send_ack(TH_RST); // Send RST
            break;

        case LISTEN:
            if (flag == TH_SYN)
            {
                Request r(ip, sport, seq);
                std::lock_guard<std::mutex> lck(req_mtx);
                if (backlog < max_backlog)
                {
                    req.push(r);
                    backlog++;
                    cv_req.notify_one();
                }
            }
            break;

        case SYN_RECV:
            if (flag == TH_RST) // Reset
                return reset();
            if (flag == TH_ACK)
            {                        // -> ESTABLISHED
                if (seq != seq_recv) // Ignore
                    return 0;
                if (seq_ack != seq_send) // Ignore
                    return 0;
                lst_ack_recv = seq_ack;
                set_state(ESTABLISHED);
                set_ok();
            }
            break;

        case SYN_SENT:
            if (flag == TH_RST) // Reset
                return reset();
            if (flag == TH_SYN + TH_ACK)
            {                            // -> ESTABLISHED
                if (seq_ack != seq_send) // Ignore
                    return 0;
                // ini_seq_recv = seq;
                seq_recv = seq;
                add_seq_recv(1);
                lst_ack_recv = seq_ack;
                set_state(ESTABLISHED);
                send_ack(); // Send ACK
                set_ok();
            }
            else if (flag == TH_SYN)
            { // -> SYN_RECVs
                // ini_seq_recv = seq;
                seq_recv = seq;
                add_seq_recv(1);
                set_state(SYN_RECV);
                send_ack(); // Send ACK
            }
            break;

        case FIN_WAIT1:
            if (flag == TH_RST) // Reset
                return reset();
            if (flag == TH_FIN)
            {                        // -> CLOSING
                if (seq != seq_recv) // Ignore
                    return 0;
                add_seq_recv(1); // If FIN with data, more work to do
                set_state(CLOSING);
                send_ack(); // Send ACK
            }
            else if (flag == TH_ACK)
            {                        // -> FIN_WAIT2
                if (seq != seq_recv) // Ignore
                    return 0;
                if (seq_ack != seq_send) // Ignore
                    return 0;
                lst_ack_recv = seq_ack;
                set_state(FIN_WAIT2);
                set_ok();
            }
            else if (flag == TH_FIN + TH_ACK)
            {                        // -> TIME_WAIT
                if (seq != seq_recv) // Ignore
                    return 0;
                if (seq_ack != seq_send) // Ignore
                    return 0;
                add_seq_recv(1); // If FIN with data, more work to do
                lst_ack_recv = seq_ack;
                set_state(TIME_WAIT);
                send_ack(); // Send ACK
                set_ok();
            }
            else if (flag == 0)
            {     // More data incoming...
                { // Check seq
                    std::lock_guard<std::mutex> lck(buf_mtx);
                    if ((seq == seq_recv) &&
                        (buffer.size() + len < SOCK_BUF_SIZE))
                    { // Good data, update seq_recv and push to buffer
                        add_seq_recv(len);
                        for (int i = 0; i < len; ++i)
                            buffer.push(tcppacket.payload[i]);
                    }
                }
                send_ack(); // Send ACK (dup if not good data)
            }
            break;

        case FIN_WAIT2:
            if (flag == TH_RST) // Reset
                return reset();
            if (flag == TH_FIN)
            {                        // -> TIME_WAIT
                if (seq != seq_recv) // Ignore
                    return 0;
                add_seq_recv(1); // If FIN with data, more work to do
                set_state(TIME_WAIT);
                send_ack(); // Send ACK
            }
            else if (flag == 0 || flag == TH_ACK)
            {     // More data incoming...
                { // Check seq
                    std::lock_guard<std::mutex> lck(buf_mtx);
                    if ((seq == seq_recv) &&
                        (buffer.size() + len < SOCK_BUF_SIZE))
                    { // Good data, update seq_recv and push to buffer
                        add_seq_recv(len);
                        for (int i = 0; i < len; ++i)
                            buffer.push(tcppacket.payload[i]);
                    }
                }
                send_ack(); // Send ACK (dup if not good data)
                // Needn't check ack since we don't send any more data
            }
            break;

        case CLOSING:
            if (flag == TH_ACK)
            {                        // -> TIME_WAIT
                if (seq != seq_recv) // Ignore
                    return 0;
                if (seq_ack != seq_send) // Ignore
                    return 0;
                lst_ack_recv = seq_ack;
                set_state(TIME_WAIT);
                set_ok();
            }
            break;

        case LAST_ACK:
            if (flag == TH_ACK)
            {                        // -> CLOSED
                if (seq != seq_recv) // Ignore
                    return 0;
                if (seq_ack != seq_send) // Ignore
                    return 0;
                lst_ack_recv = seq_ack;
                set_state(CLOSED);
                set_ok();
            }
            break;
        }
    }
    else
    {
        if (flag == TH_RST) // Reset
            return reset();
        if (flag == 0 || flag == TH_ACK)
        {
            { // Check seq
                std::lock_guard<std::mutex> lck(buf_mtx);
                if ((seq == seq_recv) &&
                    (buffer.size() + len < SOCK_BUF_SIZE))
                { // Good data, update seq_recv and push to buffer
                    add_seq_recv(len);
                    for (int i = 0; i < len; ++i)
                        buffer.push(tcppacket.payload[i]);
                }
            }
            if (len > 0)
                send_ack(); // Send ACK (dup if not good data)

            if (flag == TH_ACK)
            { // Check ack
                if (seq_ack == seq_send)
                { // Good ack, ok
                    lst_ack_recv = seq_ack;
                    set_ok();
                }
                else if (seq_ack == lst_ack_recv)
                { // Dup ACK, retransmit
                    set_retrans();
                }
                // Else strange ACK? Can't happen?
            }
        }
        else if (flag == TH_FIN)
        {                        // -> CLOSE_WAIT
            if (seq != seq_recv) // Ignore
                return 0;
            add_seq_recv(1); // If FIN with data, more work to do
            set_state(CLOSE_WAIT);
            send_ack(); // Send ACK
        }
    }
}

int Socket::bind(const struct sockaddr *address, socklen_t address_len)
{
    if (!chk_state(CLOSED))
        ERR(EINVAL);

    const struct sockaddr_in *addr =
        reinterpret_cast<const struct sockaddr_in *>(address);

    if (!hub.haveIP(addr->sin_addr))
        ERR(EINVAL);
    pDevice pdev = hub.getpDevice(addr->sin_addr);

    if (addr->sin_port != 0)
    {
        if (!pdev->acquirePort(addr->sin_port))
            ERR(EADDRINUSE);
        srcIP = addr->sin_addr;
        srcPort = addr->sin_port;
    }
    else // Allocate a port
    {
        srcIP = addr->sin_addr;
        srcPort = pdev->allocPort();
    }
    return 0;
}

int Socket::listen(int bl)
{
    if (!chk_state(CLOSED))
        ERR(EINVAL);

    if (bl < max_backlog)
        max_backlog = bl;
    if (max_backlog < 0)
        max_backlog = 0;
    set_state(LISTEN);
    return 0;
}

int Socket::connect(const struct sockaddr *address,
                    socklen_t address_len)
{
    if (!chk_state(CLOSED))
        ERR(EINVAL);

    const struct sockaddr_in *addr =
        reinterpret_cast<const struct sockaddr_in *>(address);

    // Bind srcIP and srcPort
    pDevice pdev = router.find(addr->sin_addr).pdev;
    if (!pdev)
        ERR(EADDRNOTAVAIL);
    srcIP = pdev->ipaddr;
    srcPort = pdev->allocPort();

    // Bind dstIP and dstPort
    dstIP = addr->sin_addr;
    dstPort = addr->sin_port;

    // Send SYN
    set_state(SYN_SENT);
    safe_send(TH_SYN);

    if (chk_state(ESTABLISHED))
        return 0;
    else
    {
        set_state(CLOSED);
        ERR(ETIMEDOUT);
    }
}

int Socket::accept(struct sockaddr *address, socklen_t *address_len)
{
    if (!chk_state(LISTEN))
        ERR(EINVAL);
    std::unique_lock<std::mutex> lck(req_mtx);
    cv_req.wait(lck, [&]() { return req.size() > 0; });
    auto r = req.front();
    req.pop();
    backlog--;
    lck.unlock();

    // Create a new socket
    int newfd = sockhub.addSocket();
    pSocket psock = sockhub.getpSocket(newfd);
    psock->srcIP = srcIP;
    psock->srcPort = srcPort;
    psock->dstIP = r.ip;
    psock->dstPort = r.port;
    // psock->ini_seq_recv = r.seq;
    psock->seq_recv = r.seq;
    psock->add_seq_recv(1);
    // Send SYN+ACK
    psock->set_state(SYN_RECV);
    psock->safe_send(TH_SYN + TH_ACK);

    if (!psock->chk_state(ESTABLISHED))
    {
        psock->set_state(CLOSED);
        ERR(ETIMEDOUT);
    }

    struct sockaddr_in *addr =
        reinterpret_cast<struct sockaddr_in *>(address);
    addr->sin_family = AF_INET;
    addr->sin_port = r.port;
    addr->sin_addr = r.ip;
    *address_len = INET_ADDRSTRLEN;
    return newfd;
}

ssize_t Socket::read(void *buf, size_t nbyte)
{
    // if (!chk_state(ESTABLISHED))
    //     ERR(ENOTCONN);
    std::lock_guard<std::mutex> lck(buf_mtx);
    if (buffer.size() < nbyte)
        nbyte = buffer.size();
    u_char *cbuf = (u_char *)buf;
    int i = 0;
    for (; i < nbyte; ++i)
    {
        cbuf[i] = buffer.front();
        buffer.pop();
    }
    cbuf[i] = 0;
    return nbyte;
}

ssize_t Socket::write(const void *buf, size_t nbyte)
{
    // if (!chk_state(ESTABLISHED))
    //     ERR(ENOTCONN);
    if (nbyte > TCP_DATA_LEN)
        ERR(EFBIG);
    if (safe_send(0, buf, nbyte) < 0)
        ERR(ETIMEDOUT);
    return nbyte;
}

int Socket::close()
{
    if (chk_state(SYN_SENT) || chk_state(LISTEN))
    {
        set_state(CLOSED);
        return 0;
    }
    if (chk_state(ESTABLISHED))
        set_state(FIN_WAIT1);

    if (chk_state(CLOSE_WAIT))
        set_state(LAST_ACK);

    // Send FIN
    safe_send(TH_FIN);

    // 2MSL timer
    std::this_thread::sleep_for(std::chrono::seconds(2 * MSL));

    if (chk_state(CLOSED) || chk_state(TIME_WAIT))
        return 0;
    else
        return -1;
}

/********************
 **** SocketHub ****
********************/
SocketHub sockhub;

int SocketHub::addSocket()
{
    pSocket psock = std::make_shared<Socket>();
    psockets.push_back(psock);
    return psock->fd;
}

int SocketHub::addSocket(int domain, int type, int protocol)
{
    pSocket psock = std::make_shared<Socket>(domain, type, protocol);
    psockets.push_back(psock);
    return psock->fd;
}

int SocketHub::bind(int socket, const struct sockaddr *address,
                    socklen_t address_len)
{
    const struct sockaddr_in *addr =
        reinterpret_cast<const struct sockaddr_in *>(address);
    if (!addr)
        ERR(EINVAL);
    if (addr->sin_family != AF_INET)
        ERR(EAFNOSUPPORT);
    if (address_len != INET_ADDRSTRLEN)
        ERR(EINVAL);

    if (addr->sin_addr.s_addr == INADDR_ANY)
        ERR(EINVAL);

    pSocket s = getpSocket(socket);
    if (!s)
        ERR(ENOTSOCK);
    return s->bind(address, address_len);
}

int SocketHub::listen(int socket, int backlog)
{
    pSocket s = getpSocket(socket);
    if (!s)
        ERR(ENOTSOCK);
    return s->listen(backlog);
}

int SocketHub::connect(int socket, const struct sockaddr *address,
                       socklen_t address_len)
{
    const struct sockaddr_in *addr =
        reinterpret_cast<const struct sockaddr_in *>(address);
    if (!addr)
        ERR(EINVAL);
    if (addr->sin_family != AF_INET)
        ERR(EAFNOSUPPORT);
    if (address_len != INET_ADDRSTRLEN)
        ERR(EINVAL);

    pSocket s = getpSocket(socket);
    if (!s)
        ERR(ENOTSOCK);
    return s->connect(address, address_len);
}

int SocketHub::accept(int socket, struct sockaddr *address,
                      socklen_t *address_len)
{
    pSocket s = getpSocket(socket);
    if (!s)
        ERR(ENOTSOCK);
    return s->accept(address, address_len);
}

ssize_t SocketHub::read(int socket, void *buf, size_t nbyte)
{
    if (!buf)
        ERR(EINVAL);
    pSocket s = getpSocket(socket);
    if (!s)
        ERR(EBADF);
    return s->read(buf, nbyte);
}

ssize_t SocketHub::write(int socket, const void *buf, size_t nbyte)
{
    if (!buf)
        ERR(EINVAL);
    pSocket s = getpSocket(socket);
    if (!s)
        ERR(EBADF);
    return s->write(buf, nbyte);
}

int SocketHub::close(int socket)
{
    pSocket s = getpSocket(socket);
    if (!s)
        ERR(EBADF);
    if (s->close() < 0)
        ERR(EINVAL);
    for (auto it = psockets.begin(); it != psockets.end();)
    { // Remove from sockhub
        if (*it == s)
        {
            it = psockets.erase(it);
            break;
        }
        ++it;
    }
    return 0;
}

/********************
 ******* API *******
********************/

int __wrap_socket(int domain, int type, int protocol)
{
    return sockhub.addSocket(domain, type, protocol);
}

int __wrap_bind(int socket, const struct sockaddr *address,
                socklen_t address_len)
{
    return sockhub.bind(socket, address, address_len);
}

int __wrap_listen(int socket, int backlog)
{
    return sockhub.listen(socket, backlog);
}

int __wrap_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len)
{
    return sockhub.connect(socket, address, address_len);
}

int __wrap_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len)
{
    return sockhub.accept(socket, address, address_len);
}

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte)
{
    // if (fildes <= MAX_KERNEL_FD)
    //     return __real_read(fildes, buf, nbyte);
    return sockhub.read(fildes, buf, nbyte);
}

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte)
{
    // if (fildes <= MAX_KERNEL_FD)
    //     return __real_write(fildes, buf, nbyte);
    return sockhub.write(fildes, buf, nbyte);
}

int __wrap_close(int fildes)
{
    // if (fildes <= MAX_KERNEL_FD)
    //     return __real_close(fildes);
    return sockhub.close(fildes);
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res)
{
    if (!node && !service)
        return EAI_NONAME;

    if (hints)
    {
        if (hints->ai_family != AF_INET)
            return EAI_FAMILY;
        if ((hints->ai_socktype != SOCK_STREAM) ||
            (hints->ai_protocol != IPPROTO_TCP))
            return EAI_SOCKTYPE;
        if (hints->ai_flags != 0)
            return EAI_BADFLAGS;
    }

    sockaddr_in *addr = new sockaddr_in;
    addr->sin_family = AF_INET;
    if (inet_aton(node, &(addr->sin_addr)) == 0)
        return EAI_NONAME;
    addr->sin_port = std::atoi(service);
    if (addr->sin_port == 0)
        return EAI_NONAME;

    addrinfo *rp = new addrinfo;
    rp->ai_family = AF_INET;
    rp->ai_socktype = SOCK_STREAM;
    rp->ai_protocol = IPPROTO_TCP;
    rp->ai_addrlen = INET_ADDRSTRLEN;
    rp->ai_addr = (sockaddr *)addr;
    rp->ai_next = NULL;

    *res = rp;
    return 0;
}

void __wrap_freeaddrinfo(struct addrinfo *res)
{
    for (auto rp = res; rp != NULL;)
    {
        auto nxt = rp->ai_next;
        delete rp->ai_addr;
        delete rp;
        rp = nxt;
    }
}