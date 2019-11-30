/** 
 * @file socket.h
 * @brief POSIX-compatible socket library supporting TCP protocol on IPv4.
 */
#ifndef SOCKET_H
#define SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "tcp.h"
#include <queue>
#include <condition_variable>
#include <mutex>

#define MAX_KERNEL_FD 394959
#define SOCK_BUF_SIZE 65535
#define TCP_TIMEOUT 8
#define MAX_RETRY 5
#define MSL 8

#define ERR(x)     \
    {              \
        errno = x; \
        return -1; \
    }

enum TCPStatus
{
    ESTABLISHED = 1,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT1,
    FIN_WAIT2,
    TIME_WAIT,
    CLOSED,
    CLOSE_WAIT,
    LAST_ACK,
    LISTEN,
    CLOSING
};

struct Request
{ // Connection Request
    in_addr ip;
    uint16_t port;
    uint32_t seq;
    Request(in_addr _ip, uint16_t _port, uint32_t _seq)
        : ip(_ip), port(_port), seq(_seq) {}
};

struct Socket
{
    static int current_fd;
    int fd;
    TCPStatus state;
    in_addr srcIP, dstIP;
    uint16_t srcPort, dstPort;
    int domain, type, proto;

    std::mutex state_mtx; // mutex for state
    void set_state(TCPStatus _state)
    {
        std::lock_guard<std::mutex> lck(state_mtx);
        state = _state;
    }
    bool chk_state(TCPStatus _state)
    {
        std::lock_guard<std::mutex> lck(state_mtx);
        return state == _state;
    }

    // Data buffer
    std::queue<u_char> buffer;
    std::mutex buf_mtx;

    // Sequence number
    // uint32_t ini_seq_send, ini_seq_recv;
    uint32_t seq_send, seq_recv, lst_ack_recv;
    inline void add_seq_send(uint32_t i)
    {
        uint32_t delta = UINT32_MAX - seq_send;
        if (i > delta)
            seq_send = i - delta - 1;
        else
            seq_send += i;
    }
    inline void add_seq_recv(uint32_t i)
    {
        uint32_t delta = UINT32_MAX - seq_recv;
        if (i > delta)
            seq_recv = i - delta - 1;
        else
            seq_recv += i;
    }

    // Connection requests, only used for a listening socket
    uint8_t backlog, max_backlog; // num of pending requests
    std::queue<Request> req;      // pending requests queue
    std::mutex req_mtx;           // mutex for req
    std::condition_variable cv_req;

    // In-order transfer (including retransmission)
    bool ok;      // last packet is ACKed
    bool retrans; // need to retransmit (dup ACK)
    std::condition_variable cv_ok;
    std::mutex ok_mtx;    // mutex for ok/retrans
    std::mutex send_mtx;  // mutex for send()
    std::mutex ssend_mtx; // mutex for safe_send()
    int send(const TCPPacket &tcppacket);
    int safe_send(uint8_t flags,
                  const void *buf = NULL, uint32_t len = 0);
    inline void set_ok()
    {
        std::lock_guard<std::mutex> lck(ok_mtx);
        ok = true;
        cv_ok.notify_one();
    }
    inline void set_retrans()
    {
        std::lock_guard<std::mutex> lck(ok_mtx);
        retrans = true;
        cv_ok.notify_one();
    }
    inline void send_ack(uint8_t flag = TH_ACK)
    {
        TCPPacket ACK;
        ACK.setHeader(srcPort, dstPort, seq_send, seq_recv, flag);
        ACK.setPayload();
        ACK.hton();
        ACK.setChecksum();
        send(ACK);
    }
    inline int reset()
    {
        set_state(CLOSED);
        return 0;
    }
    int receive(TCPPacket &tcppacket, const in_addr &ip);

    Socket()
    {
        srand((unsigned)time(NULL));
        fd = current_fd--; // allocate fd
        set_state(CLOSED);
        // ini_seq_send = rand();
        seq_send = rand();
        backlog = 0;
        max_backlog = 5;
        domain = AF_INET;
        type = SOCK_STREAM;
        proto = IPPROTO_TCP;
        srcIP.s_addr = INADDR_ANY;
        srcPort = 0;
        dstIP.s_addr = INADDR_ANY;
        dstPort = 0;
    }

    Socket(int _domain, int _type, int _proto)
    {
        srand((unsigned)time(NULL));
        fd = current_fd--; // allocate fd
        set_state(CLOSED);
        // ini_seq_send = rand();
        seq_send = rand();
        backlog = 0;
        max_backlog = 5;
        domain = _domain;
        type = _type;
        proto = _proto ? _proto : IPPROTO_TCP;
        srcIP.s_addr = INADDR_ANY;
        srcPort = 0;
        dstIP.s_addr = INADDR_ANY;
        dstPort = 0;
    }

    void print()
    {
        printf("########## Socket ##########\n");
        printf("fd: %d\n", fd);
        printf("src: %s:%u\n", inet_ntoa(srcIP), srcPort);
        printf("dst: %s:%u\n", inet_ntoa(dstIP), dstPort);
        printf("state: %d\n", state);
        printf("send_next(seq): %u\n", seq_send);
        printf("recv_next(ack): %u\n", seq_recv);
        printf("############################\n");
    }

    int bind(const struct sockaddr *address, socklen_t address_len);
    int listen(int bl);
    int connect(const struct sockaddr *address, socklen_t address_len);
    int accept(struct sockaddr *address, socklen_t *address_len);
    ssize_t read(void *buf, size_t nbyte);
    ssize_t write(const void *buf, size_t nbyte);
    int close();
};

using pSocket = std::shared_ptr<Socket>;

struct SocketHub
{
    std::vector<pSocket> psockets;

    int addSocket();
    int addSocket(int domain, int type, int protocol);

    int bind(int socket, const struct sockaddr *address,
             socklen_t address_len);
    int listen(int socket, int backlog);
    int connect(int socket, const struct sockaddr *address,
                socklen_t address_len);
    int accept(int socket, struct sockaddr *address,
               socklen_t *address_len);
    ssize_t read(int socket, void *buf, size_t nbyte);
    ssize_t write(int socket, const void *buf, size_t nbyte);
    int close(int socket);

    pSocket getpSocket(const int &fd)
    {
        pSocket sockPtr = nullptr;
        for (auto &psock : psockets)
            if (psock->fd == fd)
            {
                sockPtr = psock;
                break;
            }
        return sockPtr;
    }

    pSocket getpSocket(const in_addr &sip, const uint16_t &sport,
                       const in_addr &dip, const uint16_t &dport)
    {
        pSocket sockPtr = nullptr;
        for (auto &psock : psockets)
            if ((psock->srcIP.s_addr == sip.s_addr) &&
                (psock->srcPort == sport) &&
                (psock->dstIP.s_addr == dip.s_addr) &&
                (psock->dstPort == dport))
            {
                sockPtr = psock;
                break;
            }
        return sockPtr;
    }
};

extern SocketHub sockhub;

/**
 * @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/socket.html)
 */
int __wrap_socket(int domain, int type, int protocol);

/**
 * @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/bind.html)
 */
int __wrap_bind(int socket, const struct sockaddr *address,
                socklen_t address_len);

/**
 * @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/listen.html)
 */
int __wrap_listen(int socket, int backlog);

/**
 * @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/connect.html)
 */
int __wrap_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len);

/**
 * @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/accept.html)
 */
int __wrap_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len);

/**
 * @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/read.html)
 */
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/write.html)
 */
ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/close.html)
 */
int __wrap_close(int fildes);

/** 
 * @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/getaddrinfo.html)
 */
int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);

void __wrap_freeaddrinfo(struct addrinfo *res);

#endif