#include "socket.h"

#define TEST

#ifdef TEST
#define CALL(f, ...) __wrap_##f(__VA_ARGS__)
#else
#define CALL(f, ...) f(__VA_ARGS__)
#endif

#define RUN_FUNC(res, func, ...)                \
    {                                           \
        res = CALL(func, __VA_ARGS__);          \
        if (res < 0)                            \
        {                                       \
            printf("[WARN] " #func "() Failed." \
                   " Errno: %d\n",              \
                   errno);                      \
            return -1;                          \
        }                                       \
    }

inline void init()
{
    printf("Initialization\n"
           "\to  Open all devices.\n"
           "\tr  Route using NRP.\n"
           "\ta  Manually add a route.\n"
           "\ti  Info about open devices.\n"
           "\tp  Print routing table.\n"
           "\tok Okay to go.\n");

    std::string op;
    while (1)
    {
        fflush(stdout);
        std::getline(std::cin, op);
        if (op == "o")
        {
            hub.addAllDevices();
            router.init();
        }
        else if (op == "r")
        {
            router.route();
        }
        else if (op == "a")
        {
            std::string ip, netmask, macaddr;

            printf("[INPT] IP Address: ");
            std::getline(std::cin, ip);
            in_addr dstip;
            if (inet_aton(ip.c_str(), &dstip) == 0)
            {
                printf("[WARN] Invalid IP Address.\n");
                continue;
            }

            printf("[INPT] Network Mask: ");
            std::getline(std::cin, netmask);
            in_addr mask;
            if (inet_aton(netmask.c_str(), &mask) == 0)
            {
                printf("[WARN] Invalid Network Mask.\n");
                continue;
            }

            printf("[INPT] Next Hop MAC Address: ");
            std::getline(std::cin, macaddr);
            u_char mac[ETHER_ADDR_LEN];
            str2mac(mac, macaddr.c_str());
            MAC nexthopMAC(mac);

            std::string name;
            printf("[INPT] Device Name: ");
            std::getline(std::cin, name);
            pDevice p = hub.getpDevice(name);
            if (!p)
            {
                printf("[WARN] No Such Device.\n");
                continue;
            }

            setRoutingTable(dstip, mask, nexthopMAC, name.c_str());
        }
        else if (op == "i")
        {
            for (auto &pdev : hub.pdevices)
            {
                printf("[INFO]   ");
                printDevice(pdev);
            }
        }
        else if (op == "p")
        {
            router.print();
        }
        else if (op == "ok")
        {
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    printf("Usage: ./testTCPServer [IP] [Port]\n\n");
    if (argc != 3)
        exit(-1);
    char *ipStr = argv[1];
    char *portStr = argv[2];
    in_addr ip;
    uint16_t port;
    if (inet_aton(ipStr, &ip) == 0)
    {
        printf("[WARN] Invalid IP Address.\n");
        exit(-1);
    }
    port = std::atoi(portStr);

    init();

    sockaddr src, dst;
    socklen_t len;
    sockaddr_in *src_in = (sockaddr_in *)&src;
    src_in->sin_family = AF_INET;
    src_in->sin_addr = ip;
    src_in->sin_port = port;

    char recvBuffer[SOCK_BUF_SIZE];
    int xx, ls, ws;

    RUN_FUNC(ls, socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    RUN_FUNC(xx, bind, ls, &src, INET_ADDRSTRLEN);
    RUN_FUNC(xx, listen, ls, 5);
    RUN_FUNC(ws, accept, ls, &dst, &len);

    while (1)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        RUN_FUNC(xx, read, ws, recvBuffer, SOCK_BUF_SIZE);
        if (xx > 0)
            printf("[INFO] Data Received: %s\n", recvBuffer);
        if (std::string(recvBuffer) == "EXIT")
        {

            std::this_thread::sleep_for(std::chrono::seconds(5));
            printf("[INFO] Passive Close...\n");
            RUN_FUNC(xx, close, ws);
            break;
        }
    }
    return 0;
}