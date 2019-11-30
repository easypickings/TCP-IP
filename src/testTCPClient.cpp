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
    printf("Usage: ./testTCPClient [IP] [Port]\n\n");
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

    sockaddr dst;
    socklen_t len;
    sockaddr_in *dst_in = (sockaddr_in *)&dst;
    dst_in->sin_family = AF_INET;
    dst_in->sin_addr = ip;
    dst_in->sin_port = port;

    char sendBuffer[SOCK_BUF_SIZE];
    int xx, ws;

    RUN_FUNC(ws, socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    RUN_FUNC(xx, connect, ws, &dst, INET_ADDRSTRLEN);

    while (1)
    {
        printf("[INPT] Data (input \"EXIT\" to call close()): \n");
        std::cin.getline(sendBuffer, SOCK_BUF_SIZE);
        RUN_FUNC(xx, write, ws, sendBuffer, strlen(sendBuffer));
        if (std::string(sendBuffer) == "EXIT")
        {
            printf("[INFO] Active Close...\n");
            RUN_FUNC(xx, close, ws);
            break;
        }
    }
    return 0;
}