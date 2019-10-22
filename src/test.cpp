#include "arp.h"
#include "ip.h"
#include "router.h"

int defaultCallback(const void *buf, int len)
{
    char *cstr = (char *)buf;
    cstr[len] = 0;
    printf("IP Callbeck Message: %s", cstr);
    printf("\n\n");
    return 0;
}

void printDevice(pDevice pdev)
{
    std::string ipstr = inet_ntoa(pdev->ipaddr);
    std::string maskstr = inet_ntoa(pdev->netmask);
    printf("ID: %d\tName: %s\tMAC: %s\tIP: %s\tNetMask: %s\n",
           pdev->id, pdev->name.c_str(), pdev->macaddr.str().c_str(),
           ipstr.c_str(), maskstr.c_str());
}

void str2mac(u_char *mac, const char *str)
{
    int tmp[6] = {0};
    sscanf(str, "%x:%x:%x:%x:%x:%x",
           &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for (int i = 0; i < 6; ++i)
        mac[i] = static_cast<u_char>(tmp[i]);
}

void shell()
{
    pDevice pcurdev = nullptr;
    std::string op;
    while (1)
    {
        printf(">>> ");
        fflush(stdout);
        std::getline(std::cin, op);
        if (op == "")
            continue;

        if (op == "h")
        {
            printf(
                "HELP\n\n"
                "\th This help.\n"
                "\ti Information about current device.\n"
                "\to Open a device.\n"
                "\ta Open all the devices on the host.\n"
                "\ts Send a packet on current device.\n"
                "\tc Change current device.\n"
                "\tr Add an item to routing table.\n"
                "\tp Print routing table.\n"
                "\te Exit.\n");
        }

        else if (op == "i")
        {
            if (!pcurdev)
                printf("[WARN] No Current Device.\n");
            else
            {
                printf("[INFO] ");
                printDevice(pcurdev);
            }
            continue;
        }

        else if (op == "o")
        {
            std::string devicename;
            printf("[INPT] Device Name: ");
            std::getline(std::cin, devicename);
            int id = addDevice(devicename.c_str());

            if (id < 0)
                printf("[WARN] Add Device Failed.\n");
            else
            {
                pcurdev = hub.getpDevice(id);
                printf("[INFO] Current Device\t");
                printDevice(pcurdev);
            }
            continue;
        }

        else if (op == "a")
        {
            int cnt = hub.addAllDevices();
            if (cnt == 0)
                printf("[WARN] No Device Added.\n");
            else
            {
                printf("[INFO] %d Device(s) Added.\n", cnt);
                pcurdev = hub.getpDevice(0);
                printf("[INFO] Current Device\t");
                printDevice(pcurdev);
            }
            continue;
        }

        else if (op == "s")
        {
            if (!pcurdev)
            {
                printf("[WARN] No Current Device.\n");
                continue;
            }

            std::string ip, buf;
            printf("[INPT] Destination IP Address: ");
            std::getline(std::cin, ip);
            in_addr dstip;
            if (inet_aton(ip.c_str(), &dstip) == 0)
            {
                printf("[WARN] Invalid IP Address.\n");
                continue;
            }
            printf("[INPT] Data: ");
            std::getline(std::cin, buf);
            in_addr srcip = pcurdev->ipaddr;
            int len = buf.length();

            if (sendIPPacket(srcip, dstip, IPPROTO_TCP, buf.c_str(), len) < 0)
                printf("[WARN] Sending Packet Failed.\n");
            continue;
        }

        else if (op == "c")
        {
            std::string name;
            printf("[INPT] Device Name: ");
            std::getline(std::cin, name);
            pDevice p = hub.getpDevice(name);
            if (p)
            {
                pcurdev = p;
                printf("[INFO] Current Device\t");
                printDevice(pcurdev);
            }
            else
                printf("[WARN] Changing Device Failed.\n");
            continue;
        }

        else if (op == "r")
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

        else if (op == "p")
        {
            router.print();
        }

        else if (op == "e")
        {
            exit(0);
        }

        else
        {
            printf("Invalid option -- '%s'\n"
                   "Try 'h' for help.\n",
                   op.c_str());
        }
    }
}

int main(int argc, char *argv[])
{
    setFrameReceiveCallback(EtherCallback);
    setIPPacketReceiveCallback(defaultCallback);
    // std::string devicename;
    // printf("[INP] Device Name: ");
    // std::getline(std::cin, devicename);
    // int id = addDevice(devicename.c_str());
    shell();

    // hub.addAllDevices();

    // pDevice pdev = hub.getpDevice(0);

    // char *devName = argv[argc - 2];
    // char *addr = argv[argc - 1];
    // int id = addDevice(devName);
    // // if (id < 0)
    // //     return -1;
    // pDevice pdev = hub.getpDevice(id);
    // if (std::string(argv[argc - 3]) == "f")
    // {

    //     in_addr ip;
    //     int res = inet_aton(addr, &ip);
    //     // if (res < 0)
    //     //     return -1;
    //     u_char mac[ETHER_ADDR_LEN];
    //     for (int i = 0; i < 6; ++i)
    //         mac[i] = static_cast<u_char>(0xff);
    //     int ans = arpmap.findDestMAC(pdev, ip, mac);
    //     printf("ans %d\n", ans);
    //     // if (ans >= 0)
    //     printf("%s\n", mac2str(arpmap.ip_mac_map[ip]).c_str());
    //     for (int i = 0; i < 6; ++i)
    //         printf("%02x ", mac[i]);
    // }

    hub.join();
    return 0;
}