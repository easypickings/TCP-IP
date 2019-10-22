#include "device.h"

DeviceHub hub;
frameReceiveCallback callback;

void receiveFrame(u_char *args, const struct pcap_pkthdr *header,
                  const u_char *packet)
{
    pcapArgs *pa = reinterpret_cast<pcapArgs *>(args);
    int len = header->len;
    if (len != header->caplen)
    {
        printf("Data Lost!\n");
        return;
    }

    if (callback != nullptr)
        callback(packet, len, pa->id);
}

MAC getMACAddr(const char *if_name)
{
    ifreq ifinfo;
    int found = -1;
    strcpy(ifinfo.ifr_name, if_name);
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    int res = ioctl(sd, SIOCGIFHWADDR, &ifinfo);
    close(sd);

    if (res == 0 && ifinfo.ifr_hwaddr.sa_family == 1)
    {
        u_char mac[ETHER_ADDR_LEN];
        memcpy(mac, ifinfo.ifr_hwaddr.sa_data, IFHWADDRLEN);
        return MAC(mac);
    }
    return BroadCastMAC;
}

std::pair<in_addr, in_addr> getIPAddr(const char *if_name)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    in_addr ip, mask;

    ip.s_addr = 0;
    mask.s_addr = 0;

    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
        if (ifa->ifa_addr->sa_family == AF_INET &&
            std::string(ifa->ifa_name) == std::string(if_name))
        {
            sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
            ip = sa->sin_addr;
            sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_netmask);
            mask = sa->sin_addr;
            break;
        }
    freeifaddrs(ifap);
    return std::make_pair(ip, mask);
}

/*****************
 **** Device ****
*****************/
int Device::current_id = 0;

Device::Device(std::string name)
    : name(name), descr(nullptr), id(-1), sniffing(false)
{
    macaddr = getMACAddr(name.c_str());
    if (macaddr == BroadCastMAC)
        return;

    auto netpair = getIPAddr(name.c_str());
    ipaddr = netpair.first;
    netmask = netpair.second;
    if (ipaddr.s_addr == 0)
        return;

    char errbuf[PCAP_ERRBUF_SIZE];
    descr = pcap_open_live(name.c_str(), PCAP_SNAPLEN,
                           false, PCAP_TIME_OUT, errbuf);
    if (!descr)
        return;

    id = current_id++;
    startSniffing();
 }

int Device::startSniffing()
{
    if (sniffing)
        return -1;

    pcapArgs *pa = new pcapArgs(id, name, macaddr.addr);
    if (!descr)
        return -1;

    sniffingThread = std::thread(
        [=]() { pcap_loop(descr, -1, receiveFrame, reinterpret_cast<u_char *>(pa)); });

    sniffing = true;
    return 0;
}

int Device::stopSniffing()
{
    if (!sniffing)
        return -1;

    pthread_t pthread = sniffingThread.native_handle();
    if (pthread_cancel(pthread))
        return -1;
    sniffingThread.detach();
    sniffing = false;
    return 0;
}

/********************
 **** DeviceHub ****
********************/
int DeviceHub::addDevice(std::string name)
{
    if (findDevice(name) >= 0)
    {
        printf("Device Exists.\n");
        return -1;
    }

    pDevice pdev = std::make_shared<Device>(name);
    if (pdev->id < 0)
        return -1;
    pdevices.push_back(pdev);
    return pdev->id;
}

int DeviceHub::findDevice(std::string name)
{
    int id = -1;
    for (auto &pdev : pdevices)
        if (pdev->name == name)
        {
            id = pdev->id;
            break;
        }
    return id;
}

int DeviceHub::addAllDevices()
{
    int cnt = 0;
    pcap_if_t *pdevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&pdevs, errbuf);
    while (pdevs != nullptr)
    {
        int id = addDevice(pdevs->name);
        if (id >= 0)
            cnt += 1;
        pdevs = pdevs->next;
    }
    pcap_freealldevs(pdevs);
    return cnt;
}

int DeviceHub::sendFrame(const void *buf, int len, int ethtype,
                         const MAC &destmac, pDevice pdev)
{
    EtherFrame frame;
    frame.setHeader(pdev->macaddr, destmac, ethtype);
    if (frame.setPayload(buf, len) < 0)
        return -1;
    frame.hton();
    return pdev->sendFrame(frame);
}

int addDevice(const char *device)
{
    int id = -1;
    id = hub.addDevice(device);
    return id;
}

int findDevice(const char *device)
{
    int id = hub.findDevice(device);
    return id;
}
