#include "device.h"

DeviceHub hub;
extern int EtherCallback(const void *buf, int len, int id);

void receiveFrame(u_char *args, const struct pcap_pkthdr *header,
                  const u_char *packet)
{
    pcapArgs *pa = reinterpret_cast<pcapArgs *>(args);
    int len = header->len;
    if (len != header->caplen)
    {
        // printf("Data Lost!\n");
        return;
    }
    EtherCallback(packet, len, pa->id);
}

MAC getMACAddr(const char *if_name)
{
    MAC mac = BroadCastMAC;

    struct ifaddrs *ifap, *ifa;
    struct sockaddr_ll *sa;
    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
        if (ifa->ifa_addr->sa_family == AF_PACKET &&
            std::string(ifa->ifa_name) == std::string(if_name))
        {
            sa = reinterpret_cast<struct sockaddr_ll *>(ifa->ifa_addr);
            mac = MAC(sa->sll_addr);
        }
    freeifaddrs(ifap);
    return mac;
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
    : name(name), descr(nullptr), id(-1), sniff(false)
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

    {
        std::lock_guard<std::mutex> lck(p_mtx);
        for (int i = 0; i < 65536; ++i)
            ports[i] = false; // All ports unallocated
    }

    id = current_id++;
    startSniff();
    startSend();
}

int Device::startSniff()
{
    if (sniff)
        return -1;

    pcapArgs *pa = new pcapArgs(id, name, macaddr.addr);
    if (!descr)
        return -1;

    sniffThread = std::thread(
        [=]() { pcap_loop(descr, -1, receiveFrame,
                          reinterpret_cast<u_char *>(pa)); });

    sniff = true;
    return 0;
}

int Device::stopSniff()
{
    if (!sniff)
        return -1;

    pthread_t pthread = sniffThread.native_handle();
    if (pthread_cancel(pthread))
        return -1;
    sniffThread.detach();
    sniff = false;
    return 0;
}

int Device::startSend()
{
    if (!descr)
        return -1;

    sendThread = std::thread([&]() { loopSend(); });
    return 0;
}

int Device::stopSend()
{
    pthread_t pthread = sendThread.native_handle();
    if (pthread_cancel(pthread))
        return -1;
    sendThread.detach();
    return 0;
}

int Device::loopSend()
{
    std::unique_lock<std::mutex> lck(cv_mtx);

    while (true)
    {
        cv.wait(lck, [&]() { return sendq.size() > 0; });
        while (sendq.size() > 0)
        {
            EtherFrame frame;
            {
                std::lock_guard<std::mutex> lk(q_mtx);
                frame = sendq.front();
                sendq.pop();
            } // Lock the access to sendq

            if (pcap_inject(descr,
                            reinterpret_cast<const void *>(&frame),
                            frame.len) == -1)
            {
                pcap_perror(descr, 0);
                // printf("SEND FRAME FAILED\n");
            }
        }
    }
}

/********************
 **** DeviceHub ****
********************/
int DeviceHub::addDevice(std::string name)
{
    if (findDevice(name) >= 0)
        return -1;

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

void printDevice(pDevice pdev)
{
    std::string ipstr = inet_ntoa(pdev->ipaddr);
    std::string maskstr = inet_ntoa(pdev->netmask);
    printf("ID: %d\tName: %s\tMAC: %s\tIP: %s\tNetMask: %s\n",
           pdev->id, pdev->name.c_str(), pdev->macaddr.str().c_str(),
           ipstr.c_str(), maskstr.c_str());
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
