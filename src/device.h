/** 
 * @file device.h
 * @brief Library supporting network device management.
 */
#ifndef DEVICE_H
#define DEVICE_H

#include "etherframe.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <pthread.h>
#include <thread>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>

#define PCAP_SNAPLEN 65536
#define PCAP_TIME_OUT 5

struct Device
{
    static int current_id;
    int id;
    std::string name;
    MAC macaddr;
    pcap_t *descr;
    std::thread sniffingThread;
    bool sniffing;
    in_addr ipaddr;
    in_addr netmask;

    Device(std::string name);

    ~Device()
    {
        stopSniffing();
        if (descr)
            pcap_close(descr);
    }

    int sendFrame(const EtherFrame &frame)
    {
        if (pcap_inject(descr,
                        reinterpret_cast<const void *>(&frame.Frame),
                        frame.len) == -1)
        {
            pcap_perror(descr, 0);
            return -1;
        }
        return 0;
    }

    int startSniffing();
    int stopSniffing();
};

using pDevice = std::shared_ptr<Device>;

struct DeviceHub
{
    std::vector<pDevice> pdevices;

    int addDevice(std::string name);
    int findDevice(std::string name);
    int addAllDevices();
    int sendFrame(const void *buf, int len, int ethtype,
                  const MAC &destmac, pDevice pdev);

    void join()
    {
        for (auto &pdev : pdevices)
            if (pdev->sniffingThread.joinable())
                pdev->sniffingThread.join();
    }

    pDevice getpDevice(int id)
    {
        pDevice devPtr = nullptr;
        for (auto &pdev : pdevices)
            if (pdev->id == id)
            {
                devPtr = pdev;
                break;
            }
        return devPtr;
    }

    pDevice getpDevice(std::string name)
    {
        pDevice devPtr = nullptr;
        for (auto &pdev : pdevices)
            if (pdev->name == name)
            {
                devPtr = pdev;
                break;
            }
        return devPtr;
    }

    pDevice getpDevice(const in_addr &ipaddr)
    {
        pDevice devPtr = nullptr;
        for (auto &pdev : pdevices)
            if (pdev->ipaddr.s_addr == ipaddr.s_addr)
            {
                devPtr = pdev;
                break;
            }
        return devPtr;
    }

    bool haveIP(const in_addr &ip)
    {
        for (auto &pdev : pdevices)
            if (pdev->ipaddr.s_addr == ip.s_addr)
                return true;
        return false;
    }
};

struct pcapArgs
{
    int id;
    std::string name;
    u_char macaddr[ETHER_ADDR_LEN];

    pcapArgs(int id, std::string name, const u_char *mac)
        : id(id), name(name) { memcpy(macaddr, mac, ETHER_ADDR_LEN); }
};

extern DeviceHub hub;
extern frameReceiveCallback callback;

int addDevice(const char *device);
int findDevice(const char *device);

#endif
