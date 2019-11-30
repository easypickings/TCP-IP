/** 
 * @file device.h
 * @brief Library supporting network device management.
 */
#ifndef DEVICE_H
#define DEVICE_H

#include "etherframe.h"

#include <ifaddrs.h>
#include <linux/if_packet.h>
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
#include <queue>
#include <mutex>
#include <condition_variable>

#define PCAP_SNAPLEN 65536
#define PCAP_TIME_OUT 5

struct Device
{
    static int current_id;
    int id;
    std::string name;
    MAC macaddr;
    pcap_t *descr;
    std::thread sendThread;
    std::thread sniffThread;
    bool sniff;
    in_addr ipaddr;
    in_addr netmask;
    std::queue<EtherFrame> sendq;
    std::condition_variable cv;
    std::mutex cv_mtx; // mutex for cv
    std::mutex q_mtx;  // mutex for queue

    bool ports[65536]; // ports on the ip
    std::mutex p_mtx;

    Device(std::string name);

    ~Device()
    {
        stopSend();
        stopSniff();
        if (descr)
            pcap_close(descr);
    }

    int sendFrame(const EtherFrame &frame)
    {
        {
            std::lock_guard<std::mutex> lk(q_mtx);
            sendq.push(frame);
        } // Lock the access to sendq

        cv.notify_one(); // Notify loopSend
        return 0;
    }

    int startSniff();
    int stopSniff();

    int startSend();
    int stopSend();
    int loopSend();

    int allocPort()
    {
        std::lock_guard<std::mutex> lck(p_mtx);
        int i = 1024;
        for (; i < 65536; ++i)
            if (!ports[i])
            {
                ports[i] = true;
                break;
            }
        return i;
    }

    bool acquirePort(uint16_t p)
    {
        std::lock_guard<std::mutex> lck(p_mtx);
        if (ports[p])
            return false;
        ports[p] = true;
        return true;
    }

    void releasePort(uint16_t p)
    {
        std::lock_guard<std::mutex> lck(p_mtx);
        ports[p] = false;
    }
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
        {
            if (pdev->sniffThread.joinable())
                pdev->sniffThread.join();
            if (pdev->sendThread.joinable())
                pdev->sendThread.join();
        }
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
void printDevice(pDevice pdev);
int addDevice(const char *device);
int findDevice(const char *device);

#endif
