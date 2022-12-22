#ifndef ROUTERAPPLICATION_DEVICE_H
#define ROUTERAPPLICATION_DEVICE_H


#include <Winsock2.h>
#include <string>
#include <iostream>
#include "pcap.h"
#include "remote-ext.h"
#include "Util.h"

using namespace std;

class DeviceManager;

class Device {
private:
    string name;    // 设备名称
    string description; // 设备描述
    DWORD ip[2];        // IP地址
    DWORD subnetMask[2];    // 子网掩码
    BYTE mac[6];    // MAC地址

    friend class DeviceManager;

public:
    Device();

    ~Device();

    DWORD getIP(u_int idx = 0);

    DWORD getSubnetMask(u_int idx = 0);

    BYTE *getMac();

    string toStr();
};

class DeviceManager {
private:
    u_int deviceNum;
    Device *deviceList;
    Device *openDevice;
    pcap_t *openHandle;
    char errbuf[PCAP_ERRBUF_SIZE];

public:
    DeviceManager();

    ~DeviceManager();

    u_int getDeviceNum();

    Device *getOpenDevice();

    pcap_t *getOpenHandle();

    string toStr();

    void findDevices();         // 查找所有网卡,获取设备信息
    void selDevice();           // 选择并打开网卡
    void setMac(BYTE *mac, Device *device);   // 设置特定设备MAC地址
    DWORD findItf(DWORD ip);    // 根据IP地址，查看是否在同一网段，并返回对应接口IP地址
};


#endif