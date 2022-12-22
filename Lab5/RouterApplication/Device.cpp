#include "Device.h"

Device::Device() {
    name = "";
    description = "";
    ip[0] = 0;
    ip[1] = 0;
    subnetMask[0] = 0;
    subnetMask[1] = 0;
    memset(mac, 0, 6);
}

Device::~Device() {}

DWORD Device::getIP(u_int idx) {
    if (idx < 2) {
        if (subnetMask[idx] == DWORD(0)) {
            cout << "【ERR】 Get IP Error: subnetMask["<< idx << "] is not set." << endl;
        }
    } else {
        cout << "【ERR】 Get IP Error: idx out of range." << endl;
        exit(1);
    }
    return ip[idx];
}

DWORD Device::getSubnetMask(u_int idx) {
    if (idx < 2) {
        if (subnetMask[idx] == 0) {
            cout << "【ERR】 Get Subnet Mask Error: subnetMask[" << idx << "] is not set." << endl;
        }
    } else {
        cout << "【ERR】 Get Subnet Mask Error: idx: " << idx << " out of range." << endl;
        exit(1);
    }
    return subnetMask[idx];
}

BYTE *Device::getMac() {
    BYTE temp[6];
    memset(temp, 0, 6);
    if (memcmp(mac, temp, 6) == 0) {
        cout << "【ERR】 Get MAC Error: mac is not set." << endl;
        return NULL;
    }
    return mac;
}

string Device::toStr() {
    string str = "";
    str += "Name: " + name + "\nDescription: " + description;
    if (subnetMask[0] != 0) {
        if (subnetMask[1] != 0) {
            str += "\nIP Addr1: " + b2s(ip[0]) + "\tSubnet Mask: " + b2s(subnetMask[0])
                   + "\nIP Addr2: " + b2s(ip[1]) + "\tSubnet Mask: " + b2s(subnetMask[1]);
        } else {
            str += "\nIP Addr: " + b2s(ip[0]) + "\tSubnet Mask: " + b2s(subnetMask[0]);
        }
    }
    if (memcmp(mac, "\0\0\0\0\0\0", 6) != 0) {
        str += "\nMAC Addr: " + b2s(mac);
    }
    return str;
}

DeviceManager::DeviceManager() {
    deviceNum = 0;
    deviceList = NULL;
    openDevice = NULL;
    openHandle = NULL;
}

DeviceManager::~DeviceManager() {
    if (deviceList != NULL) {
        delete[] deviceList;
    }
}

u_int DeviceManager::getDeviceNum() {
    return deviceNum;
}

Device *DeviceManager::getOpenDevice() {
    return openDevice;
}

pcap_t *DeviceManager::getOpenHandle() {
    return openHandle;
}

string DeviceManager::toStr() {
    string str = "";
    u_int i;
    if (deviceNum == 0) {
        str += "No device";
    } else {
        str += "Device Num: " + v2s(deviceNum) + "\n";
        for (i = 0; i < deviceNum; i++) {
            str += "Device " + v2s(u_int(i + 1)) + ":\n" + deviceList[i].toStr() + "\n";
        }
    }
    return str;
}

void DeviceManager::findDevices() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i, j;
    pcap_addr_t *a;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {  // 获取本机所有网卡列表
        cout << "【ERR】 Error in pcap_findalldevs: " << errbuf << endl;
        exit(1);
    }
    for (d = alldevs; d != NULL; d = d->next) { // 获取设备数量
        deviceNum++;
    }
    if (deviceNum == 0) {
        cout << "【ERR】 No device found! Make sure WinPcap is installed." << endl;
        exit(1);
    }
    deviceList = new Device[deviceNum];
    for (i = 0, d = alldevs; d != NULL; d = d->next, i++) { // 获取设备名和描述
        deviceList[i].name = string(d->name);
        deviceList[i].description = string(d->description);
        for (j = 0, a = d->addresses; j < 2 && a != NULL; a = a->next) {    // 获取设备IP地址
            if (a->addr->sa_family == AF_INET) {
                deviceList[i].ip[j] = inet_addr(inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr));
                deviceList[i].subnetMask[j] = inet_addr(inet_ntoa(((struct sockaddr_in *) a->netmask)->sin_addr));
                j++;
            }
        }
    }
    pcap_freealldevs(alldevs);
    cout << "【SUC】 Find Devices Success! Devices： " << endl;
    cout << toStr() << endl;
}

void DeviceManager::selDevice() {
    u_int i;
    cout << "【CMD】 Please input the device index: ";
    cin >> i;
    if (i < 1 || i > deviceNum) {
        cout << "【ERR】 Invalid device index" << endl;
        exit(1);
    }
    i--;
    openDevice = &deviceList[i];
    if ((openHandle = pcap_open(openDevice->name.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) ==
        NULL) { // 打开网卡
        cout << "【ERR】 Error in pcap_open_live: " << errbuf << endl;
        exit(1);
    }
    if (pcap_datalink(openHandle) != DLT_EN10MB) { // 判断网卡是否为以太网适用
        cout << "【ERR】 This device is not an Ethernet" << endl;
        exit(1);
    }
    if (pcap_setnonblock(openHandle, 1, errbuf) == -1) { // 设置网卡为非阻塞模式
        cout << "【ERR】 Error in pcap_setnonblock: " << errbuf << endl;
        exit(1);
    }
    cout << "【SUC】 Device opened successfully" << endl;
}

void DeviceManager::setMac(BYTE *mac, Device *device) {
    if (mac == NULL) {
        cout << "【ERR】 Set MAC Error: mac is NULL." << endl;
        return;
    }
    if (device == NULL) {
        cout << "【ERR】 Set MAC Error: device is NULL." << endl;
    }
    if (device->getMac() != NULL) {
        cout << "【ERR】 Set MAC Error: mac is already set." << endl;
        return;
    }
    memcpy(device->mac, mac, 6);
//    cout << "【SUC】 Set MAC successfully" << endl;
}

DWORD DeviceManager::findItf(DWORD ip) {
    if (openDevice == NULL) {
        cout << "【ERR】 Find Itf Error: openDevice is NULL." << endl;
        return 0;
    }
    if (openHandle == NULL) {
        cout << "【ERR】 Find Itf Error: openHandle is NULL." << endl;
        return 0;
    }
    if ((ip & openDevice->subnetMask[0]) == (openDevice->ip[0] & openDevice->subnetMask[0])) {
        return openDevice->ip[0];
    }
    if ((ip & openDevice->subnetMask[1]) == (openDevice->ip[1] & openDevice->subnetMask[1])) {
        return openDevice->ip[1];
    }
//    cout << "【SUC】 IP Addr destined locally" << endl;
    return 0;
}