#ifndef ROUTERAPPLICATION_ROUTER_H
#define ROUTERAPPLICATION_ROUTER_H

#include <Winsock2.h>
#include <time.h>
#include <string>
#include <sstream>
#include <Windows.h>
#include <vector>
#include "pcap.h"
#include "remote-ext.h"
#include "Device.h"
#include "Packet.h"
#include "ARPTable.h"
#include "RoutingTable.h"
#include "Util.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

class Router {
private:
    DeviceManager *deviceManager;
    ARPTable *arpTable;
    RoutingTable *routingTable;
    PacketList* pktBuf;
    u_int pktLifetime;
    char errbuf[PCAP_ERRBUF_SIZE];
    HANDLE hFwdThrd;
    HANDLE hRcvThrd;
    CRITICAL_SECTION cs;

    BYTE *getOpenDeviceMac(Device *device);         // 获取IP地址与MAC地址映射
    void parseCmd(char* cmd);                       // 解析命令，由主控线程调用
    void cmdThrd();                                 // 主控线程
    bool bcstARPReq(DWORD ip);                      // 广播ARP请求，默认不找自己
    void forward(ICMPPingPkt *pkt, BYTE *dstMac);   // 转发数据包
    static DWORD WINAPI fwdThrd(LPVOID lpParam);    // 转发线程函数
    static DWORD WINAPI rcvThrd(LPVOID lpParam);    // 接收线程函数

public:

    Router();

    ~Router();

    DeviceManager *getDeviceManager();

    ARPTable *getARPTable();

    RoutingTable *getRoutingTable();

    PacketList* getPktBuf();

    u_int getPktLifetime();

    CRITICAL_SECTION& getCS();

    void tryToFwd(Packet* pkt);                      // 尝试转发数据包，由转发线程调用
};


#endif //ROUTERAPPLICATION_ROUTER_H
