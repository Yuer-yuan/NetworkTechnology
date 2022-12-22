#ifndef ROUTERAPPLICATION_PACKET_H
#define ROUTERAPPLICATION_PACKET_H

#include <winsock2.h>
#include <time.h>
#include "pcap.h"
#include "remote-ext.h"
#include <iostream>

using namespace std;

#pragma pack(1) // 字节对齐

typedef struct EthHeader { // 帧首部-14B
    BYTE dstMac[6];
    BYTE srcMac[6];
    WORD type;
} EthHeader;

typedef struct IPHeader {   // IP首部-20B
    BYTE verLen;
    BYTE tos;
    WORD totalLen;
    WORD id;
    WORD flagOffset;
    BYTE ttl;
    BYTE protocol;
    WORD checksum;
    DWORD srcIP;
    DWORD dstIP;
} IPHeader;

typedef struct ARPData {// ARP数据包
    WORD hType;         //  硬件类型
    WORD pType;         //  协议类型
    BYTE hLen;          //  硬件地址长度
    BYTE pLen;          //  协议地址长度
    WORD op;            //  操作类型
    BYTE srcMac[6];     //  发送端硬件地址
    DWORD srcIP;        //  发送端IP地址
    BYTE dstMac[6];     //  接收端硬件地址
    DWORD dstIP;        //  接收端IP地址
} ARPData;

typedef struct ICMPPingData {   //ICMP echo request(reply)报文
    BYTE type;
    BYTE code;
    WORD checksum;
    WORD id;
    WORD seq;
    BYTE data[32];
} ICMPPingData;

typedef struct ICMPTimeExceededData { // ICMP time exceeded报文
    BYTE type;
    BYTE code;
    WORD checksum;
    BYTE unused[4];
    IPHeader ipHeader;
    BYTE data[8];
} ICMPTimeExceededData;

typedef struct ICMPDestUnreachableData { // ICMP destination unreachable报文
    BYTE type;
    BYTE code;
    WORD checksum;
    BYTE unused[4];
    IPHeader ipHeader;
    BYTE data[8];
} ICMPDestUnreachableData;

typedef struct IPPkt {  // IP数据包
    EthHeader eh;
    IPHeader ih;
} IPPkt;

typedef struct ARPPkt {
    EthHeader eh;
    ARPData ad;
} ARPPkt;

typedef struct ICMPPingPkt {
    EthHeader eh;
    IPHeader ih;
    ICMPPingData icmpPingData;
} ICMPPingPkt;

typedef struct ICMPTimeExceededPkt {
    EthHeader eh;
    IPHeader ih;
    ICMPTimeExceededData icmpTimeExceededData;
} ICMPTimeExceededPkt;

typedef struct ICMPDestUnreachablePkt {
    EthHeader eh;
    IPHeader ih;
    ICMPDestUnreachableData icmpDestUnreachableData;
} ICMPDestUnreachablePkt;

#pragma pack() // 恢复默认对齐方式

ARPPkt *makeARPPkt(u_char *dstMac, u_char *srcMac, WORD operation, DWORD dstIP, DWORD srcIP);

#define MK_ARP_REQ_PKT(dstMac, srcMac, srcIP, dstIP) makeARPPkt( dstMac, srcMac, 0x0001, dstIP, srcIP)
#define MK_ARP_RPL_PKT(dstMac, srcMac, srcIP, dstIP) makeARPPkt( dstMac, srcMac, 0x0002, dstIP, srcIP)

bool isARPPkt(const u_char *pktData);

bool isIPPkt(const u_char *pktData);

u_short calIPChecksum(u_char *pktData, int len);

u_short calICMPChecksum(u_short *pktData, int len);

bool isICMPCorrupted(u_short *pktData, int len);

void setICMPChecksum(u_short *pktData);

class PacketList;

class Packet {
private:
    ICMPPingPkt *icmpPingPkt;
    time_t time;
    bool discardState;
    Packet* prev;
    Packet* next;

public:
    Packet(ICMPPingPkt *ipPkt, time_t time);

    ~Packet();

    ICMPPingPkt *getICMPPingPkt() const;

    time_t getTime() const;

    bool shouldDiscard() const;

    void setDiscardState(bool discardState);

    Packet* getNext();

    friend class PacketList;
};

class PacketList {
private:
    Packet *head;
    Packet *tail;
    u_int size;

public:
    PacketList();

    ~PacketList();

    void addBefore(ICMPPingPkt *icmpPingPkt);

    Packet* del(Packet *packet);

    Packet *getHead() const;

    u_int getSize() const;
};

#endif

