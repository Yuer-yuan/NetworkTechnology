#ifndef ROUTERAPPLICATION_ARP_TABLE_H
#define ROUTERAPPLICATION_ARP_TABLE_H

#include <time.h>
#include <Winsock2.h>
#include <string>
#include <iostream>
#include "Util.h"
using namespace std;

class ARPTable;             // ARP表

class ARPEntry {
private:
    DWORD ip;               // IP地址
    BYTE mac[6];            // MAC地址
    time_t time;            // 更新时间
    ARPEntry* prev;
    ARPEntry* next;
    friend class ARPTable;

public:
    ARPEntry( DWORD ip, BYTE* mac, time_t time );
    ~ARPEntry();
    BYTE* getMac();
    string toStr(bool showAttr = true);
};

class ARPTable {
private:
    ARPEntry* head;
    ARPEntry* tail;
    u_int size;
    u_int agingTime;

public:
    ARPTable();
    ~ARPTable();
    void add(DWORD ip, BYTE* mac);
    void del(ARPEntry* arpEntry);
    ARPEntry* lookup(DWORD ip);
    bool isExpired(ARPEntry* arpEntry);
    string toStr();
};

#endif