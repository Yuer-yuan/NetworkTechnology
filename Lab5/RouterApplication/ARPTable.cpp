#include "ARPTable.h"

ARPEntry::ARPEntry(DWORD ip, BYTE *mac, time_t time) {
    this->ip = ip;
    memcpy(this->mac, mac, 6);
    this->time = time;
    this->prev = NULL;
    this->next = NULL;
}

ARPEntry::~ARPEntry() {}

BYTE *ARPEntry::getMac() {
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0) {
        cout << "¡¾ERR¡¿ Get MAC Error: mac is not set." << endl;
        return NULL;
    }
    return mac;
}

string ARPEntry::toStr(bool showAttr) {
    string str = "";
    string temp;
    if (showAttr) {
        str += "IP Address      Mac Address       Time\n";
    }//example: 255.255.255.255 12-12-12-12-12-12 ......
    temp = b2s(ip); temp.resize(16, ' '); str += temp;
    temp = b2s(mac); temp.resize(18, ' '); str += temp;
    temp = t2s(time);  str += temp;
    return str;
}

ARPTable::ARPTable() {
    this->head = NULL;
    this->tail = NULL;
    this->size = 0;
    this->agingTime = 60;
}

ARPTable::~ARPTable() {
    ARPEntry *arpEntry;
    arpEntry = head;
    while (arpEntry != NULL) {
        ARPEntry *next = arpEntry->next;
        delete arpEntry;
        arpEntry = next;
    }
}

void ARPTable::add(DWORD ip, BYTE *mac) {
    ARPEntry *arpEntry;
    if(lookup(ip) != NULL) {
//        cout << "¡¾ERR¡¿ Add ARP Error: ip already exists." << endl;
        return;
    }
    arpEntry = new ARPEntry(ip, mac, time(NULL));
    cout << "¡¾INF¡¿ Add ARP Entry: " << arpEntry->toStr(false) << endl;
    if (head == NULL) {
        head = arpEntry;
        tail = arpEntry;
    } else {
        tail->next = arpEntry;
        arpEntry->prev = tail;
        tail = arpEntry;
    }
    size++;
}

void ARPTable::del(ARPEntry *arpEntry) {
    cout << "¡¾INF¡¿ Delete ARP Entry: " << arpEntry->toStr(false) << endl;
    if (arpEntry->prev == NULL) {
        head = arpEntry->next;
    } else {
        arpEntry->prev->next = arpEntry->next;
    }
    if (arpEntry->next == NULL) {
        tail = arpEntry->prev;
    } else {
        arpEntry->next->prev = arpEntry->prev;
    }
    delete arpEntry;
    size--;
}

ARPEntry *ARPTable::lookup(DWORD ip) {
    ARPEntry *arpEntry;
    arpEntry = head;
    while (arpEntry != NULL) {
        if (arpEntry->ip == ip) {
//            cout << "¡¾SUC¡¿ ARP Entry Found£º\n" << arpEntry->toStr() << endl;
            return arpEntry;
        }
        arpEntry = arpEntry->next;
    }
//    cout << "¡¾ERR¡¿ ARP Table Lookup Error: ip not found." << endl;
    return NULL;
}

bool ARPTable::isExpired(ARPEntry *arpEntry) {
    return u_int(time(NULL) - arpEntry->time) > this->agingTime;
}

string ARPTable::toStr() {
    string str = "";
    ARPEntry *arpEntry;
    if(size == 0) {
        str += "ARP Table: None";
        return str;
    }
    str += "ARPTable: \nIP Address      Mac Address       Time\n";
    arpEntry = head;
    while (arpEntry != NULL) {
        str += arpEntry->toStr(false) + "\n";
        arpEntry = arpEntry->next;
    }
    return str;
}