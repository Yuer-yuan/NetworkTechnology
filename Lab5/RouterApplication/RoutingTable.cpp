#include "RoutingTable.h"

RoutingEntry::RoutingEntry(DWORD dest, DWORD netmask, DWORD gw, DWORD itf) {
    this->dest = dest;
    this->netmask = netmask;
    this->gw = gw;
    this->itf = itf;
    this->prev = NULL;
    this->next = NULL;
}

RoutingEntry::~RoutingEntry() {}

DWORD RoutingEntry::getGw() {
    return this->gw;
}

string RoutingEntry::toStr(bool showAttr) {
    string str = "";
    string temp;
    if (showAttr) {
        str += "Destination     Netmask         Gateway         Interface\n";
    }         //255.255.255.255 255.255.255.255 255.255.255.255 255.255.255.255
    temp = b2s(this->dest);  temp.resize(16, ' ');  str += temp;
	temp = b2s(this->netmask);  temp.resize(16, ' ');  str += temp;
	temp = b2s(this->gw);  temp.resize(16, ' ');  str += temp;
	temp = b2s(this->itf);  str += temp;
    return str;
}

RoutingTable::RoutingTable(Device *openDevice) {
    this->openDevice = openDevice;
    this->head = NULL;
    this->tail = NULL;
    this->size = 0;
}

RoutingTable::~RoutingTable() {
    RoutingEntry *routingEntry;
    routingEntry = this->head;
    while (routingEntry != NULL) {
        RoutingEntry *next = routingEntry->next;
        delete routingEntry;
        routingEntry = next;
    }
}

void RoutingTable::add(DWORD dest, DWORD netmask, DWORD gw) {
    RoutingEntry *routingEntry;
    DWORD itf;

    if((routingEntry = lookup(dest)) != NULL && (routingEntry->netmask != 0)) {
        return;
    }
    switch(netmask) {
    case 0:
        if ((openDevice->getIP(0) & openDevice->getSubnetMask(0)) == (gw & openDevice->getSubnetMask(0))) {
            itf = openDevice->getIP(0);
        } else if ((openDevice->getIP(1) & openDevice->getSubnetMask(1)) == (gw & openDevice->getSubnetMask(1))) {
            itf = openDevice->getIP(1);
        } else {
            cout << "¡¾ERR¡¿ Add Routing Entry Error: default destination is unreachable" << endl;
            return;
        }
        routingEntry = new RoutingEntry(0, 0, gw, itf);
        break;
    default:
        if ((openDevice->getIP(0) & openDevice->getSubnetMask(0)) == (gw & openDevice->getSubnetMask(0))) {
            itf = openDevice->getIP(0);
        } else if ((openDevice->getIP(1) & openDevice->getSubnetMask(1)) == (gw & openDevice->getSubnetMask(1))) {
            itf = openDevice->getIP(1);
        } else {
            cout << "¡¾ERR¡¿ Add Routing Entry Error: No interface found for this destination." << endl;
            return;
        }
        routingEntry = new RoutingEntry(dest&netmask, netmask, gw, itf);
    }

    if (head == NULL) {
        head = tail = routingEntry;
    } else {
        tail->next = routingEntry;
        routingEntry->prev = tail;
        tail = routingEntry;
    }
    size++;
	cout << "¡¾INF¡¿ Routing Entry Added£º " << routingEntry->toStr(false) << endl;
}

void RoutingTable::add(const char *dest, const char *netmask, const char *gw) {
    add(inet_addr(dest), inet_addr(netmask), inet_addr(gw));
}

void RoutingTable::del(RoutingEntry *routingEntry) {
    if (routingEntry == NULL) {
        cout << "¡¾ERR¡¿ Delete Routing Entry Error: Routing entry not found." << endl;
        return;
    }
    if (size == 0) {
        cout << "¡¾ERR¡¿ Delete Routing Entry Error: Routing table is empty." << endl;
        return;
    }
    cout << "¡¾INF¡¿ Delete Routing Entry: " << routingEntry->toStr(false) << endl;
    if (routingEntry->prev == NULL) {
        head = routingEntry->next;
    } else {
        routingEntry->prev->next = routingEntry->next;
    }
    if (routingEntry->next == NULL) {
        tail = routingEntry->prev;
    } else {
        routingEntry->next->prev = routingEntry->prev;
    }
    delete routingEntry;
    size--;
}

RoutingEntry *RoutingTable::lookup(DWORD dest) {
    RoutingEntry *routingEntry;
    RoutingEntry *candidate;
    DWORD maxPrefixNetmask;

    routingEntry = head;
    if (routingEntry == NULL) {
        cout << "¡¾ERR¡¿ Look up Routing Table Error: Routing table is empty." << endl;
        return NULL;
    }
    candidate = NULL;
    maxPrefixNetmask = head->netmask;
    while (routingEntry != NULL) {
        if ((routingEntry->dest & routingEntry->netmask) == (dest & routingEntry->netmask)) {
            if (ntohl(routingEntry->netmask) > ntohl(maxPrefixNetmask)) { // little endian in network
                maxPrefixNetmask = routingEntry->netmask;
                candidate = routingEntry;
            }
            candidate = routingEntry;
        }
        routingEntry = routingEntry->next;
    }
    if (candidate == NULL) {
        cout << "¡¾ERR¡¿ Look up Routing Table Error: Routing entry not found." << endl;
    } else {
//        if(candidate->netmask != 0) {
//            cout << "¡¾SUC¡¿ Routing Entry Found: \n" << candidate->toStr() << endl;
//        } else {
//            cout << "¡¾INF¡¿ Default Gateway chosen: \n" << candidate->toStr() << endl;
//        }
    }
    return candidate;
}

string RoutingTable::toStr() {
    string str = "";
    RoutingEntry *routingEntry;

    routingEntry = head;
    if (routingEntry == NULL) {
        str += "RoutingTable: None";
    } else {
        str += "RoutingTable: \nDestination     Netmask         Gateway         Interface\n";
        while (routingEntry != NULL) {
            str += routingEntry->toStr(false) + "\n";
            routingEntry = routingEntry->next;
        }
    }
    return str;
}