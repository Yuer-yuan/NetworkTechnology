#include "Packet.h"

ARPPkt *makeARPPkt(u_char *dstMac, u_char *srcMac, WORD operation, DWORD dstIP, DWORD srcIP) {
    ARPPkt *pkt = new ARPPkt;
    memcpy(pkt->eh.dstMac, dstMac, 6);
    memcpy(pkt->eh.srcMac, srcMac, 6);
    pkt->eh.type = htons(0x0806);
    pkt->ad.hType = htons(0x0001);      // ÒÔÌ«Íø
    pkt->ad.pType = htons(0x0800);      // IPV4
    pkt->ad.hLen = 6;
    pkt->ad.pLen = 4;
    pkt->ad.op = htons(operation);
    memcpy(pkt->ad.srcMac, srcMac, 6);
    pkt->ad.srcIP = srcIP;
    memcpy(pkt->ad.dstMac, dstMac, 6);
    pkt->ad.dstIP = dstIP;
    return pkt;
}

bool isARPPkt(const u_char *pktData) {
    return ntohs(((ARPPkt *) pktData)->eh.type) == 0x0806;
}

bool isIPPkt(const u_char *pktData) {
    return ntohs(((ARPPkt *) pktData)->eh.type) == 0x0800;
}

u_short calIPChecksum(u_short *pktData, int len) {
    u_long sum;
    u_short bac;
    u_short* ori;
    sum = 0;
    bac = ((IPPkt *) pktData)->ih.checksum;
    ori = pktData;
    ((IPPkt *) pktData)->ih.checksum = 0;
    pktData = (u_short *) &(((IPPkt *) pktData)->ih);
    len -= sizeof (EthHeader);
    while (len > 1) {
        sum += *pktData++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char *) pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    pktData = ori;
    ((IPPkt *)pktData)->ih.checksum = bac;
    return (u_short) (~sum);
}

u_short calICMPChecksum(u_short *pktData, int len) {
    u_long sum;
    u_short bac;
    u_short* ori;
    sum = 0;
    bac = ((ICMPPingPkt*)pktData)->icmpPingData.checksum;
    ori = pktData;
    ((ICMPPingPkt*)pktData)->icmpPingData.checksum = 0;
    pktData = (u_short*)&((ICMPPingPkt*)pktData)->ih;
    len -= sizeof(EthHeader);
    while (len > 1) {
        sum += *pktData++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char *) pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    pktData = ori;
    ((ICMPPingPkt*)pktData)->icmpPingData.checksum = bac;
    return (u_short) (~sum);
}

bool isICMPCorrupted(u_short *pktData, int len) {
    u_long sum;
    sum = 0;
    pktData = (u_short*)&((ICMPPingPkt*)pktData)->ih;
    len -= sizeof(EthHeader);
    while (len > 1) {
        sum += *pktData++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char *) pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    if(sum != 0xffff) {
        cout << "¡¾ERR¡¿ ICMP checksum error" << endl;
    }
    return sum != 0xffff;
}

void setICMPChecksum(u_short *pktData) {
    ((IPPkt*)pktData)->ih.checksum = calIPChecksum(pktData, sizeof(IPPkt));
    ((ICMPPingPkt*)pktData)->icmpPingData.checksum = calICMPChecksum(pktData, sizeof (ICMPPingPkt));
}

Packet::Packet(ICMPPingPkt* icmpPingPkt, time_t time) {
    this->icmpPingPkt = icmpPingPkt;
    this->time = time;
    this->discardState = false;
    next = NULL;
}

Packet::~Packet() {}

ICMPPingPkt *Packet::getICMPPingPkt() const {
    return icmpPingPkt;
}

time_t Packet::getTime() const {
    return time;
}

bool Packet::shouldDiscard() const {
    return this->discardState;
}

void Packet::setDiscardState(bool discardState) {
    this->discardState = discardState;
}

Packet* Packet::getNext() {
    return next;
}

PacketList::PacketList() {
    head = NULL;
    tail = NULL;
    size = 0;
}

PacketList::~PacketList() {
    Packet *p = head;
    while (p != NULL) {
        Packet *tmp = p;
        p = p->next;
        delete tmp;
    }
}

void PacketList::addBefore(ICMPPingPkt *icmpPingPkt) {
    Packet *pkt = new Packet(icmpPingPkt, time(NULL));
    if (head == NULL) {
        head = pkt;
        tail = pkt;
    } else {
        pkt->next = head;
        head->prev = pkt;
        head = pkt;
    }
    size++;
}

Packet* PacketList::del(Packet *packet) {
    Packet* ret;
    ret = packet->next;
    if (packet == head) {
        head = packet->next;
        if (head != NULL) {
            head->prev = NULL;
        }
    } else if (packet == tail) {
        tail = packet->prev;
        if (tail != NULL) {
            tail->next = NULL;
        }
    } else {
        packet->prev->next = packet->next;
        packet->next->prev = packet->prev;
    }
    delete packet;
    size--;
    return ret;
}

Packet *PacketList::getHead() const {
    return head;
}

u_int PacketList::getSize() const {
    return size;
}
