#include "Capture.h"

int main()
{
    /* 获取本机网卡列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s", errbuf);
        exit(1);
    }

    /* 获取设备数 */
    cnt = 0;
    printf("All device are listed here.\n");
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next)
    {
        ++cnt;
    }
    if (cnt == 0)
    {
        printf("No interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    /* 展示网卡列表 */
    devices = new Device[cnt];
    i = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next)
    {
        /* 获取列表中的设备名和描述 */
        devices[i].name = new char[strlen(d->name) + 1]{0};
        strcpy_s(devices[i].name, strlen(d->name) + 1, d->name);
        devices[i].description = new char[strlen(d->description) + 1]{0};
        strcpy_s(devices[i].description, strlen(d->description) + 1, d->description);
        printf("%d\tName: %s\nDescription: %s\n", i+1, devices[i].name, devices[i].description);

        for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next)
        {
            if (a->addr->sa_family == AF_INET) // 判断该地址是否为IP地址
            {
                // 获取IP地址
                devices[i].ipAddr = new char[strlen(inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr)) + 1]{0};
                strcpy_s(devices[i].ipAddr, strlen(inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr)) + 1, inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
                printf("\tIP address: %s\n", devices[i].ipAddr);
                // printf("\tNetmask: %s\n", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
                // printf("\tBroadcast address: %s\n", inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr));
                // printf("\tDestination address: %s\n", inet_ntoa(((struct sockaddr_in*)a->dstaddr)->sin_addr));
            }
        }
        printf("\n");
        i++;
    }

    /* 输入监听的网卡序号 */
    i = 0;
    printf("Enter the device number (1-%d):", cnt);
    scanf_s("%d", &i);
    if (i < 1 || i > cnt)
    {
        printf("Device number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 打开网卡 */
    if ((adhandle = pcap_open(devices[i-1].name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", devices[i-1].name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\nHandling %s...\n", devices[i-1].description);

    /* 释放网卡列表 */
    pcap_freealldevs(alldevs);

#ifdef LAB1
    Lab1();
#endif // LAB1

#ifdef LAB2
    Lab2();
#endif // LAB2

    return 0;
}

//==函数定义=====================================================================

/* 计算ip帧校验和 */
USHORT checkSum(USHORT *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size)
    {
        cksum += *(UCHAR *)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff); //将高16bit与低16bit相加
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

/* 显示时间 */
void printTime(struct pcap_pkthdr *header)
{
    struct tm ltime;
    time_t local_tv_sec;
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    printf("[%02d:%02d:%02d.%.6ld]\n", ltime.tm_hour, ltime.tm_min, ltime.tm_sec, header->ts.tv_usec);
}

/* 解析以太网帧首部和数据包 */
void parse(struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct IPData *data = (struct IPData *)pkt_data;
    /* 打印数据包长度 */
    printf("PAKT LENGTH: %d\n", atoi(to_string(header->len), 16));
    /* 打印实际捕获数据包长度 */
    printf("CAPT LENGTH: %d\n", atoi(to_string(header->caplen), 16));
    /* 打印帧类型 */
    printf("FRAME TYPE: %04x,", ntohs(data->fh.type));
    switch (ntohs(data->fh.type))
    {
    case 0x0800:
        printf("IPV4\n");
        /* 打印序列号 */
        printf("ID: % 04x\n", ntohs(data->ih.id));
        /* 打印IP数据包长度 */
        printf("IP PKT LENGTH: %d\n", atoi(to_string(ntohs(data->ih.totalLen)), 16));
        /* 打印目的Mac地址和源Mac地址 */
        printf("DEST Mac: %02x:%02x:%02x:%02x:%02x:%02x\n SRC Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", data->fh.dstMac[0], data->fh.dstMac[1], data->fh.dstMac[2], data->fh.dstMac[3], data->fh.dstMac[4], data->fh.dstMac[5], data->fh.srcMac[0], data->fh.srcMac[1], data->fh.srcMac[2], data->fh.srcMac[3], data->fh.srcMac[4], data->fh.srcMac[5]); // 解析目的MAC和源MAC
        /* 打印校验和 */
        printf("ORI CKECKSUM: %04x\n", ntohs(data->ih.checksum));
        /* 打印计算得到的校验和 */
        data->ih.checksum = 0;
        printf("CAL CHECKSUM: %04x", ntohs(checkSum((USHORT *)&data->ih, 20)));
        break;
    case 0x86dd:
        printf("IPV6");
        break;
    case 0x0806:
        printf("ARP ");
        break;
    case 0x8035:
        printf("RARP");
        break;
    default:
        printf("OTHER TYPE");
        break;
    }
}

/* 深拷贝字符串 */
void deepCopy(char *dst, const char *src)
{
    dst = new char[strlen(src) + 1]{0};
    strcpy_s(dst, strlen(src) + 1, src);
}

/* 任意进制转十进制 */
int atoi(string s, int radix)
{
    int ans = 0;
    for (int i = 0; i < s.size(); i++)
    {
        char t = s[i];
        if (t >= '0' && t <= '9')
            ans = ans * radix + t - '0';
        else
            ans = ans * radix + t - 'a' + 10;
    }
    return ans;
}

/* 整合ARP数据包 
 * @param u_char* dstMac: 数据包目的Mac地址，ARP请求中没有意义
 * @param u_char* srcMac: 数据包源Mac地址
 * @param WORD operation: ARP类型 1为ARP请求 2为ARP应答
 * @param const char* srcIP: 源IP地址
 * @param const char* dstIP: 目的IP地址
 */
u_char* makeARPPacket(u_char* dstMac, u_char* srcMac, WORD operation, const char* srcIP, const char* dstIP)
{
    struct ARPData arpData[42];
	// 设置以太网帧的目的Mac地址
    //u_char dstMac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
	memcpy(arpData->fh.dstMac, dstMac, 6);
	// 设置以太网帧的源Mac地址
    //u_char srcMac[6] = { 0x0f,0x0f,0x0f,0x0f,0x0f,0x0f };   // 这里使用伪造的本机Mac地址
	memcpy(arpData->fh.srcMac, srcMac, 6);
	
	// 设置以太网帧的类型为ARP，不修改
	arpData->fh.type = htons(0x0806);
	// 设置ARP数据包硬件类型为以太网，不修改
    arpData->ap.hardwareType = htons(0x0001); 
	// 设置ARP数据包协议类型为IPV4，不修改
	arpData->ap.protocolType = htons(0x0800);
	// 设置ARP数据包硬件地址长度为6，不修改
    arpData->ap.hLen = 6;
	// 设置ARP数据包协议地址长度为4，不修改
    arpData->ap.pLen = 4;
	
	// 设置ARP数据包操作码为ARP请求
	arpData->ap.operation = operation;
	// 设置ARP数据包的源Mac地址
	memcpy(arpData->ap.sendHa, srcMac, 6);
	// 设置ARP数据包的源IP地址
    arpData->ap.sendIP = inet_addr(srcIP);
	// 设置ARP数据包的目的Mac地址
    //u_char reqDstMac[6] = { 0x0,0x0,0x0,0x0,0x0,0x0 };
	memcpy(arpData->ap.recvHa, dstMac, 6);   // arp请求中该项没有意义
	// 设置ARP数据包的目的IP地址
    arpData->ap.recvIP = inet_addr(dstIP);
	
	return (u_char*)arpData;
}

/* MAC地址比较 */
bool macCompare(BYTE *mac1, BYTE *mac2)
{
    for (int i = 0; i < 6; i++)
    {
        if (mac1[i] != mac2[i])
            return false;
    }
    return true;
}

void Lab1()
{
    /* 捕获数据包 */
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        /* 超时继续 */
        if (res == 0)
        {
            continue;
        }

        /* 打印时间 */
        printTime(header);

        /* 解析数据包并打印相关信息 */
        parse(header, pkt_data);
        printf("\n-----------------------------------------------------------------\n");
    }
    if (res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        exit(1);
    }
}

void Lab2()
{
    /* 构造获取本机MAC的虚构MAC地址的ARP数据包 */
    u_char dstMac[6] = BROADCAST_MAC;
    u_char srcMac[6] = FAKE_MAC;
    char* hostIP = devices[i - 1].ipAddr;   // 打开网卡的IP地址
    u_char* broadcastArpData = makeARPPacket(dstMac, srcMac, ARP_REQUEST, FAKE_IP, hostIP); // 向本机发送虚构地址的ARP请求数据包
    BYTE hostMac[6];
    /* 广播ARP数据包 */
    pcap_sendpacket(adhandle, broadcastArpData, 42);
    /* 捕获ARP数据包，分析本机MAC地址 */
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        /* 超时继续 */
        if (res == 0)
        {
            continue;
        }
        /* 分析捕获的唯一ARP数据包 */
        struct ARPData* caughtArpData = (struct ARPData*) pkt_data;
        WORD caughtPacketType = ntohs(caughtArpData->fh.type);
        WORD operation = caughtArpData->ap.operation;
        memcpy_s(hostMac, 6, caughtArpData->fh.srcMac, 6);
        if(res==1 && caughtPacketType ==0x0806 && operation==ARP_REPLY)   // 判断捕获的ARP数据包为ARP类型，且为ARP响应
        {
            printf("Host mac address: %02x-%02x-%02x-%02x-%02x-%02x\n", hostMac[0], hostMac[1], hostMac[2], hostMac[3], hostMac[4], hostMac[5]);
            break;
        }
    }
    if (res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        exit(-1);
    }

    while (1)
    {
        char dstIP[16] = { 0 };
        printf("\nWhat IP do you want to find the corresponding mac? Input here: ");
        scanf_s("%s", dstIP, 16);
        /* 分析查询的IP地址是否与打开网卡相同，若查询本机则使用虚构的MAC和IP地址，否则使用本机的MAC和IP地址填入发送端*/
        if (strcmp(hostIP, dstIP))
        {
            /* 查询远端网卡 */
            memcpy_s(srcMac, 6, hostMac, 6);
            broadcastArpData = makeARPPacket(dstMac, srcMac, ARP_REQUEST, hostIP, dstIP);
            pcap_sendpacket(adhandle, broadcastArpData, 42);
            while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
            {
                if (res == 0) continue;
                struct ARPData* caughtArpData = (struct ARPData*)pkt_data;
                WORD caughtPacketType = ntohs(caughtArpData->fh.type);
                BYTE caughtSrcMac[6];
                memcpy_s(caughtSrcMac, 6, caughtArpData->fh.srcMac, 6);
                WORD operation = caughtArpData->ap.operation;
                if (res == 1 && caughtPacketType == 0x0806 && operation == ARP_REPLY && !macCompare(caughtSrcMac, hostMac))   // 判断捕获的ARP数据包为ARP类型，且为ARP响应，且捕获的源MAC地址不为本机MAC地址
                {
                    printf("Caught mac address: %02x-%02x-%02x-%02x-%02x-%02x\n", caughtSrcMac[0], caughtSrcMac[1], caughtSrcMac[2], caughtSrcMac[3], caughtSrcMac[4], caughtSrcMac[5]);
                    break;
                }
            }
            if (res == -1)
            {
                printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
                exit(-1);
            }
        }
        else
        {
            /* 查询本机 */ // 其实这里直接返回保存的本机MAC地址也可，这里重复之前工作继续验证
            BYTE fakeSrcMac[6] = FAKE_MAC;
            memcpy_s(srcMac, 6, fakeSrcMac, 6);
            broadcastArpData = makeARPPacket(dstMac, srcMac, ARP_REQUEST, FAKE_IP, hostIP);
            pcap_sendpacket(adhandle, broadcastArpData, 42);
            while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
            {
                if (res == 0) continue;
                struct ARPData* caughtArpData = (struct ARPData*)pkt_data;
                WORD caughtPacketType = ntohs(caughtArpData->fh.type);
                BYTE caughtSrcMac[6];
                memcpy_s(caughtSrcMac, 6, caughtArpData->fh.srcMac, 6);
                WORD operation = caughtArpData->ap.operation;
                if (res == 1 && caughtPacketType == 0x0806 && operation == ARP_REPLY && macCompare(caughtSrcMac, hostMac))   // 判断捕获的ARP数据包为ARP类型，且为ARP响应，且捕获的源MAC地址必须为本机MAC地址
                {
                    printf("Caught mac address: %02x-%02x-%02x-%02x-%02x-%02x\n", caughtSrcMac[0], caughtSrcMac[1], caughtSrcMac[2], caughtSrcMac[3], caughtSrcMac[4], caughtSrcMac[5]);
                    break;
                }
            }
            if (res == -1)
            {
                printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
                exit(-1);
            }
        }
    }
}