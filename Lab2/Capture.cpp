#include "pcap.h"
#include <time.h>
#include <string>
using namespace std;


//==变量声明========================================================================
pcap_if_t* alldevs; //网卡列表
pcap_if_t* d;   //设备指针
pcap_addr_t* a; //地址
pcap_t* adhandle;   //适配器句柄
struct pcap_pkthdr* header; //数据包头
struct tm ltime;    // 本地时间
time_t local_tv_sec;    // 本地时间
const u_char* pkt_data; // 数据包数据
char errbuf[PCAP_ERRBUF_SIZE];  // 错误信息
char timestr[16];   // 时间字符串
int cnt = 0;    // 网卡计数
int res = 0;    // 捕获数据包计数
int i;  // 作为输入，选中的网卡序号[1-cnt]


//==帧首部和IP首部定义========================================================================

#pragma pack(1) // 进入字节对齐模式
typedef struct FrameHeader
{
    BYTE dstMac[6]; // 目的MAC地址
    BYTE srcMac[6]; // 源MAC地址
    WORD type;      // 类型
};
typedef struct IPHeader
{
    BYTE verLen;
    BYTE tos;
    WORD totalLen;
    WORD id; // 标识
    WORD flagOffset;
    BYTE ttl;
    BYTE protocol;
    WORD checksum; // 校验和
    DWORD srcIP;
    DWORD dstIP;
};
typedef struct Data
{
    struct FrameHeader fh;
    struct IPHeader ih;
};
#pragma pack() // 恢复默认对齐方式


//==函数声明=======================================================================

/* 任意进制转十进制 */
int Atoi(string s, int radix);

/* 计算校验和 */
USHORT CheckSum(USHORT* buffer, int size);

/*解析数据包的帧首部和IP首部，得到类型、标识、序列号、校验和等*/
void parse(const u_char* pkt_data);


//==主函数========================================================================

int main()
{
    /* 获取本机网卡列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s", errbuf);
        exit(1);
    }

    /* 展示网卡列表 */
    printf("All device are listed here.\n");
    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("%d\tName: %s\tDescription: %s\n", ++cnt, d->name, d->description);
    }
    if (cnt == 0)
    {
        printf("No interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    /* 选择输入监听的网卡序号 */
    printf("Enter the device number (1-%d):", cnt);
    scanf_s("%d", &i);
    if (i < 1 || i > cnt)
    {
        printf("Device number out of range.\n");
        /* 释放网卡列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 选中对应网卡 */
    for (d = alldevs, cnt = 0; cnt < i - 1; d = d->next, cnt++)
        ;

    /* 打开网卡 */
    if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放网卡列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\nListening on %s...\n", d->description);

    /* 释放网卡列表 */
    pcap_freealldevs(alldevs);

    /* 捕获数据包 */
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {

        if (res == 0)
            continue; /* 超时继续 */

        /* 打印时间 */
        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
        printf("[%s,%.6ld]\t", timestr, header->ts.tv_usec);

		/* 打印数据包长度 */
        printf("PKT LENGTH: %d\n", Atoi(to_string(header->len),16));

        /* 打印数据包原始内容 */
        /*int len = header->len;
        for (i = 1; i < len; i++)
        {
            printf("%.2x ", pkt_data[i - 1]);
            if ((i % 16) == 0)
                printf("\n");
        }*/

        /* 解析数据包并打印相关信息 */
        parse(pkt_data);
        printf("\n-----------------------------------------------------------------\n");
    }
    if (res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }

    return 0;
}


//==函数定义=====================================================================

/* 计算校验和 */
USHORT CheckSum(USHORT* buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);  //将高16bit与低16bit相加
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

/*解析数据包的帧首部和IP首部，得到类型、标识、头部校验和*/
void parse(const u_char* pkt_data)
{
    struct Data* data = (struct Data*)pkt_data;
    /* 打印序列号 */
    printf("ID: % 04x\t\t", ntohs(data->ih.id));

    /* 打印IP数据包长度 */
    printf("IP PKT LENGTH: %d\n", Atoi(to_string(ntohs(data->ih.totalLen)), 16));

    /* 打印目的Mac地址和源Mac地址 */
    printf("DEST Mac: %02x:%02x:%02x:%02x:%02x:%02x\n SRC Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", data->fh.dstMac[0], data->fh.dstMac[1], data->fh.dstMac[2], data->fh.dstMac[3], data->fh.dstMac[4], data->fh.dstMac[5], data->fh.srcMac[0], data->fh.srcMac[1], data->fh.srcMac[2], data->fh.srcMac[3], data->fh.srcMac[4], data->fh.srcMac[5]); // 解析目的MAC和源MAC

    /* 打印帧类型 */
    printf("FRAME TYPE: %04x,", ntohs(data->fh.type));
    switch (ntohs(data->fh.type))
    {
    case 0x0800:
        printf("IPV4\n");
        /* 打印校验和 */
        printf("ORI CKECKSUM: %04x\n", ntohs(data->ih.checksum));
        /* 打印计算得到的校验和 */
        data->ih.checksum = 0;
        printf("CAL CHECKSUM: %04x", ntohs(CheckSum((USHORT*)&data->ih, 20)));
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

/* 任意进制转十进制 */
int Atoi(string s, int radix)
{
    int ans = 0;
    for (int i = 0; i < s.size(); i++)
    {
        char t = s[i];
        if (t >= '0' && t <= '9') ans = ans * radix + t - '0';
        else ans = ans * radix + t - 'a' + 10;
    }
    return ans;
}