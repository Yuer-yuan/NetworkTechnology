#include "pcap.h"
#include <time.h>
#include <string>
using namespace std;
#define _WINSOCK_DEPRECATED_NO_WARNING

#define LAB2
#ifdef LAB2
#define BROADCAST_MAC { 0xff,0xff,0xff,0xff,0xff,0xff }
#define FAKE_MAC { 0x0f,0x0f,0x0f,0x0f,0x0f,0x0f }
#define ARP_REQUEST htons(0x0001)
#define ARP_REPLY htons(0x0002)
#define FAKE_IP "112.112.112.112"

#endif // LAB2


//==帧首部、IP首部、ARP帧定义========================================================================
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
typedef struct IPData
{
    struct FrameHeader fh;
    struct IPHeader ih;
};
typedef struct ARPPacket
{
	WORD hardwareType;  // 硬件类型
	WORD protocolType;  //  协议类型
	BYTE hLen;  //  硬件地址长度
	BYTE pLen;  //  协议地址长度
	WORD operation; //  操作类型
	BYTE sendHa[6]; //  发送端硬件地址
	DWORD sendIP;   //  发送端IP地址
	BYTE recvHa[6]; //  接收端硬件地址
	DWORD recvIP;   //  接收端IP地址
};
typedef struct ARPData
{
	struct FrameHeader fh;
	struct ARPPacket ap;
};
#pragma pack() // 恢复默认对齐方式
struct Device
{
    char *name = NULL;
    char *description = NULL;
    char *ipAddr = NULL;
};

//==变量声明========================================================================
pcap_if_t *alldevs;            // 网卡列表
pcap_t *adhandle;              // 适配器句柄
Device *devices;               // 设备信息
struct pcap_pkthdr *header;    // 以太网数据帧头
const u_char *pkt_data;        // 以太网数据包
int res = 0;                   // 捕获数据包计数
char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息
int cnt;                       // 网卡计数
int i;                         // 用以输入要打开的设备序号

//==函数声明=======================================================================

/* 任意进制转十进制 */
int atoi(string s, int radix);

/* 深拷贝字符数组 */ // 无效！！！
void deepCopy(char *dst, const char *src);

/* 计算校验和 */
USHORT checkSum(USHORT *buffer, int size);

/* 打印时间 */
void printTime(struct pcap_pkthdr *header);

/* 解析数据包的帧首部和IP首部，得到类型、标识、序列号、校验和等 */
void parse(struct pcap_pkthdr *header, const u_char *pkt_data);

/* 构造ARP数据包 */
u_char* makeARPPacket(u_char* dstMac, u_char* srcMac, WORD operation, const char* srcIP, const char* dstIP);

/* MAC地址比较 */
bool macCompare(BYTE *mac1, BYTE *mac2);

/* IP数据包捕获实验 */
void Lab1();

/* 获取IP地址与MAC地址映射实验 */
void Lab2();
