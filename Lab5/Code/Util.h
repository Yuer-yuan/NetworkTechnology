#ifndef ROUTERAPPLICATION_UTIL_H
#define ROUTERAPPLICATION_UTIL_H

#include <Winsock2.h>
#include <stdio.h>
#include <string>
#include <time.h>
using namespace std;

string b2s(DWORD addr);  // 将DWORD类型的IP地址转换为字符串

string b2s(BYTE* mac);   // 将BYTE类型的MAC地址转换为字符串

string v2s(int value);  // 将int类型的值转换为字符串

string v2s(u_int value); // 将u_int类型的值转换为字符串

string t2s(time_t time); // 将time_t类型的时间转换为字符串

bool macCmp(BYTE* mac1, BYTE* mac2); // 比较两个MAC地址是否相同

string recvLog(DWORD srcIP, BYTE* srcMac, DWORD dstIP, BYTE* dstMac, int ttl); // 打印接收日志

string fwrdLog(DWORD dstIP, BYTE* dstMac, int ttl, bool nextHop = true); // 打印转发日志

#endif //ROUTERAPPLICATION_UTIL_H
