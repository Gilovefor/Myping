#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Myping.h"

int main() {
    CPing objPing;
    char input[128];         // 输入缓冲区
    char szDestIP[64];       // IP 地址缓冲区，支持IPv6
    int pingCount = 4;       // 默认次数
    int infinite = 0;        // 是否无限次
    int forceIPv4 = 0;       // 是否强制IPv4
    int forceIPv6 = 0;       // 是否强制IPv6

    printf("请输入命令，格式为: ping [-4|-6] [-n 次数] [-t] IP\n");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("输入无效，请重试。\n");
        return 1;
    }

    // 去除结尾换行符
    input[strcspn(input, "\r\n")] = 0;

    // 参数解析
    // 支持顺序: ping -4 -n 次数 -t IP
    //          ping -6 -n 次数 IP
    //          ping -n 次数 IP
    //          ping -t IP
    //          ping IP
    char* token = strtok(input, " ");
    if (!token || strcmp(token, "ping") != 0) {
        printf("输入格式错误，请输入: ping [-4|-6] [-n 次数] [-t] IP\n");
        return 1;
    }

    // 逐个参数解析
    szDestIP[0] = '\0';
    while ((token = strtok(NULL, " ")) != NULL) {
        if (strcmp(token, "-4") == 0) {
            forceIPv4 = 1;
            forceIPv6 = 0;
        } else if (strcmp(token, "-6") == 0) {
            forceIPv6 = 1;
            forceIPv4 = 0;
        } else if (strcmp(token, "-n") == 0) {
            char* nstr = strtok(NULL, " ");
            if (!nstr || (pingCount = atoi(nstr)) <= 0) {
                printf("参数错误: -n 后需跟正整数\n");
                return 1;
            }
        } else if (strcmp(token, "-t") == 0) {
            infinite = 1;
        } else {
            // 剩下的就是IP
            strncpy(szDestIP, token, sizeof(szDestIP) - 1);
            szDestIP[sizeof(szDestIP) - 1] = '\0';
            // 允许IP后还有参数则忽略
            break;
        }
    }

    if (szDestIP[0] == '\0') {
        printf("缺少目标IP地址\n");
        return 1;
    }

    PingReply reply;
    printf("Pinging %s with %d bytes of data:\n", szDestIP, DEF_PACKET_SIZE);
    int count = 0;
    BOOL rv = 0;

    // 判断是否为IPv6地址（包含:即为IPv6）
    int isIPv6 = strchr(szDestIP, ':') != NULL;
    // 优先命令行参数
    if (forceIPv4) isIPv6 = 0;
    if (forceIPv6) isIPv6 = 1;

    while (infinite || count < pingCount) {
        rv = objPing.Ping(szDestIP, &reply);
        if (rv) {
            printf("Reply from %s: bytes=%d time=%ld ms TTL=%ld\n",
                szDestIP, reply.m_dwBytes, reply.m_dwRoundTripTime, reply.m_dwTTL);
        } else {
            printf("time out, can't connect to %s\n", szDestIP);
        }
        Sleep(500);
        count++;
    }
    return 0;
}
