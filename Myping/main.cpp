#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Myping.h"

int main() {
    CPing objPing;
    char input[128];         // ���뻺����
    char szDestIP[64];       // IP ��ַ��������֧��IPv6
    int pingCount = 4;       // Ĭ�ϴ���
    int infinite = 0;        // �Ƿ����޴�
    int forceIPv4 = 0;       // �Ƿ�ǿ��IPv4
    int forceIPv6 = 0;       // �Ƿ�ǿ��IPv6

    printf("�����������ʽΪ: ping [-4|-6] [-n ����] [-t] IP\n");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("������Ч�������ԡ�\n");
        return 1;
    }

    // ȥ����β���з�
    input[strcspn(input, "\r\n")] = 0;

    // ��������
    // ֧��˳��: ping -4 -n ���� -t IP
    //          ping -6 -n ���� IP
    //          ping -n ���� IP
    //          ping -t IP
    //          ping IP
    char* token = strtok(input, " ");
    if (!token || strcmp(token, "ping") != 0) {
        printf("�����ʽ����������: ping [-4|-6] [-n ����] [-t] IP\n");
        return 1;
    }

    // �����������
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
                printf("��������: -n �����������\n");
                return 1;
            }
        } else if (strcmp(token, "-t") == 0) {
            infinite = 1;
        } else {
            // ʣ�µľ���IP
            strncpy(szDestIP, token, sizeof(szDestIP) - 1);
            szDestIP[sizeof(szDestIP) - 1] = '\0';
            // ����IP���в��������
            break;
        }
    }

    if (szDestIP[0] == '\0') {
        printf("ȱ��Ŀ��IP��ַ\n");
        return 1;
    }

    PingReply reply;
    printf("Pinging %s with %d bytes of data:\n", szDestIP, DEF_PACKET_SIZE);
    int count = 0;
    BOOL rv = 0;

    // �ж��Ƿ�ΪIPv6��ַ������:��ΪIPv6��
    int isIPv6 = strchr(szDestIP, ':') != NULL;
    // ���������в���
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
