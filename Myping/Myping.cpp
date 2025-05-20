#include "Myping.h"
#include <iostream>
#include <stdio.h>
#include <ws2tcpip.h> // for sockaddr_in6, inet_pton
using namespace std;

// 静态成员初始化：ICMP包序列号
USHORT CPing::s_usPacketSeq = 0;

CPing::CPing() : m_szICMPData(NULL), m_bIsInitSucc(FALSE), m_event(NULL), m_sockRaw(INVALID_SOCKET), m_usCurrentProcID(0) {  
   WSADATA WSAData;  
   // 初始化Winsock库  
   if (WSAStartup(MAKEWORD(1, 1), &WSAData) != 0) {  
       printf("WSAStartup() failed: %d\n", GetLastError());  
       return;  
   }  
   m_event = WSACreateEvent();  
   m_usCurrentProcID = (USHORT)GetCurrentProcessId();  

   // 创建原始套接字用于ICMP协议  
   m_sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);  
   if (m_sockRaw == INVALID_SOCKET) {  
       cerr << "WSASocket() failed: " << WSAGetLastError() << endl;  
   }  
   else {  
       WSAEventSelect(m_sockRaw, m_event, FD_READ);  
       m_bIsInitSucc = TRUE;  
       // 分配ICMP数据缓冲区  
       m_szICMPData = (char*)malloc(DEF_PACKET_SIZE + sizeof(ICMPHeader));  
       if (m_szICMPData == NULL) {  
           m_bIsInitSucc = FALSE;  
       }  
   }  
}

// 析构函数：释放资源
CPing::~CPing() {
    WSACleanup();
    if (m_szICMPData != NULL) {
        free(m_szICMPData);
        m_szICMPData = NULL;
    }
}

/*****************************************************************************/
// 通过DWORD类型IP地址发送Ping
BOOL CPing::Ping(DWORD dwDestIP, PingReply* pPingReply, DWORD dwTimeout) {
    return PingCore(dwDestIP, pPingReply, dwTimeout);
}

// 通过字符串类型IP地址发送Ping
BOOL CPing::Ping(char* szDestIP, PingReply* pPingReply, DWORD dwTimeout) {
    if (szDestIP == NULL) {
        return FALSE;
    }
    // 判断是否为IPv6地址（包含:即为IPv6）
    if (strchr(szDestIP, ':')) {
        return PingIPv6(szDestIP, pPingReply, dwTimeout);
    }
    else {
        return PingCore(inet_addr(szDestIP), pPingReply, dwTimeout);
    }
}
/*****************************************************************************/

// Ping核心实现
BOOL CPing::PingCore(DWORD dwDestIP, PingReply* pPingReply, DWORD dwTimeout) {
    if (!m_bIsInitSucc)
        return FALSE;

    sockaddr_in sockaddrDest;
    sockaddrDest.sin_family = AF_INET;
    sockaddrDest.sin_addr.s_addr = dwDestIP;
    int nSockaddrDestSize = sizeof(sockaddrDest);

    int nICMPDataSize = DEF_PACKET_SIZE + sizeof(ICMPHeader);
    ULONG ulSendTimeStamp = GetTickCountCalibrate();
    USHORT usSeq = ++s_usPacketSeq;
    memset(m_szICMPData, 0, nICMPDataSize);

    // 构造ICMP头部
    ICMPHeader* pICMPHeader = (ICMPHeader*)m_szICMPData;
    pICMPHeader->m_byType = ECHO_REQUEST;
    pICMPHeader->m_byCode = 0;
    pICMPHeader->m_usID = m_usCurrentProcID;
    pICMPHeader->m_usSeq = usSeq;
    pICMPHeader->m_ulTimeStamp = ulSendTimeStamp;
    pICMPHeader->m_usChecksum = CalCheckSum((USHORT*)m_szICMPData, nICMPDataSize);

    // 发送ICMP请求
    if (sendto(m_sockRaw, m_szICMPData, nICMPDataSize, 0, (struct sockaddr*)&sockaddrDest, nSockaddrDestSize) == SOCKET_ERROR) {
        return FALSE;
    }

    // 如果不需要接收应答，直接返回
    if (pPingReply == NULL) {
        return TRUE;
    }

    char recvbuf[256] = { 0 };
    while (TRUE) {
        // 等待接收ICMP应答
        if (WSAWaitForMultipleEvents(1, &m_event, FALSE, 100, FALSE) != WSA_WAIT_TIMEOUT) {
            WSANETWORKEVENTS netEvent;
            WSAEnumNetworkEvents(m_sockRaw, m_event, &netEvent);

            if (netEvent.lNetworkEvents & FD_READ) {
                ULONG nRecvTimestamp = GetTickCountCalibrate();
                int nPacketSize = recvfrom(m_sockRaw, recvbuf, 256, 0, (struct sockaddr*)&sockaddrDest, &nSockaddrDestSize);
                if (nPacketSize != SOCKET_ERROR) {
                    IPHeader* pIPHeader = (IPHeader*)recvbuf;
                    USHORT usIPHeaderLen = (USHORT)((pIPHeader->m_byVerHLen & 0x0f) * 4);
                    ICMPHeader* pICMPHeader = (ICMPHeader*)(recvbuf + usIPHeaderLen);

                    // 检查应答包是否为本进程发出的请求的应答
                    if (pICMPHeader->m_usID == m_usCurrentProcID &&
                        pICMPHeader->m_byType == ECHO_REPLY &&
                        pICMPHeader->m_usSeq == usSeq) {
                        pPingReply->m_usSeq = usSeq;
                        pPingReply->m_dwRoundTripTime = nRecvTimestamp - pICMPHeader->m_ulTimeStamp;
                        pPingReply->m_dwBytes = nPacketSize - usIPHeaderLen - sizeof(ICMPHeader);
                        pPingReply->m_dwTTL = pIPHeader->m_byTTL;
                        return TRUE;
                    }
                }
            }
        }
        // 超时处理
        if (GetTickCountCalibrate() - ulSendTimeStamp >= dwTimeout) {
            return FALSE;
        }
    }
}

BOOL CPing::PingIPv6(const char* szDestIP, PingReply* pPingReply, DWORD dwTimeout) {
    // 1. 创建 IPv6 原始套接字
    SOCKET sockRaw6 = WSASocket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, NULL, 0, 0);
    if (sockRaw6 == INVALID_SOCKET) {
        printf("WSASocket(AF_INET6) failed: %d\n", WSAGetLastError());
        return FALSE;
    }

    // 2. 设置非阻塞事件
    WSAEVENT event6 = WSACreateEvent();
    WSAEventSelect(sockRaw6, event6, FD_READ);

    // 3. 构造目标地址
    sockaddr_in6 sockaddrDest6 = { 0 };
    sockaddrDest6.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, szDestIP, &sockaddrDest6.sin6_addr) != 1) {
        printf("inet_pton failed for IPv6 address: %s\n", szDestIP);
        closesocket(sockRaw6);
        WSACloseEvent(event6);
        return FALSE;
    }
    int nSockaddrDest6Size = sizeof(sockaddrDest6);

    // 4. 构造ICMPv6数据包
    int nICMPv6DataSize = DEF_PACKET_SIZE + sizeof(ICMPv6Header);
    char* icmpv6Data = (char*)malloc(nICMPv6DataSize);
    if (!icmpv6Data) {
        closesocket(sockRaw6);
        WSACloseEvent(event6);
        return FALSE;
    }
    memset(icmpv6Data, 0, nICMPv6DataSize);

    ICMPv6Header* pICMPv6Header = (ICMPv6Header*)icmpv6Data;
    pICMPv6Header->m_byType = 128; // ICMPv6 Echo Request
    pICMPv6Header->m_byCode = 0;
    pICMPv6Header->m_usID = m_usCurrentProcID;
    USHORT usSeq = ++s_usPacketSeq;
    pICMPv6Header->m_usSeq = usSeq;
    pICMPv6Header->m_usChecksum = 0; // 让内核自动计算

    // 5. 发送ICMPv6请求
    ULONG ulSendTimeStamp = GetTickCountCalibrate();
    int nSend = sendto(sockRaw6, icmpv6Data, nICMPv6DataSize, 0, (sockaddr*)&sockaddrDest6, nSockaddrDest6Size);
    if (nSend == SOCKET_ERROR) {
        free(icmpv6Data);
        closesocket(sockRaw6);
        WSACloseEvent(event6);
        return FALSE;
    }

    // 6. 接收ICMPv6应答
    BOOL bResult = FALSE;
    char recvbuf[256] = { 0 };
    int nRecvAddrLen = sizeof(sockaddr_in6);
    sockaddr_in6 recvAddr6 = { 0 };

    while (TRUE) {
        if (WSAWaitForMultipleEvents(1, &event6, FALSE, 100, FALSE) != WSA_WAIT_TIMEOUT) {
            WSANETWORKEVENTS netEvent;
            WSAEnumNetworkEvents(sockRaw6, event6, &netEvent);

            if (netEvent.lNetworkEvents & FD_READ) {
                ULONG nRecvTimestamp = GetTickCountCalibrate();
                int nPacketSize = recvfrom(sockRaw6, recvbuf, sizeof(recvbuf), 0, (sockaddr*)&recvAddr6, &nRecvAddrLen);
                if (nPacketSize != SOCKET_ERROR) {
                    // IPv6无IP头，直接ICMPv6头
                    ICMPv6Header* pICMPv6Reply = (ICMPv6Header*)recvbuf;
                    if (pICMPv6Reply->m_byType == 129 && // Echo Reply
                        pICMPv6Reply->m_usID == m_usCurrentProcID &&
                        pICMPv6Reply->m_usSeq == usSeq) {
                        if (pPingReply) {
                            pPingReply->m_usSeq = usSeq;
                            pPingReply->m_dwRoundTripTime = nRecvTimestamp - ulSendTimeStamp;
                            pPingReply->m_dwBytes = nPacketSize - sizeof(ICMPv6Header);
                            pPingReply->m_dwTTL = 0; // Windows原始套接字无法直接获取TTL
                        }
                        bResult = TRUE;
                        break;
                    }
                }
            }
        }
        // 超时
        if (GetTickCountCalibrate() - ulSendTimeStamp >= dwTimeout) {
            break;
        }
    }

    free(icmpv6Data);
    closesocket(sockRaw6);
    WSACloseEvent(event6);
    return bResult;
}
/*****************************************************************************/

// 计算ICMP校验和
USHORT CPing::CalCheckSum(USHORT* pBuffer, int nSize) {
    unsigned long ulCheckSum = 0;
    while (nSize > 1) {
        ulCheckSum += *pBuffer;
        pBuffer++;
        nSize -= sizeof(USHORT);
    }
    if (nSize)
        ulCheckSum += *(UCHAR*)pBuffer;
    ulCheckSum = (ulCheckSum >> 16) + (ulCheckSum & 0xffff);
    ulCheckSum += (ulCheckSum >> 16);
    return (USHORT)(~ulCheckSum);
}
/*****************************************************************************/

// 获取当前时间（用于时间戳，做一定校准）
ULONG CPing::GetTickCountCalibrate() {
    static ULONG s_ulFirstCallTick = 0;
    static LONGLONG s_ullFirstCallTickMS = 0;

    SYSTEMTIME systemtime;
    FILETIME filetime;
    GetLocalTime(&systemtime);
    SystemTimeToFileTime(&systemtime, &filetime);
    LARGE_INTEGER liCurrentTime;
    liCurrentTime.HighPart = filetime.dwHighDateTime;
    liCurrentTime.LowPart = filetime.dwLowDateTime;
    LONGLONG llCurrentTimeMS = liCurrentTime.QuadPart / 10000;
    if (s_ulFirstCallTick == 0) {
        s_ulFirstCallTick = GetTickCount();
    }
    if (s_ullFirstCallTickMS == 0) {
        s_ullFirstCallTickMS = llCurrentTimeMS;
    }
    return s_ulFirstCallTick + (ULONG)(llCurrentTimeMS - s_ullFirstCallTickMS);
}
