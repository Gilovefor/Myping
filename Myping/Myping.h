#pragma once
#include <winsock2.h>
#pragma comment(lib,"WS2_32") // 链接 Winsock2 库

#define DEF_PACKET_SIZE 32     // 默认 ICMP 数据包大小
#define ECHO_REQUEST 8         // ICMP 回显请求类型
#define ECHO_REPLY 0           // ICMP 回显应答类型

// IP 数据包头部结构
struct IPHeader {
    BYTE m_byVerHLen;          // 版本和头部长度
    BYTE m_byTOS;              // 服务类型
    USHORT m_usTotalLen;       // 总长度
    USHORT m_usID;             // 标识
    USHORT m_usFlagFragOffset; // 3位标志 + 13位片偏移
    BYTE m_byTTL;              // 存活时间（TTL）
    BYTE m_byProtocol;         // 协议类型
    USHORT m_usHChecksum;      // 首部校验和
    ULONG m_ulSrcIP;           // 源 IP 地址
    ULONG m_ulDestIP;          // 目的 IP 地址
};

// ICMP 数据包头部结构
struct ICMPHeader {
    BYTE m_byType;             // ICMP 类型（如回显请求/应答）
    BYTE m_byCode;             // 代码
    USHORT m_usChecksum;       // 校验和
    USHORT m_usID;             // 标识符
    USHORT m_usSeq;            // 序列号
    ULONG m_ulTimeStamp;       // 时间戳
};

// ICMPv6 头部结构
struct ICMPv6Header {
    BYTE m_byType;
    BYTE m_byCode;
    USHORT m_usChecksum;
    USHORT m_usID;
    USHORT m_usSeq;
    // ICMPv6 头部没有时间戳字段，需自定义数据区
};

// Ping 应答信息结构
struct PingReply {
    USHORT m_usSeq;            // ICMP 序列号
    DWORD m_dwRoundTripTime;   // 往返时间（毫秒）
    DWORD m_dwBytes;           // 返回数据字节数
    DWORD m_dwTTL;             // TTL 值
};

class CPing {  
private:  
   SOCKET m_sockRaw;          // 原始套接字  
   WSAEVENT m_event;          // 套接字事件  
   USHORT m_usCurrentProcID;  // 当前进程 ID  
   char* m_szICMPData;        // ICMP 数据缓冲区  
   BOOL m_bIsInitSucc;        // 初始化是否成功  
   static USHORT s_usPacketSeq; // 静态包序列号  

public:  
   CPing();                   // 构造函数  
   ~CPing();                  // 析构函数  

   // 通过 IP 地址（DWORD）发送 Ping  
   BOOL Ping(DWORD dwDestIP, PingReply* pPingReply = NULL, DWORD dwTimeout = 2000);  
   // 通过 IP 地址（字符串）发送 Ping  
   BOOL Ping(char* szDestIP, PingReply* pPingReply = NULL, DWORD dwTimeout = 2000);  

private:  
   // Ping 核心实现  
   BOOL PingCore(DWORD dwDestIP, PingReply* pPingReply, DWORD dwTimeout);  
   // 新增 Ping 接口 - 将 PingIPv6 方法从 private 移动到 public  
   BOOL PingIPv6(const char* szDestIP, PingReply* pPingReply = NULL, DWORD dwTimeout = 2000);
   // 计算校验和  
   USHORT CalCheckSum(USHORT* pBuffer, int nSize);  
   // 获取当前时间（用于时间戳）  
   ULONG GetTickCountCalibrate();  
};
