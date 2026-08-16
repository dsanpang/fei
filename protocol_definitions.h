/*
 * FEI_HEADER_V3 协议定义
 * 36字节变长二进制流协议
 */

#ifndef PROTOCOL_DEFINITIONS_H
#define PROTOCOL_DEFINITIONS_H

#include <stdint.h>

// 定义FEI协议包头结构 (36字节)
#pragma pack(push, 1)  // 设置内存对齐为1字节
typedef struct {
    uint32_t magic;         // 0x00: 固定魔术字：0x46454900 ("FEI\0")
    uint16_t proto_ver;     // 0x04: 协议版本号：当前代号 0x0300 (v3.0.0)
    uint16_t type;          // 0x06: 状态类型：0x01心跳, 0x02插件载入, 0x03执行回传, 0x04异常, 0x05销毁
    uint32_t seq;           // 0x08: 防重放锁：基于单次会话 Nonce 与 Counter 的滚动哈希值
    uint32_t length;        // 0x0C: 核心 Payload 真实物理长度（解密后长度）
    uint16_t padding_len;   // 0x10: 尾部填充的垃圾数据长度（0 ~ 128 字节）
    uint8_t  agent_id[8];   // 0x12: 裁剪后的受控端 8 字节唯一物理设备指纹
    uint8_t  timestamp[8];  // 0x1A: 大端序 64 位毫秒级时间戳
} FEI_HEADER_V3;
#pragma pack(pop)  // 恢复默认内存对齐

// 协议类型定义
#define FEI_TYPE_HEARTBEAT      0x01    // 心跳包
#define FEI_TYPE_PLUGIN_LOAD    0x02    // 插件载入
#define FEI_TYPE_EXEC_RETURN    0x03    // 执行回传
#define FEI_TYPE_EXCEPTION      0x04    // 异常状态
#define FEI_TYPE_DESTROY        0x05    // 销毁指令

// 魔术字定义
#define FEI_MAGIC               0x46454900  // "FEI\0"

// 协议版本
#define FEI_PROTO_VER           0x0300      // v3.0.0

#endif // PROTOCOL_DEFINITIONS_H