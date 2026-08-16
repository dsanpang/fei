# FEI协议解析器使用指南

## 简介

`fei_protocol_parser.py` 是一个用于解析和创建FEI_HEADER_V3协议头的Python工具。它可以帮助开发者理解和验证36字节的FEI协议格式。

## 协议头结构

FEI_HEADER_V3协议头包含以下字段：

| 偏移 | 长度 | 字段名 | 说明 |
|------|------|--------|------|
| 0x00 | 4字节 | magic | 固定魔术字：0x46454900 ("FEI\0") |
| 0x04 | 2字节 | proto_ver | 协议版本号：当前代号 0x0300 (v3.0.0) |
| 0x06 | 2字节 | type | 状态类型：0x01心跳, 0x02插件载入, 0x03执行回传, 0x04异常, 0x05销毁 |
| 0x08 | 4字节 | seq | 防重放锁：基于单次会话 Nonce 与 Counter 的滚动哈希值 |
| 0x0C | 4字节 | length | 核心 Payload 真实物理长度（解密后长度） |
| 0x10 | 2字节 | padding_len | 尾部填充的垃圾数据长度（0 ~ 128 字节） |
| 0x12 | 8字节 | agent_id | 裁剪后的受控端 8 字节唯一物理设备指纹 |
| 0x1A | 8字节 | timestamp | 大端序 64 位毫秒级时间戳 |

## 使用方法

### 运行演示

```bash
python fei_protocol_parser.py
```

### 在代码中使用

```python
from fei_protocol_parser import parse_fei_header, create_fei_header

# 解析现有的协议头
header_bytes = b'\x00\x49\x45\x46...'  # 36字节的协议头数据
parsed = parse_fei_header(header_bytes)
print(f"代理ID: {parsed['agent_id']}")

# 创建新的协议头
new_header = create_fei_header(
    msg_type=0x01,  # 心跳包
    seq=12345,
    length=1024,
    agent_id_hex="A1B2C3D4E5F60001"
)
```

## 消息类型

| 值 | 名称 | 说明 |
|----|------|------|
| 0x01 | 心跳包 | 保持连接活跃 |
| 0x02 | 插件载入 | 向端点发送插件 |
| 0x03 | 执行回传 | 返回插件执行结果 |
| 0x04 | 异常状态 | 报告执行异常 |
| 0x05 | 销毁指令 | 销毁端点 |

## 注意事项

- 协议头必须恰好是36字节
- 时间戳使用大端序64位毫秒级时间戳
- 代理ID使用8字节十六进制表示
- 所有数值字段在网络传输时使用小端序（除了时间戳）