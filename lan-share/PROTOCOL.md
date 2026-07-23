# LanShare Protocol (LSP) v3.0

## 1. 概述

LSP v3.0 是一个面向局域网文件传输的二进制协议。
设计目标：安全、可靠、高效、可扩展。

### 1.1 设计原则

1. **多路复用** — 单连接上并行多个操作（Stream）
2. **端到端加密** — X25519 密钥交换 + ChaCha20-Poly1305 AEAD
3. **流量控制** — 滑动窗口，背压传导，零窗口探测
4. **可靠传输** — 序列号 + ACK + 超时重传 + 快速重传 + SACK
5. **拥塞控制** — 慢启动 + 拥塞避免 + 快速恢复（RFC 5681）
6. **差异传输** — rsync 风格增量同步（Adler-32 + SHA-256）
7. **透明压缩** — LZ4（默认）/ Zstd，自动跳过不可压缩文件
8. **可扩展** — 扩展帧头 + 能力协商

---

## 2. 帧格式

### 2.1 基础帧头（24 字节）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Magic = 0x4C535033 ("LSP3")                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version      |  FrameType    |          Flags                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Frame Length                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Stream ID                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 字段 | 大小 | 说明 |
|------|------|------|
| Magic | 4B | `0x4C535033`（"LSP3"） |
| Version | 1B | 协议版本，当前 = 3 |
| FrameType | 1B | 帧类型（见 §3） |
| Flags | 2B | 标志位（见 §2.2） |
| FrameLength | 4B | 帧总长度（含帧头），最大 16MB |
| StreamID | 4B | 流 ID（0 = 控制流） |
| SequenceNumber | 4B | 该流内的序列号 |

### 2.2 Flags

```
Bit 0:  ENCRYPTED     — 载荷已加密
Bit 1:  COMPRESSED    — 载荷已压缩
Bit 2:  FIN           — 流结束
Bit 3:  RST           — 流重置
Bit 4:  ACK_FRAME     — 这是一个 ACK 帧
Bit 5:  HAS_EXT       — 存在扩展帧头
Bit 6:  PRIORITY      — 高优先级
Bit 7:  RELIABLE      — 需要可靠传输（ACK 确认）
Bit 8-15: 保留
```

### 2.3 扩展帧头（可选，16 字节）

当 `Flags.HAS_EXT` 设置时，紧跟基础帧头之后：

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Extension Type                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Extension Length                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Extension Data (variable)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

扩展类型：

| Type | 名称 | 说明 |
|------|------|------|
| 0x0001 | TIMESTAMP | 帧发送时间戳（8 字节，Unix ms） |
| 0x0002 | PADDING | 填充（防流量分析） |
| 0x0003 | TRACE_ID | 分布式追踪 ID |
| 0x0004 | CUSTOM | 自定义扩展 |

### 2.4 帧结构总览

```
┌─────────────────────────────────────────────────────────┐
│ 基础帧头 (24B)                                          │
├─────────────────────────────────────────────────────────┤
│ 扩展帧头 (可选, 16B+)     ← Flags.HAS_EXT              │
├─────────────────────────────────────────────────────────┤
│ 加密 Nonce (可选, 12B)    ← Flags.ENCRYPTED            │
├─────────────────────────────────────────────────────────┤
│ Payload (变长)                                          │
│ = 帧总长度 - 帧头 - 扩展头 - Nonce - AEAD Tag(16B)     │
├─────────────────────────────────────────────────────────┤
│ AEAD Auth Tag (可选, 16B) ← Flags.ENCRYPTED            │
└─────────────────────────────────────────────────────────┘
```

---

## 3. 帧类型

### 3.1 连接管理

| ID | 名称 | 说明 |
|----|------|------|
| 0x01 | HELLO | 客户端握手（能力协商） |
| 0x02 | HELLO_ACK | 服务端握手响应 |
| 0x03 | AUTH_INIT | 认证初始化（X25519 公钥） |
| 0x04 | AUTH_CHALLENGE | 认证挑战（服务端公钥 + 加密 PIN 验证） |
| 0x05 | AUTH_RESPONSE | 认证响应（PIN 证明 + HMAC） |
| 0x06 | AUTH_OK | 认证成功（会话密钥确认） |
| 0x07 | AUTH_FAIL | 认证失败 |
| 0x08 | CAPABILITY | 能力协商 |
| 0x09 | KEEPALIVE | 心跳 |
| 0x0A | KEEPALIVE_ACK | 心跳响应 |
| 0x0B | GOODBYE | 优雅断开 |

### 3.2 流管理

| ID | 名称 | 说明 |
|----|------|------|
| 0x10 | STREAM_OPEN | 打开新流 |
| 0x11 | STREAM_OPEN_ACK | 确认打开流 |
| 0x12 | STREAM_CLOSE | 关闭流 |
| 0x13 | STREAM_WINDOW_UPDATE | 流量控制窗口更新 |
| 0x14 | STREAM_RESET | 重置流 |

### 3.3 文件操作

| ID | 名称 | 说明 |
|----|------|------|
| 0x20 | FILE_LIST | 列出目录 |
| 0x21 | FILE_LIST_RESP | 目录列表响应 |
| 0x22 | FILE_STAT | 获取文件元数据 |
| 0x23 | FILE_STAT_RESP | 元数据响应 |
| 0x24 | FILE_MKDIR | 创建目录 |
| 0x25 | FILE_RENAME | 重命名/移动 |
| 0x26 | FILE_DELETE | 删除文件/目录 |
| 0x27 | FILE_LOCK | 加锁 |
| 0x28 | FILE_UNLOCK | 解锁 |
| 0x29 | FILE_WATCH | 监听变更 |
| 0x2A | FILE_NOTIFY | 变更通知 |

### 3.4 数据传输

| ID | 名称 | 说明 |
|----|------|------|
| 0x30 | READ_REQ | 读取文件（指定范围） |
| 0x31 | READ_DATA | 读取响应（数据块） |
| 0x32 | WRITE_REQ | 写入文件（开始） |
| 0x33 | WRITE_DATA | 写入数据块 |
| 0x34 | WRITE_COMMIT | 提交写入 |
| 0x35 | WRITE_ROLLBACK | 回滚写入 |

### 3.5 可靠传输（v3.0 新增）

| ID | 名称 | 说明 |
|----|------|------|
| 0x40 | SACK | 选择性确认（累计确认 + SACK 块） |
| 0x41 | WINDOW_UPDATE | 流量控制窗口更新 |
| 0x42 | DELTA_SYNC | 差异同步请求（请求文件签名） |
| 0x43 | DELTA_SYNC_RESP | 差异同步响应（文件签名） |
| 0x44 | DELTA_DATA | 差异数据传输（Copy/Literal 指令） |

### 3.6 通用

| ID | 名称 | 说明 |
|----|------|------|
| 0xF0 | ACK | 确认帧 |
| 0xF1 | NACK | 否定确认（请求重传） |
| 0xFE | ERROR | 错误 |
| 0xFF | PING | 延迟测试 |
| 0xFE | PONG | 延迟测试响应 |

---

## 4. 连接生命周期

### 4.1 状态机

```
                    ┌──────────┐
                    │  CLOSED  │
                    └────┬─────┘
                         │ TCP connect
                         ▼
                    ┌──────────┐
            ┌──────│  HELLO   │──────┐
            │      └──────────┘      │ timeout
            │ success                 ▼
            │                   ┌──────────┐
            │                   │  FAILED  │
            │                   └──────────┘
            ▼
       ┌──────────┐
       │AUTH_INIT │  X25519 密钥交换
       └────┬─────┘
            │
            ▼
       ┌──────────────┐
       │AUTH_CHALLENGE│  服务端验证 PIN
       └────┬─────────┘
            │
            ▼
       ┌──────────────┐
       │AUTH_RESPONSE │  客户端证明
       └────┬─────────┘
            │
      ┌─────┴─────┐
      │           │
      ▼           ▼
 ┌─────────┐ ┌──────────┐
 │AUTH_OK  │ │AUTH_FAIL │
 └────┬────┘ └──────────┘
      │
      ▼
 ┌──────────┐
 │ESTABLISHED│ ← 正常工作状态
 └────┬─────┘
      │ GOODBYE / timeout / error
      ▼
 ┌──────────┐
 │ CLOSING  │
 └────┬─────┘
      │
      ▼
 ┌──────────┐
 │  CLOSED  │
 └──────────┘
```

### 4.2 握手流程

```
Client                              Server
  │                                    │
  │──── HELLO ────────────────────────>│
  │     { version: 2,                  │
  │       capabilities: [              │
  │         "stream_multiplex",        │
  │         "encryption",              │
  │         "compression",             │
  │         "file_watch",              │
  │         "incremental_sync"         │
  │       ],                           │
  │       device_info: {               │
  │         id: "uuid",                │
  │         name: "My PC",             │
  │         os: "windows",             │
  │         version: "1.0.0"           │
  │       }                            │
  │     }                              │
  │                                    │
  │<──── HELLO_ACK ────────────────────│
  │      { version: 2,                 │
  │        capabilities: [             │
  │          "stream_multiplex",       │
  │          "encryption"              │
  │        ],                          │
  │        max_streams: 64,            │
  │        max_frame_size: 1048576,    │
  │        session_id: "uuid"          │
  │      }                             │
  │                                    │
  │──── AUTH_INIT ────────────────────>│
  │     { client_pubkey: 32bytes }     │
  │                                    │
  │<──── AUTH_CHALLENGE ──────────────│
  │      { server_pubkey: 32bytes,     │
  │        nonce: 12bytes,             │
  │        encrypted_challenge: bytes  │
  │      }                             │
  │                                    │
  │  (双方计算 shared_secret           │
  │   = X25519(client_priv, server_pub)│
  │   = X25519(server_priv, client_pub)│
  │   派生会话密钥)                     │
  │                                    │
  │──── AUTH_RESPONSE ────────────────>│
  │     { pin_proof: HMAC(pin, key),   │
  │       device_name: "...",          │
  │       session_token: "..."         │
  │     }                              │
  │                                    │
  │<──── AUTH_OK ─────────────────────│
  │      { permission: "readwrite",    │
  │        server_proof: HMAC(...)     │
  │      }                             │
  │                                    │
  │  ===== ESTABLISHED =====           │
```

### 4.3 密钥派生

```
shared_secret = X25519(client_private, server_public)
              = X25519(server_private, client_public)

// HKDF 派生
session_key  = HKDF-SHA256(shared_secret, "lsp-session-key",  nonce || timestamp)
write_key    = HKDF-SHA256(session_key,  "lsp-client-write",  "")  // 客户端→服务端
read_key     = HKDF-SHA256(session_key,  "lsp-server-write",  "")  // 服务端→客户端
```

---

## 5. 多路复用（Stream）

### 5.1 流模型

```
Connection
├── Stream 0 (控制流)    — 心跳、ACK、错误
├── Stream 1 (文件列表)  — list / stat / watch
├── Stream 2 (下载)      — read_req / read_data
├── Stream 3 (上传)      — write_req / write_data
└── Stream N ...
```

- Stream 0 保留为控制流，始终存在
- 每个流独立编号，独立序列号空间
- 流之间互不阻塞
- 每个流有独立的流量控制窗口

### 5.2 流生命周期

```
OPEN → OPEN_ACK → DATA... → FIN → CLOSE
                 ↘ RST → CLOSE（异常）
```

### 5.3 流量控制

```
发送方维护：
  - send_window: 对方允许的发送窗口大小
  - bytes_in_flight: 已发送未确认的字节数
  - 约束: bytes_in_flight < send_window

接收方通过 STREAM_WINDOW_UPDATE 通知窗口变化：
  { stream_id: 2, increment: 65536 }

初始窗口: 1MB
最大窗口: 64MB
```

---

## 6. 可靠传输

### 6.1 ACK 机制

```
发送方:  seq=1, seq=2, seq=3, seq=4, seq=5
接收方:  ACK(3)  ← 累积确认，表示 1-3 全部收到
         NACK(4) ← 请求重传 seq=4
```

### 6.2 超时重传

```
RTO (Retransmission Timeout) 计算：
  SRTT = 平滑 RTT
  RTTVAR = RTT 偏差
  RTO = SRTT + max(4 * RTTVAR, 100ms)

初始 RTO = 1s
最大重传次数 = 5
退避策略: RTO * 2^retransmit_count
```

### 6.3 NACK 快速重传

收到 NACK 立即重传指定序列号的帧，不等超时。

---

## 7. 文件操作详细设计

### 7.1 文件元数据

```json
{
    "name": "document.pdf",
    "path": "/docs/document.pdf",
    "size": 1048576,
    "created": 1700000000,
    "modified": 1700001000,
    "accessed": 1700002000,
    "is_dir": false,
    "readonly": false,
    "hidden": false,
    "sha256": "abcdef...",
    "mime_type": "application/pdf",
    "permissions": "rw-r--r--"
}
```

### 7.2 增量同步

```
Client                              Server
  │                                    │
  │──── FILE_WATCH ───────────────────>│
  │     { path: "/docs",               │
  │       events: ["create","modify",  │
  │                "delete","rename"]   │
  │     }                              │
  │                                    │
  │<──── FILE_NOTIFY ─────────────────│  (异步推送)
  │      { event: "modify",            │
  │        path: "/docs/report.pdf",   │
  │        old_size: 1024,             │
  │        new_size: 2048,             │
  │        modified: 1700003000        │
  │      }                             │
```

### 7.3 文件锁

```
Client A                          Server                    Client B
  │                                  │                         │
  │──── FILE_LOCK ──────────────────>│                         │
  │     { path: "data.csv",          │                         │
  │       mode: "exclusive",         │                         │
  │       ttl: 300 }                 │                         │
  │                                  │                         │
  │<──── ACK (locked) ──────────────│                         │
  │                                  │<──── FILE_LOCK ─────────│
  │                                  │      { path: "data.csv",│
  │                                  │        mode: "exclusive"}
  │                                  │──────→ CONFLICT / WAIT │
  │                                  │                         │
  │──── FILE_UNLOCK ────────────────>│                         │
  │                                  │──────→ ACK to B ───────│
```

---

## 8. 错误码

| 码 | 名称 | 说明 |
|----|------|------|
| 0x01 | VERSION_MISMATCH | 协议版本不支持 |
| 0x02 | AUTH_FAILED | 认证失败 |
| 0x03 | PERMISSION_DENIED | 权限不足 |
| 0x04 | NOT_FOUND | 文件/目录不存在 |
| 0x05 | ALREADY_EXISTS | 文件已存在 |
| 0x06 | DISK_FULL | 磁盘空间不足 |
| 0x07 | FILE_LOCKED | 文件被锁定 |
| 0x08 | CHECKSUM_MISMATCH | 校验失败 |
| 0x09 | STREAM_LIMIT | 流数量超限 |
| 0x0A | FRAME_TOO_LARGE | 帧过大 |
| 0x0B | INVALID_STATE | 非法状态 |
| 0x0C | TIMEOUT | 超时 |
| 0x0D | INTERNAL_ERROR | 内部错误 |
| 0x0E | CAPABILITY_NOT_SUPPORTED | 能力不支持 |
| 0x0F | QUOTA_EXCEEDED | 配额超限 |

---

## 9. 能力协商

HELLO 阶段双方交换支持的能力列表，取交集：

| 能力 | 说明 |
|------|------|
| `stream_multiplex` | 多路复用 |
| `encryption` | 端到端加密 |
| `compression` | 载荷压缩 |
| `file_watch` | 文件变更监听 |
| `file_lock` | 文件锁 |
| `delta_sync` | 差异同步（rsync 风格） |
| `resume` | 断点续传 |
| `reliable_transport` | 可靠传输（重传 + SACK） |
| `batch` | 批量操作 |

---

## 10. 版本对比

| 维度 | v1.0 | v2.0 | v3.0 |
|------|------|------|------|
| 帧头 | 20B 固定 | 24B + 可选扩展头 | 24B + 扩展头 + 压缩元数据 |
| 加密 | 无 | 预留 | ✅ X25519 + ChaCha20-Poly1305 |
| 多路复用 | ❌ | ✅ Stream 模型 | ✅ Stream 模型 |
| 流控 | ❌ | 预留 | ✅ 滑动窗口 + 零窗口探测 |
| 重传 | ❌ | 预留 | ✅ 超时重传 + 快速重传 + SACK |
| 拥塞控制 | ❌ | ❌ | ✅ 慢启动/拥塞避免/快速恢复 |
| 压缩 | ❌ | 预留 | ✅ LZ4/Zstd 透明压缩 |
| 差异传输 | ❌ | ❌ | ✅ rsync 风格增量同步 |
| 文件锁 | ❌ | ✅ 排他锁/共享锁 | ✅ 排他锁/共享锁 |
| 目录操作 | list only | mkdir/rename/delete/stat | mkdir/rename/delete/stat |
| 变更通知 | ❌ | ✅ file watch | ✅ file watch |
| 能力协商 | ❌ | ✅ HELLO 阶段 | ✅ HELLO 阶段 |
| 状态机 | 无 | 完整连接状态机 | 完整连接状态机 |
| 扩展性 | 无 | 扩展帧头 | 扩展帧头 |
| 密钥交换 | 无 | 简化 SHA256 | ✅ X25519 + HKDF |
